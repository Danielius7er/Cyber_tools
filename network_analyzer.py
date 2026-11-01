"""
Módulo de Análise de Rede.

Detecta:
  - Conexões ativas e seus processos associados
  - Portas abertas (listening)
  - Conexões para IPs suspeitos / portas incomuns
  - Possíveis backdoors ou reverse shells ativos
"""

import socket
from datetime import datetime
from typing import Optional
import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ── Portas conhecidas de C2 e atividade maliciosa ───────────────────────────
SUSPICIOUS_PORTS = {
    1234, 4444, 5555, 6666, 7777, 8888, 9999,   # Metasploit defaults
    31337, 12345, 54321,                          # Clássicos backdoors
    1080, 3128, 8080, 9050,                       # Proxies/Tor
    6667, 6668, 6669,                             # IRC (C2 antigo)
    2222, 2323,                                   # SSH alternativo suspeito
    65535, 65534,                                 # Portas finais (muito incomuns)
}

# ── Faixas de IP privado (normais) ──────────────────────────────────────────
import ipaddress

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip


def _get_process_name(pid: Optional[int]) -> str:
    if pid is None:
        return "N/A"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"PID:{pid}"


class NetworkAnalyzer:
    """Analisa conexões de rede e detecta anomalias."""

    def get_connections(self) -> list[dict]:
        """Retorna todas as conexões TCP/UDP ativas."""
        conns = []
        try:
            for c in psutil.net_connections(kind="all"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                conns.append({
                    "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "local": laddr,
                    "remote": raddr,
                    "status": c.status or "-",
                    "pid": c.pid,
                    "process": _get_process_name(c.pid),
                    "remote_ip": c.raddr.ip if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "local_port": c.laddr.port if c.laddr else None,
                })
        except psutil.AccessDenied:
            console.print("[yellow]⚠[/]  Acesso negado a algumas conexões (execute como root para visão completa)")
        return conns

    def get_open_ports(self) -> list[dict]:
        """Retorna portas em modo LISTEN."""
        ports = []
        try:
            for c in psutil.net_connections(kind="all"):
                if c.status == "LISTEN" or (c.type == socket.SOCK_DGRAM and c.laddr):
                    ports.append({
                        "port": c.laddr.port if c.laddr else 0,
                        "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                        "address": c.laddr.ip if c.laddr else "?",
                        "pid": c.pid,
                        "process": _get_process_name(c.pid),
                        "suspicious": c.laddr.port in SUSPICIOUS_PORTS if c.laddr else False,
                    })
        except psutil.AccessDenied:
            pass
        return sorted(ports, key=lambda x: x["port"])

    def detect_suspicious(self) -> dict:
        """Detecta conexões e portas potencialmente maliciosas."""
        conns = self.get_connections()
        ports = self.get_open_ports()

        suspicious_conns = []
        suspicious_ports_found = []

        for c in conns:
            reasons = []
            rip = c.get("remote_ip")
            rport = c.get("remote_port")

            if rip and rip not in ("", "0.0.0.0", "::") and not _is_private(rip):
                if rport and rport in SUSPICIOUS_PORTS:
                    reasons.append(f"Conexão externa para porta suspeita {rport}")

            if rport and rport in SUSPICIOUS_PORTS:
                reasons.append(f"Porta remota suspeita: {rport}")

            if c.get("local_port") and c["local_port"] in SUSPICIOUS_PORTS:
                reasons.append(f"Porta local suspeita: {c['local_port']}")

            if reasons:
                c["reasons"] = reasons
                suspicious_conns.append(c)

        for p in ports:
            if p["suspicious"]:
                suspicious_ports_found.append(p)

        return {
            "suspicious_connections": suspicious_conns,
            "suspicious_ports": suspicious_ports_found,
            "checked_at": datetime.now().isoformat(),
            "total_connections": len(conns),
        }

    def render_connections(self, conns: list[dict]):
        """Renderiza tabela de conexões ativas."""
        t = Table(
            title=f"Conexões Ativas ({len(conns)})",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            show_lines=False,
        )
        t.add_column("Proto", style="cyan", width=6)
        t.add_column("Local")
        t.add_column("Remoto")
        t.add_column("Status", justify="center")
        t.add_column("Processo", style="yellow")
        t.add_column("PID", justify="right", style="dim")

        status_colors = {
            "ESTABLISHED": "green",
            "LISTEN": "blue",
            "CLOSE_WAIT": "yellow",
            "TIME_WAIT": "dim",
            "SYN_SENT": "red",
        }

        for c in conns[:100]:  # Limita exibição
            status = c["status"]
            color = status_colors.get(status, "white")
            t.add_row(
                c["protocol"],
                c["local"],
                c["remote"],
                f"[{color}]{status}[/]",
                c["process"],
                str(c["pid"] or "-"),
            )

        console.print(t)
        if len(conns) > 100:
            console.print(f"[dim]... e mais {len(conns) - 100} conexões[/]")

    def render_ports(self, ports: list[dict]):
        """Renderiza tabela de portas abertas."""
        t = Table(
            title=f"Portas Abertas ({len(ports)})",
            box=box.SIMPLE_HEAVY,
            border_style="blue",
        )
        t.add_column("Porta", justify="right")
        t.add_column("Proto", style="cyan")
        t.add_column("Endereço")
        t.add_column("Processo", style="yellow")
        t.add_column("Risco", justify="center")

        for p in ports:
            risk = "[bold red]⚠ SUSPEITA[/]" if p["suspicious"] else "[green]OK[/]"
            t.add_row(
                str(p["port"]),
                p["protocol"],
                p["address"],
                p["process"],
                risk,
            )

        console.print(t)

    def render_suspicious(self, data: dict):
        """Renderiza alertas de rede suspeita."""
        total_susp = len(data["suspicious_connections"]) + len(data["suspicious_ports"])

        if total_susp == 0:
            console.print(Panel(
                "[bold green]✔  Nenhuma atividade de rede suspeita detectada.[/]",
                border_style="green",
            ))
            return

        console.print(Panel(
            f"[bold red]⚠  {total_susp} indicador(es) suspeito(s) de rede encontrado(s)![/]",
            border_style="red",
            title="Alerta de Rede",
        ))

        if data["suspicious_connections"]:
            t = Table(
                title=f"[red]Conexões Suspeitas ({len(data['suspicious_connections'])})[/]",
                box=box.SIMPLE_HEAVY,
                border_style="red",
            )
            t.add_column("Local")
            t.add_column("Remoto")
            t.add_column("Processo", style="yellow")
            t.add_column("Motivo", style="red")
            for c in data["suspicious_connections"]:
                t.add_row(
                    c["local"],
                    c["remote"],
                    c["process"],
                    "; ".join(c.get("reasons", [])),
                )
            console.print(t)

        if data["suspicious_ports"]:
            t = Table(
                title=f"[red]Portas Suspeitas em Escuta ({len(data['suspicious_ports'])})[/]",
                box=box.SIMPLE_HEAVY,
                border_style="red",
            )
            t.add_column("Porta", justify="right")
            t.add_column("Proto")
            t.add_column("Processo", style="yellow")
            for p in data["suspicious_ports"]:
                t.add_row(str(p["port"]), p["protocol"], p["process"])
            console.print(t)
