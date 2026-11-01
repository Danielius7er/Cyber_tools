"""
Módulo de Monitoramento de Processos.

Detecta:
  - Processos com alto consumo de CPU/RAM anormal
  - Processos mascarando nomes de processos legítimos
  - Processos executando a partir de diretórios suspeitos
  - Possíveis processos ocultos (discrepância PID)
  - Processos sem executável identificável (processo morto)
"""

import os
import re
from datetime import datetime
import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ── Nomes de processos legítimos comuns (que podem ser falsificados) ─────────
LEGIT_PROCESS_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
    "systemd", "kthreadd", "init", "launchd", "kernel_task",
}

# ── Diretórios de onde processos NÃO deveriam ser executados ────────────────
SUSPICIOUS_DIRS = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "C:\\Users\\Public\\", "C:\\Temp\\", "C:\\Windows\\Temp\\",
    "/home/.hidden", "/.hidden",
]

# ── Regex para detectar nomes de processos que imitam processos legítimos ────
MASQUERADE_PATTERNS = [
    (re.compile(r"^svch0st|svchos7|svch[^\s]st$", re.I), "Possível mascaramento de svchost"),
    (re.compile(r"^l[s5]ass|lsas[s5]$", re.I), "Possível mascaramento de lsass"),
    (re.compile(r"^system[d0]$", re.I), "Possível mascaramento de systemd"),
    (re.compile(r"^init[il1]$", re.I), "Possível mascaramento de init"),
    (re.compile(r"^python3?\d*\s+-c\s+", re.I), "Python executando código inline suspeito"),
]


class ProcessMonitor:
    """Analisa processos em execução em busca de anomalias."""

    def _get_all_processes(self) -> list[dict]:
        """Coleta informações de todos os processos ativos."""
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username",
                                       "cpu_percent", "memory_percent", "status",
                                       "create_time", "ppid"]):
            try:
                info = p.info
                # cpu_percent precisa de intervalo; chamamos novamente
                cpu = p.cpu_percent(interval=0.0)
                procs.append({
                    "pid": info["pid"],
                    "ppid": info.get("ppid"),
                    "name": info["name"] or "",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(info.get("cmdline") or [])[:120],
                    "username": info.get("username") or "?",
                    "cpu": round(cpu, 1),
                    "mem": round(info.get("memory_percent") or 0, 2),
                    "status": info.get("status") or "?",
                    "create_time": info.get("create_time"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return procs

    def _flag_suspicious(self, proc: dict) -> list[str]:
        """Retorna lista de motivos suspeitos para um processo."""
        flags = []

        # Execução a partir de diretório suspeito
        exe = proc.get("exe", "")
        for d in SUSPICIOUS_DIRS:
            if exe.startswith(d):
                flags.append(f"Executado a partir de diretório suspeito: {d}")

        # Nome mascarado
        name = proc.get("name", "")
        for pattern, msg in MASQUERADE_PATTERNS:
            if pattern.search(name):
                flags.append(msg)

        # Sem executável mapeável (processo fantasma)
        if name and not exe and proc.get("status") not in ("zombie", "dead"):
            flags.append("Sem caminho de executável mapeável (possível processo oculto)")

        # Uso extremo de CPU
        if proc["cpu"] > 90:
            flags.append(f"CPU muito alto: {proc['cpu']}%")

        # Alto uso de memória
        if proc["mem"] > 50:
            flags.append(f"Memória muito alta: {proc['mem']}%")

        # Processo rodando como root com nome suspeito
        if proc.get("username") in ("root", "SYSTEM") and any(
            kw in proc.get("cmdline", "").lower()
            for kw in ["curl", "wget", "nc ", "netcat", "base64", "python -c", "bash -i"]
        ):
            flags.append("Processo root com comando suspeito na linha de comando")

        return flags

    def _check_hidden_pids(self) -> list[int]:
        """
        Tenta detectar PIDs ocultos comparando /proc com psutil.
        Funciona apenas em Linux.
        """
        hidden = []
        try:
            proc_pids = {int(d) for d in os.listdir("/proc") if d.isdigit()}
            psutil_pids = set(psutil.pids())
            hidden = list(proc_pids - psutil_pids)
        except (PermissionError, FileNotFoundError):
            pass
        return hidden

    def analyze(self, top_n: int = 20, check_suspicious: bool = True, check_hidden: bool = False) -> dict:
        """Executa análise completa de processos."""
        all_procs = self._get_all_processes()

        # Ordena por CPU + MEM
        sorted_procs = sorted(all_procs, key=lambda p: (p["cpu"] + p["mem"]), reverse=True)
        top_procs = sorted_procs[:top_n]

        suspicious = []
        if check_suspicious:
            for p in all_procs:
                flags = self._flag_suspicious(p)
                if flags:
                    p["flags"] = flags
                    suspicious.append(p)

        hidden_pids = []
        if check_hidden:
            hidden_pids = self._check_hidden_pids()

        return {
            "total_processes": len(all_procs),
            "top_processes": top_procs,
            "suspicious": suspicious,
            "hidden_pids": hidden_pids,
            "checked_at": datetime.now().isoformat(),
        }

    def render(self, results: dict):
        """Renderiza resultados da análise de processos."""
        # Top processos
        t = Table(
            title=f"Top Processos por Uso de Recursos (Total: {results['total_processes']})",
            box=box.SIMPLE_HEAVY,
            border_style="blue",
        )
        t.add_column("PID", justify="right", style="dim")
        t.add_column("Nome", style="cyan")
        t.add_column("Usuário", style="yellow")
        t.add_column("CPU%", justify="right")
        t.add_column("MEM%", justify="right")
        t.add_column("Status")
        t.add_column("Comando", style="dim", max_width=40)

        for p in results["top_processes"]:
            cpu_color = "red" if p["cpu"] > 80 else "yellow" if p["cpu"] > 50 else "green"
            mem_color = "red" if p["mem"] > 30 else "yellow" if p["mem"] > 10 else "green"
            t.add_row(
                str(p["pid"]),
                p["name"],
                p["username"],
                f"[{cpu_color}]{p['cpu']}%[/]",
                f"[{mem_color}]{p['mem']}%[/]",
                p["status"],
                p["cmdline"][:40],
            )

        console.print(t)

        # Processos suspeitos
        if results.get("suspicious"):
            console.print(Panel(
                f"[bold red]⚠  {len(results['suspicious'])} processo(s) suspeito(s) detectado(s)![/]",
                border_style="red",
            ))
            t2 = Table(
                title="Processos Suspeitos",
                box=box.SIMPLE_HEAVY,
                border_style="red",
                show_lines=True,
            )
            t2.add_column("PID", justify="right")
            t2.add_column("Nome", style="cyan")
            t2.add_column("Usuário", style="yellow")
            t2.add_column("Motivo(s)", style="red")

            for p in results["suspicious"]:
                t2.add_row(
                    str(p["pid"]),
                    p["name"],
                    p["username"],
                    "\n".join(p.get("flags", [])),
                )
            console.print(t2)
        else:
            console.print("[green]✔[/]  Nenhum processo suspeito detectado.\n")

        # PIDs ocultos
        if results.get("hidden_pids"):
            console.print(Panel(
                f"[bold red]🚨  {len(results['hidden_pids'])} PID(s) potencialmente oculto(s): {results['hidden_pids']}[/]",
                border_style="red",
                title="ALERTA CRÍTICO",
            ))
