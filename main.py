#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          CyberSec Toolkit - CLI de Segurança         ║
║       Detecção de Malware & Monitoramento            ║
╚══════════════════════════════════════════════════════╝
"""

import click
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from datetime import datetime

from core.scanner import FileScanner
from core.malware_detector import MalwareDetector
from core.integrity import IntegrityMonitor
from core.network_analyzer import NetworkAnalyzer
from core.reporter import Reporter
from core.process_monitor import ProcessMonitor
from core.utils import load_config, print_banner, setup_logging

console = Console()
logger = setup_logging()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version="1.0.0", prog_name="CyberSec Toolkit")
def cli():
    """
    \b
    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║
   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║
   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝

    \b
    Toolkit de Cibersegurança | Detecção de Malware & Monitoramento
    Uso ético e educacional apenas. Respeite leis locais e internacionais.
    """
    pass


# ─────────────────────────── SCAN ───────────────────────────

@cli.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--deep", "-d", is_flag=True, help="Varredura profunda (mais lenta, mais completa)")
@click.option("--output", "-o", type=click.Choice(["json", "html", "txt"]), default="txt", help="Formato do relatório")
@click.option("--save", "-s", is_flag=True, help="Salvar relatório em reports/")
@click.option("--threads", "-t", default=4, show_default=True, help="Número de threads paralelas")
def scan(path, deep, output, save, threads):
    """
    Varredura completa de arquivos em busca de ameaças.

    \b
    Exemplos:
      python main.py scan /home/user
      python main.py scan /var/www --deep --output html --save
      python main.py scan . -d -o json -s -t 8
    """
    print_banner("VARREDURA DE ARQUIVOS", "blue")
    console.print(f"[dim]Alvo:[/] [bold cyan]{Path(path).resolve()}[/]")
    console.print(f"[dim]Modo:[/] [yellow]{'Profundo' if deep else 'Rápido'}[/]")
    console.print(f"[dim]Threads:[/] {threads}\n")

    scanner = FileScanner(path, deep=deep, threads=threads)
    detector = MalwareDetector()
    reporter = Reporter()

    results = scanner.run(detector)
    reporter.render_scan_results(results, output_format=output)

    if save:
        report_path = reporter.save(results, output_format=output, prefix="scan")
        console.print(f"\n[green]✔[/] Relatório salvo em: [bold]{report_path}[/]")

    sys.exit(1 if results["threats_found"] > 0 else 0)


# ─────────────────────────── INTEGRITY ───────────────────────────

@cli.group("integrity")
def integrity():
    """Monitoramento de integridade de arquivos (baseline + diff)."""
    pass


@integrity.command("baseline")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--name", "-n", default="default", help="Nome da baseline")
@click.option("--exclude", "-e", multiple=True, help="Padrões a excluir (glob)")
def integrity_baseline(path, name, exclude):
    """
    Cria uma baseline de integridade (snapshot de hashes).

    \b
    Exemplos:
      python main.py integrity baseline /etc --name sistema
      python main.py integrity baseline /var/www -n webapp -e "*.log" -e "*.tmp"
    """
    print_banner("CRIANDO BASELINE", "green")
    monitor = IntegrityMonitor()
    baseline_file = monitor.create_baseline(path, name=name, excludes=list(exclude))
    console.print(f"\n[green]✔[/] Baseline '[bold]{name}[/]' salva em: [dim]{baseline_file}[/]")


@integrity.command("check")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--name", "-n", default="default", help="Nome da baseline")
@click.option("--save", "-s", is_flag=True, help="Salvar relatório de diferenças")
def integrity_check(path, name, save):
    """
    Compara estado atual com a baseline salva.

    \b
    Exemplos:
      python main.py integrity check /etc --name sistema
      python main.py integrity check /var/www -n webapp --save
    """
    print_banner("VERIFICAÇÃO DE INTEGRIDADE", "yellow")
    monitor = IntegrityMonitor()
    diff = monitor.check(path, name=name)
    monitor.render_diff(diff)

    if save:
        reporter = Reporter()
        path_out = reporter.save(diff, output_format="json", prefix="integrity")
        console.print(f"\n[green]✔[/] Relatório salvo em: [bold]{path_out}[/]")

    sys.exit(1 if diff["changes_found"] else 0)


@integrity.command("watch")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--interval", "-i", default=5, show_default=True, help="Intervalo em segundos")
def integrity_watch(path, interval):
    """
    Modo watch: monitora mudanças em tempo real.

    \b
    Exemplo:
      python main.py integrity watch /etc -i 10
    """
    print_banner("MODO WATCH", "magenta")
    monitor = IntegrityMonitor()
    monitor.watch(path, interval=interval)


# ─────────────────────────── NETWORK ───────────────────────────

@cli.command("netcheck")
@click.option("--connections", "-c", is_flag=True, help="Listar conexões ativas")
@click.option("--ports", "-p", is_flag=True, help="Portas abertas e serviços")
@click.option("--suspicious", "-s", is_flag=True, help="Detectar conexões suspeitas")
@click.option("--save", is_flag=True, help="Salvar relatório")
def netcheck(connections, ports, suspicious, save):
    """
    Análise de rede: conexões, portas abertas, atividades suspeitas.

    \b
    Exemplos:
      python main.py netcheck --connections --suspicious
      python main.py netcheck -c -p -s --save
      python main.py netcheck -s
    """
    if not any([connections, ports, suspicious]):
        connections = ports = suspicious = True

    print_banner("ANÁLISE DE REDE", "cyan")
    analyzer = NetworkAnalyzer()

    results = {}
    if connections:
        results["connections"] = analyzer.get_connections()
        analyzer.render_connections(results["connections"])

    if ports:
        results["ports"] = analyzer.get_open_ports()
        analyzer.render_ports(results["ports"])

    if suspicious:
        results["suspicious"] = analyzer.detect_suspicious()
        analyzer.render_suspicious(results["suspicious"])

    if save:
        reporter = Reporter()
        p = reporter.save(results, output_format="json", prefix="network")
        console.print(f"\n[green]✔[/] Relatório salvo em: [bold]{p}[/]")


# ─────────────────────────── PROCESSES ───────────────────────────

@cli.command("processes")
@click.option("--top", "-t", default=20, show_default=True, help="Número de processos a exibir")
@click.option("--suspicious", "-s", is_flag=True, help="Destacar processos suspeitos")
@click.option("--hidden", is_flag=True, help="Tentar detectar processos ocultados")
@click.option("--save", is_flag=True, help="Salvar relatório")
def processes(top, suspicious, hidden, save):
    """
    Monitoramento de processos em execução e detecção de anomalias.

    \b
    Exemplos:
      python main.py processes --suspicious
      python main.py processes -t 50 -s --hidden
    """
    print_banner("MONITORAMENTO DE PROCESSOS", "red")
    monitor = ProcessMonitor()

    results = monitor.analyze(top_n=top, check_suspicious=suspicious, check_hidden=hidden)
    monitor.render(results)

    if save:
        reporter = Reporter()
        p = reporter.save(results, output_format="json", prefix="processes")
        console.print(f"\n[green]✔[/] Relatório salvo em: [bold]{p}[/]")


# ─────────────────────────── FULL AUDIT ───────────────────────────

@cli.command("audit")
@click.argument("path", default="/", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["json", "html", "txt"]), default="html")
@click.option("--quick", "-q", is_flag=True, help="Auditoria rápida (sem varredura profunda)")
def audit(path, output, quick):
    """
    Auditoria completa: scan + integridade + rede + processos.

    \b
    Exemplos:
      python main.py audit /
      python main.py audit /home --quick -o json
    """
    print_banner("AUDITORIA COMPLETA DO SISTEMA", "red")
    console.print(f"[yellow]⚠[/]  Auditoria iniciada às [bold]{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}[/]\n")

    reporter = Reporter()
    all_results = {"timestamp": datetime.now().isoformat(), "path": str(path)}

    # 1. File scan
    console.rule("[bold blue]1/4 - Varredura de Arquivos")
    scanner = FileScanner(path, deep=not quick, threads=4)
    detector = MalwareDetector()
    all_results["scan"] = scanner.run(detector)
    reporter.render_scan_results(all_results["scan"], output_format="txt")

    # 2. Network
    console.rule("[bold cyan]2/4 - Análise de Rede")
    analyzer = NetworkAnalyzer()
    all_results["network"] = {"suspicious": analyzer.detect_suspicious()}
    analyzer.render_suspicious(all_results["network"]["suspicious"])

    # 3. Processes
    console.rule("[bold red]3/4 - Processos")
    proc_monitor = ProcessMonitor()
    all_results["processes"] = proc_monitor.analyze(top_n=20, check_suspicious=True)
    proc_monitor.render(all_results["processes"])

    # 4. Summary
    console.rule("[bold green]4/4 - Relatório Final")
    report_path = reporter.save(all_results, output_format=output, prefix="audit")
    reporter.render_audit_summary(all_results)
    console.print(f"\n[green]✔[/] Relatório completo: [bold]{report_path}[/]")


# ─────────────────────────── HASH ───────────────────────────

@cli.command("hash")
@click.argument("file", type=click.Path(exists=True))
@click.option("--algo", "-a", type=click.Choice(["md5", "sha1", "sha256", "sha512"]), default="sha256")
@click.option("--check-vt", is_flag=True, help="Verificar no VirusTotal (requer API key em config)")
def hash_file(file, algo, check_vt):
    """
    Calcula o hash de um arquivo e opcionalmente verifica no VirusTotal.

    \b
    Exemplos:
      python main.py hash arquivo.exe
      python main.py hash suspeito.bin --algo md5
      python main.py hash malware.dll --check-vt
    """
    from core.utils import compute_hash, check_virustotal
    print_banner("HASH & VERIFICAÇÃO", "yellow")

    file_hash = compute_hash(file, algo)
    size = Path(file).stat().st_size

    console.print(f"\n[dim]Arquivo:[/]    [bold]{file}[/]")
    console.print(f"[dim]Tamanho:[/]    {size:,} bytes ({size/1024:.1f} KB)")
    console.print(f"[dim]Algoritmo:[/]  {algo.upper()}")
    console.print(f"[dim]Hash:[/]       [bold yellow]{file_hash}[/]\n")

    if check_vt:
        config = load_config()
        api_key = config.get("virustotal", {}).get("api_key", "")
        if not api_key:
            console.print("[red]✗[/] API key do VirusTotal não configurada em config/config.yaml")
        else:
            check_virustotal(file_hash, api_key)


# ─────────────────────────── MALWARE DB ───────────────────────────

@cli.group("db")
def db():
    """Gerenciamento da base de assinaturas de malware."""
    pass


@db.command("update")
def db_update():
    """Atualiza a base de assinaturas de malware (hashes conhecidos)."""
    print_banner("ATUALIZANDO BASE DE ASSINATURAS", "green")
    detector = MalwareDetector()
    detector.update_signatures()


@db.command("stats")
def db_stats():
    """Exibe estatísticas da base de assinaturas atual."""
    print_banner("ESTATÍSTICAS DA BASE", "blue")
    detector = MalwareDetector()
    detector.show_stats()


if __name__ == "__main__":
    cli()
