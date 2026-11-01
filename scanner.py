"""
Módulo de Varredura de Arquivos.

Responsável por percorrer o sistema de arquivos de forma
eficiente (multi-thread) e alimentar o MalwareDetector.
"""

import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

from core.utils import compute_hashes, format_size, load_config
from core.malware_detector import MalwareDetector

console = Console()

# Diretórios a ignorar por padrão
DEFAULT_SKIP_DIRS = {
    "/proc", "/sys", "/dev", "/run",
    "/snap", "/boot/efi",
    "__pycache__", ".git", "node_modules", ".venv", "venv",
}

# Extensões a ignorar (muito comuns e raramente maliciosas isoladas)
SKIP_EXTENSIONS = {".pyc", ".pyo", ".cache", ".class"}


class FileScanner:
    """Varre o sistema de arquivos buscando indicadores de comprometimento."""

    def __init__(self, root_path: str, deep: bool = False, threads: int = 4):
        self.root = Path(root_path).resolve()
        self.deep = deep
        self.threads = threads
        self.config = load_config()
        self.max_file_size = 100 * 1024 * 1024 if deep else 10 * 1024 * 1024  # 100MB / 10MB

        # Diretórios a pular (configuráveis)
        skip_cfg = self.config.get("scanner", {}).get("skip_dirs", [])
        self.skip_dirs = DEFAULT_SKIP_DIRS | set(skip_cfg)

    def _collect_files(self) -> list[Path]:
        """Coleta recursivamente todos os arquivos a serem analisados."""
        files = []
        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True):
            # Remove diretórios a pular in-place (evita descer neles)
            dirnames[:] = [
                d for d in dirnames
                if d not in self.skip_dirs and str(Path(dirpath) / d) not in self.skip_dirs
            ]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                try:
                    size = fpath.stat().st_size
                    if size > self.max_file_size:
                        continue
                    files.append(fpath)
                except (PermissionError, OSError):
                    continue
        return files

    def _analyze_one(self, filepath: Path, detector: MalwareDetector) -> Optional[dict]:
        """Analisa um único arquivo. Retorna resultado ou None se sem ameaça."""
        hashes = compute_hashes(str(filepath))
        result = detector.analyze_file(str(filepath), hashes)
        result["hashes"] = hashes
        return result

    def run(self, detector: MalwareDetector) -> dict:
        """Executa a varredura completa e retorna um relatório estruturado."""
        start = time.time()
        console.print(f"[dim]Coletando arquivos em[/] [bold]{self.root}[/]...")

        files = self._collect_files()
        total = len(files)
        console.print(f"[dim]Total de arquivos a analisar:[/] [bold]{total:,}[/]\n")

        threats = []
        suspicious = []
        scanned = 0
        errors = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[bold]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Analisando arquivos...", total=total)

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._analyze_one, f, detector): f for f in files}

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        scanned += 1
                        if result["risk_level"] == "CRITICAL" or result["threats"]:
                            threats.append(result)
                        elif result["risk_level"] in ("HIGH", "MEDIUM"):
                            suspicious.append(result)
                    except Exception:
                        errors += 1
                    progress.advance(task)

        elapsed = round(time.time() - start, 2)

        results = {
            "root": str(self.root),
            "scanned": scanned,
            "total_files": total,
            "errors": errors,
            "elapsed_seconds": elapsed,
            "threats_found": len(threats),
            "suspicious_found": len(suspicious),
            "threats": threats,
            "suspicious": suspicious,
        }

        return results

    def render_results_table(self, results: dict):
        """Exibe tabela resumida dos resultados (delegado ao Reporter)."""
        from core.reporter import Reporter
        Reporter().render_scan_results(results, output_format="txt")


def _classify_severity_color(level: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(level, "white")
