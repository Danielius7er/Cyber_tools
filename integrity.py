"""
Módulo de Monitoramento de Integridade de Arquivos.

Fluxo:
  1. baseline → gera snapshot de hashes de todos os arquivos
  2. check     → compara estado atual com o snapshot
  3. watch     → monitora em tempo real com polling
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.utils import compute_hash, DATA_DIR

console = Console()

BASELINES_DIR = DATA_DIR / "baselines"


class IntegrityMonitor:
    """Monitor de integridade baseado em hashes SHA-256."""

    def __init__(self):
        BASELINES_DIR.mkdir(parents=True, exist_ok=True)

    def _baseline_path(self, name: str) -> Path:
        return BASELINES_DIR / f"{name}.json"

    def _collect_hashes(self, root: str, excludes: list[str] = None) -> dict:
        """Percorre o diretório e calcula SHA-256 de cada arquivo."""
        import fnmatch
        excludes = excludes or []
        hashes = {}
        root_path = Path(root).resolve()

        for dirpath, _, filenames in os.walk(root_path):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                rel = str(fpath.relative_to(root_path))

                # Verifica exclusões
                if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                    continue

                try:
                    stat = fpath.stat()
                    h = compute_hash(str(fpath), "sha256")
                    hashes[rel] = {
                        "sha256": h,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "mode": oct(stat.st_mode),
                    }
                except (PermissionError, OSError):
                    hashes[rel] = {"sha256": "ERROR", "size": -1, "mtime": 0, "mode": "?"}

        return hashes

    def create_baseline(self, root: str, name: str = "default", excludes: list[str] = None) -> str:
        """Cria e salva uma baseline de integridade."""
        console.print(f"[dim]Gerando hashes de[/] [bold]{root}[/]...")

        from rich.progress import Progress, SpinnerColumn, TextColumn
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            p.add_task("Calculando hashes SHA-256...")
            hashes = self._collect_hashes(root, excludes)

        baseline = {
            "name": name,
            "root": str(Path(root).resolve()),
            "created_at": datetime.now().isoformat(),
            "excludes": excludes or [],
            "files": hashes,
            "total_files": len(hashes),
        }

        out_path = self._baseline_path(name)
        with open(out_path, "w") as f:
            json.dump(baseline, f, indent=2)

        console.print(f"[green]✔[/] {len(hashes):,} arquivos indexados na baseline '[bold]{name}[/]'")
        return str(out_path)

    def check(self, root: str, name: str = "default") -> dict:
        """Compara estado atual com a baseline salva."""
        baseline_path = self._baseline_path(name)
        if not baseline_path.exists():
            console.print(f"[red]✗[/] Baseline '[bold]{name}[/]' não encontrada. Execute primeiro: [cyan]integrity baseline[/]")
            return {"changes_found": False, "error": "baseline_not_found"}

        with open(baseline_path) as f:
            baseline = json.load(f)

        console.print(f"[dim]Baseline carregada:[/] '{name}' — {baseline['total_files']:,} arquivos ({baseline['created_at'][:19]})")
        console.print(f"[dim]Calculando estado atual de[/] [bold]{root}[/]...\n")

        current = self._collect_hashes(root, baseline.get("excludes", []))
        old = baseline["files"]

        added = {k: v for k, v in current.items() if k not in old}
        removed = {k: v for k, v in old.items() if k not in current}
        modified = {}
        permission_changed = {}

        for k in set(current) & set(old):
            c, o = current[k], old[k]
            if c["sha256"] != o["sha256"] and c["sha256"] != "ERROR":
                modified[k] = {"old_hash": o["sha256"], "new_hash": c["sha256"], "old_size": o["size"], "new_size": c["size"]}
            elif c.get("mode") != o.get("mode"):
                permission_changed[k] = {"old": o.get("mode"), "new": c.get("mode")}

        changes_found = bool(added or removed or modified or permission_changed)

        return {
            "baseline_name": name,
            "root": root,
            "checked_at": datetime.now().isoformat(),
            "changes_found": changes_found,
            "added": added,
            "removed": removed,
            "modified": modified,
            "permission_changed": permission_changed,
            "summary": {
                "added": len(added),
                "removed": len(removed),
                "modified": len(modified),
                "permission_changed": len(permission_changed),
            },
        }

    def render_diff(self, diff: dict):
        """Renderiza as diferenças encontradas no terminal."""
        if diff.get("error"):
            return

        summary = diff.get("summary", {})
        total_changes = sum(summary.values())

        if not diff["changes_found"]:
            console.print(Panel(
                "[bold green]✔  Nenhuma alteração detectada. Sistema íntegro.[/]",
                border_style="green",
            ))
            return

        # Summary panel
        color = "red" if total_changes > 10 else "yellow"
        console.print(Panel(
            f"[bold {color}]⚠  {total_changes} alteração(ões) detectada(s)![/]\n"
            f"  Adicionados: [green]{summary['added']}[/]  |  "
            f"Removidos: [red]{summary['removed']}[/]  |  "
            f"Modificados: [yellow]{summary['modified']}[/]  |  "
            f"Permissões: [magenta]{summary['permission_changed']}[/]",
            border_style=color,
            title="Relatório de Integridade",
        ))

        def make_table(title: str, data: dict, color: str, cols: list[tuple]) -> Table:
            t = Table(title=title, box=box.SIMPLE_HEAVY, border_style=color, show_lines=True)
            for col_name, col_style in cols:
                t.add_column(col_name, style=col_style)
            return t, data

        if diff["added"]:
            t = Table(title=f"[green]Arquivos Adicionados ({len(diff['added'])})[/]",
                      box=box.SIMPLE_HEAVY, border_style="green")
            t.add_column("Arquivo", style="green")
            t.add_column("Tamanho", justify="right")
            for path, info in list(diff["added"].items())[:50]:
                from core.utils import format_size
                t.add_row(path, format_size(info.get("size", 0)))
            console.print(t)

        if diff["removed"]:
            t = Table(title=f"[red]Arquivos Removidos ({len(diff['removed'])})[/]",
                      box=box.SIMPLE_HEAVY, border_style="red")
            t.add_column("Arquivo", style="red")
            t.add_column("Último tamanho", justify="right")
            for path, info in list(diff["removed"].items())[:50]:
                from core.utils import format_size
                t.add_row(path, format_size(info.get("size", 0)))
            console.print(t)

        if diff["modified"]:
            t = Table(title=f"[yellow]Arquivos Modificados ({len(diff['modified'])})[/]",
                      box=box.SIMPLE_HEAVY, border_style="yellow")
            t.add_column("Arquivo")
            t.add_column("Hash anterior", style="dim")
            t.add_column("Hash atual", style="yellow")
            t.add_column("Δ Tamanho", justify="right")
            for path, info in list(diff["modified"].items())[:50]:
                delta = info["new_size"] - info["old_size"]
                delta_str = f"[green]+{delta}[/]" if delta > 0 else f"[red]{delta}[/]" if delta < 0 else "0"
                t.add_row(
                    path,
                    info["old_hash"][:16] + "...",
                    info["new_hash"][:16] + "...",
                    delta_str,
                )
            console.print(t)

        if diff["permission_changed"]:
            t = Table(title=f"[magenta]Permissões Alteradas ({len(diff['permission_changed'])})[/]",
                      box=box.SIMPLE_HEAVY, border_style="magenta")
            t.add_column("Arquivo")
            t.add_column("Antes", style="dim")
            t.add_column("Depois", style="magenta")
            for path, info in diff["permission_changed"].items():
                t.add_row(path, str(info["old"]), str(info["new"]))
            console.print(t)

    def watch(self, root: str, interval: int = 5):
        """Modo watch: polling periódico e alerta de mudanças em tempo real."""
        console.print(f"[bold cyan]Modo Watch ativo[/] — verificando a cada [yellow]{interval}s[/]")
        console.print(f"[dim]Diretório monitorado:[/] {root}")
        console.print("[dim]Pressione Ctrl+C para sair.\n[/]")

        # Cria baseline temporária
        temp_name = f"_watch_{int(time.time())}"
        self.create_baseline(root, name=temp_name)

        try:
            check_count = 0
            while True:
                time.sleep(interval)
                check_count += 1
                diff = self.check(root, name=temp_name)
                ts = datetime.now().strftime("%H:%M:%S")

                if diff["changes_found"]:
                    console.print(f"\n[bold red][{ts}] ⚠ ALTERAÇÃO DETECTADA[/]")
                    self.render_diff(diff)
                    # Atualiza baseline para próxima comparação
                    self.create_baseline(root, name=temp_name)
                else:
                    console.print(f"[dim][{ts}] Verificação #{check_count} — sem alterações[/]")

        except KeyboardInterrupt:
            # Limpa baseline temporária
            tmp = self._baseline_path(temp_name)
            if tmp.exists():
                tmp.unlink()
            console.print("\n[yellow]Modo Watch encerrado.[/]")
