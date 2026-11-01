"""
Módulo de Geração de Relatórios.

Suporta saída em:
  - TXT (Rich terminal)
  - JSON (estruturado)
  - HTML (relatório visual standalone)
"""

import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.utils import REPORTS_DIR, format_size

console = Console()


class Reporter:
    """Gera e salva relatórios de segurança em múltiplos formatos."""

    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def _report_filename(self, prefix: str, fmt: str) -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return REPORTS_DIR / f"{prefix}_{ts}.{fmt}"

    # ── SCAN ────────────────────────────────────────────────────────────────

    def render_scan_results(self, results: dict, output_format: str = "txt"):
        """Renderiza os resultados de varredura no terminal."""
        threats = results.get("threats", [])
        suspicious = results.get("suspicious", [])

        # Summary
        color = "red" if threats else "yellow" if suspicious else "green"
        icon = "✘" if threats else "⚠" if suspicious else "✔"
        console.print(Panel(
            f"[bold {color}]{icon}  Varredura concluída[/]\n"
            f"  Arquivos verificados: [bold]{results.get('scanned', 0):,}[/]  |  "
            f"Ameaças: [bold red]{results.get('threats_found', 0)}[/]  |  "
            f"Suspeitos: [bold yellow]{results.get('suspicious_found', 0)}[/]  |  "
            f"Tempo: {results.get('elapsed_seconds', 0):.1f}s",
            border_style=color,
            title="Resultado da Varredura",
        ))

        if threats:
            t = Table(
                title=f"[red]Ameaças Detectadas ({len(threats)})[/]",
                box=box.SIMPLE_HEAVY,
                border_style="red",
                show_lines=True,
            )
            t.add_column("Arquivo", max_width=60)
            t.add_column("Nível", justify="center")
            t.add_column("Ameaça / Indicador", style="red", max_width=50)

            for item in threats[:50]:
                threat_text = "\n".join(item.get("threats", []) + item.get("indicators", []))
                level = item.get("risk_level", "?")
                level_str = {
                    "CRITICAL": "[bold red]CRÍTICO[/]",
                    "HIGH": "[red]ALTO[/]",
                    "MEDIUM": "[yellow]MÉDIO[/]",
                }.get(level, level)
                t.add_row(item["filepath"], level_str, threat_text[:100])
            console.print(t)

        if suspicious:
            t = Table(
                title=f"[yellow]Arquivos Suspeitos ({len(suspicious)})[/]",
                box=box.SIMPLE_HEAVY,
                border_style="yellow",
            )
            t.add_column("Arquivo", max_width=60)
            t.add_column("Nível", justify="center")
            t.add_column("Indicadores", style="yellow", max_width=50)

            for item in suspicious[:30]:
                indicators = "; ".join(item.get("indicators", []))
                level = item.get("risk_level", "?")
                level_str = "[red]ALTO[/]" if level == "HIGH" else "[yellow]MÉDIO[/]"
                t.add_row(item["filepath"], level_str, indicators[:80])
            console.print(t)

    # ── AUDIT SUMMARY ───────────────────────────────────────────────────────

    def render_audit_summary(self, results: dict):
        """Renderiza o painel de resumo final da auditoria completa."""
        scan = results.get("scan", {})
        threats = scan.get("threats_found", 0)
        suspicious_net = len(results.get("network", {}).get("suspicious", {}).get("suspicious_connections", []))
        suspicious_proc = len(results.get("processes", {}).get("suspicious", []))

        total_issues = threats + suspicious_net + suspicious_proc
        overall = "CRÍTICO" if threats > 0 else "ATENÇÃO" if total_issues > 0 else "OK"
        color = "red" if threats > 0 else "yellow" if total_issues > 0 else "green"

        console.print(Panel(
            f"[bold {color}]SCORE DE SEGURANÇA: {overall}[/]\n\n"
            f"  • Ameaças de arquivos:   [red bold]{threats}[/]\n"
            f"  • Conexões suspeitas:    [yellow]{suspicious_net}[/]\n"
            f"  • Processos suspeitos:   [yellow]{suspicious_proc}[/]\n\n"
            f"[dim]Total de problemas encontrados: {total_issues}[/]",
            border_style=color,
            title="Auditoria Completa — Resumo Final",
            padding=(1, 4),
        ))

    # ── SAVE ────────────────────────────────────────────────────────────────

    def save(self, data: dict, output_format: str = "json", prefix: str = "report") -> str:
        """Salva o relatório no formato especificado."""
        path = self._report_filename(prefix, output_format)

        if output_format == "json":
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        elif output_format == "txt":
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"CyberSec Toolkit — Relatório\n")
                f.write(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write("=" * 60 + "\n")
                f.write(json.dumps(data, indent=2, ensure_ascii=False, default=str))

        elif output_format == "html":
            html = self._generate_html(data, prefix)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)

        return str(path)

    def _generate_html(self, data: dict, title: str) -> str:
        """Gera um relatório HTML standalone com visual profissional."""
        ts = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        data_json = json.dumps(data, indent=2, ensure_ascii=False, default=str)

        # Métricas de destaque
        threats = 0
        if "scan" in data:
            threats = data["scan"].get("threats_found", 0)
        elif "threats_found" in data:
            threats = data.get("threats_found", 0)

        suspicious = data.get("suspicious_found", 0) or len(data.get("suspicious", []))
        scanned = data.get("scanned", data.get("scan", {}).get("scanned", 0))

        severity_color = "#e74c3c" if threats > 0 else "#f39c12" if suspicious > 0 else "#27ae60"
        severity_label = "CRÍTICO" if threats > 0 else "ATENÇÃO" if suspicious > 0 else "SEGURO"

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSec Toolkit — {title.upper()}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #6e7681; --accent: #58a6ff;
    --red: #f85149; --yellow: #e3b341; --green: #3fb950;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: .25rem; }}
  .subtitle {{ color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .card .value {{ font-size: 2.5rem; font-weight: 700; }}
  .card .label {{ font-size: .8rem; color: var(--muted); margin-top: .25rem; text-transform: uppercase; letter-spacing: .05em; }}
  .severity {{ background: var(--surface); border: 2px solid {severity_color}; border-radius: 8px;
               padding: 1rem 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 1rem; }}
  .severity .badge {{ background: {severity_color}; color: #fff; font-weight: 700; padding: .4rem .9rem;
                       border-radius: 4px; font-size: 1rem; }}
  pre {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
         padding: 1.5rem; overflow-x: auto; font-size: .8rem; line-height: 1.5; color: var(--text); }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; }}
</style>
</head>
<body>
<h1>🛡 CyberSec Toolkit</h1>
<p class="subtitle">Relatório: <strong>{title.upper()}</strong> — Gerado em {ts}</p>

<div class="severity">
  <span class="badge">{severity_label}</span>
  <span>Nível de risco geral do sistema baseado nos resultados desta análise.</span>
</div>

<div class="cards">
  <div class="card">
    <div class="value" style="color: var(--accent)">{scanned:,}</div>
    <div class="label">Arquivos Verificados</div>
  </div>
  <div class="card">
    <div class="value" style="color: {'var(--red)' if threats > 0 else 'var(--green)'}">{threats}</div>
    <div class="label">Ameaças Encontradas</div>
  </div>
  <div class="card">
    <div class="value" style="color: {'var(--yellow)' if suspicious > 0 else 'var(--green)'}">{suspicious}</div>
    <div class="label">Suspeitos</div>
  </div>
</div>

<h2 style="color: var(--accent); margin-bottom: 1rem; font-size: 1.1rem;">Dados Completos (JSON)</h2>
<pre>{data_json}</pre>

<footer>CyberSec Toolkit v1.0 — Uso ético e educacional. Respeite as leis locais.</footer>
</body>
</html>"""
