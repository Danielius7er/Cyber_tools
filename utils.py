"""
Utilitários centrais do CyberSec Toolkit.
"""

import hashlib
import logging
import yaml
import os
import requests
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BASE_DIR = Path(__file__).parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"


def setup_logging(level=logging.INFO) -> logging.Logger:
    """Configura e retorna o logger do toolkit."""
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / f"cybersec_{datetime.now().strftime('%Y%m%d')}.log"

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ],
    )
    # Silencia logs ruidosos de libs externas
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    logger = logging.getLogger("cybersec")
    return logger


def load_config() -> dict:
    """Carrega configuração do arquivo YAML."""
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {}


def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Calcula o hash criptográfico de um arquivo."""
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    h = algos.get(algorithm, hashlib.sha256)()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError) as e:
        return f"ERROR:{e}"


def compute_hashes(filepath: str) -> dict:
    """Calcula múltiplos hashes de uma vez (mais eficiente)."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except (PermissionError, OSError):
        return {"md5": None, "sha1": None, "sha256": None}


def print_banner(title: str, color: str = "blue"):
    """Exibe um banner estilizado para o comando atual."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    panel = Panel(
        Text(f"  {title}  ", style=f"bold {color}", justify="center"),
        subtitle=f"[dim]{now}[/dim]",
        border_style=color,
        padding=(0, 4),
    )
    console.print(panel)


def check_virustotal(file_hash: str, api_key: str):
    """Consulta o VirusTotal pela hash de um arquivo."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        console.print("[dim]Consultando VirusTotal...[/]")
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 404:
            console.print("[yellow]⚠[/]  Hash não encontrado no VirusTotal (arquivo pode ser benigno ou desconhecido).")
            return

        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            color = "green" if malicious == 0 else "red"
            icon = "✔" if malicious == 0 else "✘"
            console.print(
                f"[{color}]{icon}[/]  VirusTotal: [bold]{malicious}[/]/{total} motores detectaram como malicioso "
                f"([yellow]{suspicious}[/] suspeito)"
            )

            if malicious > 0:
                names = list(data["data"]["attributes"].get("popular_threat_classification", {}).get("popular_threat_name", []))
                if names:
                    threat = names[0].get("value", "Desconhecido")
                    console.print(f"    Ameaça identificada: [red bold]{threat}[/]")
        else:
            console.print(f"[red]✗[/] Erro na API do VirusTotal: HTTP {r.status_code}")

    except requests.RequestException as e:
        console.print(f"[red]✗[/] Falha na requisição: {e}")


def format_size(size_bytes: int) -> str:
    """Formata bytes em unidade legível."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def is_binary(filepath: str) -> bool:
    """Detecta se um arquivo é binário."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except OSError:
        return False
