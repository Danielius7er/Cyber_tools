#!/usr/bin/env bash
# ──────────────────────────────────────────────────
#  CyberSec Toolkit — Script de Instalação
# ──────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      CyberSec Toolkit — Setup v1.0       ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_ok()   { echo -e "${GREEN}✔${NC}  $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
log_err()  { echo -e "${RED}✗${NC}  $1"; }
log_info() { echo -e "${CYAN}→${NC}  $1"; }

banner

# ── Verificar Python ────────────────────────────────────────────
log_info "Verificando Python 3.9+..."
if ! command -v python3 &>/dev/null; then
    log_err "Python 3 não encontrado. Instale Python 3.9+."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 9 ]]; then
    log_err "Python $PY_VERSION encontrado. É necessário Python 3.9+."
    exit 1
fi
log_ok "Python $PY_VERSION encontrado."

# ── Criar ambiente virtual ──────────────────────────────────────
log_info "Criando ambiente virtual (.venv)..."
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    log_ok "Ambiente virtual criado."
else
    log_warn "Ambiente virtual já existe. Reutilizando."
fi

# ── Ativar e instalar dependências ─────────────────────────────
log_info "Instalando dependências..."
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
log_ok "Dependências instaladas."

# ── Criar estrutura de diretórios ──────────────────────────────
log_info "Criando estrutura de diretórios..."
mkdir -p reports logs data/baselines data/signatures
log_ok "Diretórios criados."

# ── Permissões dos scripts bash ────────────────────────────────
log_info "Configurando permissões dos scripts..."
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x main.py
log_ok "Permissões configuradas."

# ── Alias / symlink opcional ────────────────────────────────────
INSTALL_ALIAS=false
if [[ "${1:-}" == "--install-alias" ]]; then
    INSTALL_ALIAS=true
fi

if $INSTALL_ALIAS; then
    LINK_PATH="/usr/local/bin/cybersec"
    SCRIPT_PATH="$(pwd)/main.py"
    echo "#!/bin/bash" > /tmp/cybersec_wrapper
    echo "source $(pwd)/.venv/bin/activate && python3 $SCRIPT_PATH \"\$@\"" >> /tmp/cybersec_wrapper
    sudo mv /tmp/cybersec_wrapper "$LINK_PATH"
    sudo chmod +x "$LINK_PATH"
    log_ok "Comando 'cybersec' disponível globalmente."
fi

# ── Verificação final ──────────────────────────────────────────
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo -e "${GREEN}${BOLD}  Instalação concluída com sucesso!${NC}"
echo -e "${BOLD}──────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${CYAN}Uso:${NC}"
echo -e "    ${BOLD}source .venv/bin/activate${NC}"
echo -e "    ${BOLD}python main.py --help${NC}"
echo ""
echo -e "  ${CYAN}Exemplos rápidos:${NC}"
echo -e "    python main.py scan ."
echo -e "    python main.py integrity baseline /etc"
echo -e "    python main.py netcheck -s"
echo -e "    python main.py processes --suspicious"
echo -e "    python main.py audit / --quick"
echo ""
