#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  full_audit.sh — Auditoria completa automatizada do sistema
#  Uso: sudo ./scripts/full_audit.sh [--quick]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

QUICK_FLAG="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$ROOT_DIR/reports/audit_$(date +%Y%m%d_%H%M%S).log"

[[ -d "$ROOT_DIR/.venv" ]] && source "$ROOT_DIR/.venv/bin/activate"
mkdir -p "$ROOT_DIR/reports"

# Redireciona stdout e stderr para o log também
exec > >(tee -a "$LOG_FILE") 2>&1

echo "╔══════════════════════════════════════════════════╗"
echo "║   CyberSec Toolkit — Auditoria Completa          ║"
echo "║   $(date '+%d/%m/%Y %H:%M:%S')                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Informações do sistema
echo "[ Informações do Sistema ]"
echo "  OS        : $(uname -srm)"
echo "  Hostname  : $(hostname -f 2>/dev/null || hostname)"
echo "  Uptime    : $(uptime -p 2>/dev/null || uptime)"
echo "  Usuário   : $(whoami)"
echo ""

# Verificações de segurança básicas do sistema operacional
echo "[ Verificações de SO ]"

# Usuários com shell válido
echo "  → Usuários com shell de login:"
grep -E "(/bash|/sh|/zsh|/fish)$" /etc/passwd | awk -F: '{print "     " $1 " (UID:" $3 ")"}' 2>/dev/null || echo "     N/A"

# Últimos logins
echo "  → Últimos logins (last 5):"
last -n 5 2>/dev/null | head -5 | awk '{print "     " $0}' || echo "     N/A"

# Tentativas de login falhadas
echo "  → Tentativas de login falhadas:"
if [[ -f /var/log/auth.log ]]; then
    grep -c "Failed password" /var/log/auth.log 2>/dev/null | awk '{print "     " $0 " tentativa(s) no auth.log"}' || echo "     0"
elif [[ -f /var/log/secure ]]; then
    grep -c "Failed password" /var/log/secure 2>/dev/null | awk '{print "     " $0 " tentativa(s)"}' || echo "     0"
else
    echo "     Log de auth não encontrado"
fi

# Processos SUID
echo "  → Arquivos SUID suspeitos:"
find / -perm -4000 -type f 2>/dev/null | grep -v -E "^/(usr/bin|usr/lib|bin|sbin)" | head -10 | awk '{print "     " $0}' || echo "     Nenhum fora do padrão"

echo ""
echo "[ Iniciando Análise via CyberSec Toolkit ]"
echo ""

# Chama a auditoria completa do Python
CMD="python3 $ROOT_DIR/main.py audit / --output html"
[[ "$QUICK_FLAG" == "--quick" ]] && CMD="$CMD --quick"
eval $CMD

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Log salvo em: $LOG_FILE"
echo "  Relatórios em: $ROOT_DIR/reports/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
