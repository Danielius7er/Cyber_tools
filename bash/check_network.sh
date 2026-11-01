#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  check_network.sh — Análise rápida de rede e conexões
#  Uso: ./scripts/check_network.sh [--save]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

SAVE_FLAG="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

[[ -d "$ROOT_DIR/.venv" ]] && source "$ROOT_DIR/.venv/bin/activate"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberSec Toolkit — Análise de Rede"
echo "  $(date '+%d/%m/%Y %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Informações brutas do sistema antes do toolkit
echo ""
echo "[ Informações Rápidas do Sistema ]"
echo "  Hostname : $(hostname)"
echo "  IP Local : $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A')"

# Conexões estabelecidas
echo ""
echo "[ Conexões TCP ESTABLISHED ]"
ss -tnp state established 2>/dev/null | head -30 || \
  netstat -tnp 2>/dev/null | grep ESTABLISHED | head -30 || \
  echo "  (instale ss ou netstat para esta seção)"

# Portas em escuta
echo ""
echo "[ Portas em LISTEN ]"
ss -tlnp 2>/dev/null | grep LISTEN | head -20 || \
  netstat -tlnp 2>/dev/null | grep LISTEN | head -20 || \
  echo "  N/A"

echo ""
echo "[ Análise Avançada via CyberSec Toolkit ]"

CMD="python3 $ROOT_DIR/main.py netcheck -c -p -s"
[[ "$SAVE_FLAG" == "--save" ]] && CMD="$CMD --save"
eval $CMD
