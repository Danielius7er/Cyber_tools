#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  quick_scan.sh — Varredura rápida de diretório alvo
#  Uso: ./scripts/quick_scan.sh [DIRETÓRIO] [--save]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

TARGET="${1:-.}"
SAVE_FLAG="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Ativa venv se existir
if [[ -d "$ROOT_DIR/.venv" ]]; then
    source "$ROOT_DIR/.venv/bin/activate"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberSec Toolkit — Varredura Rápida"
echo "  Alvo: $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CMD="python3 $ROOT_DIR/main.py scan \"$TARGET\" -t 4"
[[ "$SAVE_FLAG" == "--save" ]] && CMD="$CMD --save --output html"

eval $CMD

EXIT_CODE=$?
if [[ $EXIT_CODE -eq 0 ]]; then
    echo ""
    echo "✔  Varredura finalizada: nenhuma ameaça crítica encontrada."
else
    echo ""
    echo "⚠  Ameaças detectadas! Revise o relatório em reports/"
fi
exit $EXIT_CODE
