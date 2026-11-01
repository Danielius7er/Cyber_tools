#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  baseline.sh — Cria ou verifica baselines de integridade
#
#  Uso:
#    ./scripts/baseline.sh create [DIRETÓRIO] [NOME]
#    ./scripts/baseline.sh check  [DIRETÓRIO] [NOME]
#    ./scripts/baseline.sh watch  [DIRETÓRIO] [INTERVALO]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

ACTION="${1:-help}"
TARGET="${2:-.}"
NAME="${3:-default}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

[[ -d "$ROOT_DIR/.venv" ]] && source "$ROOT_DIR/.venv/bin/activate"

case "$ACTION" in
  create|baseline)
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Criando baseline: '$NAME' em '$TARGET'"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    python3 "$ROOT_DIR/main.py" integrity baseline "$TARGET" --name "$NAME"
    ;;

  check|verify)
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Verificando integridade: '$NAME' em '$TARGET'"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    python3 "$ROOT_DIR/main.py" integrity check "$TARGET" --name "$NAME" --save
    ;;

  watch)
    INTERVAL="${3:-10}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Modo Watch: '$TARGET' (intervalo: ${INTERVAL}s)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    python3 "$ROOT_DIR/main.py" integrity watch "$TARGET" --interval "$INTERVAL"
    ;;

  help|*)
    echo "Uso:"
    echo "  $0 create [DIRETÓRIO] [NOME]     — Cria baseline"
    echo "  $0 check  [DIRETÓRIO] [NOME]     — Verifica integridade"
    echo "  $0 watch  [DIRETÓRIO] [INTERVALO]— Modo watch em tempo real"
    echo ""
    echo "Exemplos:"
    echo "  $0 create /etc sistema"
    echo "  $0 check  /etc sistema"
    echo "  $0 watch  /var/www 15"
    ;;
esac
