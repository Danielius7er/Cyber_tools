#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  monitor_processes.sh — Monitoramento contínuo de processos
#  Uso: ./scripts/monitor_processes.sh [INTERVALO_SEGUNDOS]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

INTERVAL="${1:-30}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

[[ -d "$ROOT_DIR/.venv" ]] && source "$ROOT_DIR/.venv/bin/activate"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberSec Toolkit — Monitoramento de Processos"
echo "  Intervalo: ${INTERVAL}s | Ctrl+C para parar"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

trap 'echo -e "\n  Monitoramento encerrado."; exit 0' INT TERM

ITERATION=0
while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date '+%d/%m/%Y %H:%M:%S')

    echo ""
    echo "━━━━ Verificação #${ITERATION} — ${TIMESTAMP} ━━━━"

    python3 "$ROOT_DIR/main.py" processes --suspicious --top 15

    # Alerta se houver processos suspeitos (exit code 1)
    if [[ $? -ne 0 ]]; then
        echo "⚠  ALERTA: Processos suspeitos detectados!"
        # Aqui poderia enviar email, notificação, etc.
    fi

    echo ""
    echo "  Próxima verificação em ${INTERVAL}s..."
    sleep "$INTERVAL"
done
