#!/usr/bin/env bash
# =============================================================================
# parar.sh — encerra apenas os processos *java* do projeto (Q1 a Q4).
# Filtra por nome do executável ("java") para não derrubar o shell que chamou
# o script (que pode conter os padrões no seu próprio command line).
# =============================================================================

encerrar() {
  local pat="$1"
  local pid
  for pid in $(pgrep -f "$pat" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    if [ "$(ps -o comm= -p "$pid" 2>/dev/null)" = "java" ]; then
      if kill "$pid" 2>/dev/null; then
        echo "  -> encerrado java PID $pid ($pat)"
      fi
    fi
  done
}

echo "[stop] Encerrando processos Java do projeto..."
encerrar "q1_minidns"
encerrar "q2_discovery"
encerrar "q3_p2p"
encerrar "q4_cdn"
echo "[stop] Concluído."
