#!/usr/bin/env bash
# =============================================================================
# lib.sh — funções comuns dos scripts de inicialização (Prática Offline 1).
# Uso: source "$(dirname "$0")/lib.sh"
# =============================================================================

# Diretório raiz do projeto (pasta acima de scripts/)
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLASSES="$PROJ/bin"
LOG_DIR="$PROJ/logs"
JAVA_BIN="${JAVA:-java}"

# -----------------------------------------------------------------------------
# compilar(): recompila todas as fontes para bin/
# -----------------------------------------------------------------------------
compilar() {
  echo "[build] Compilando o projeto para $CLASSES ..."
  mkdir -p "$CLASSES" "$LOG_DIR"
  if ! javac -d "$CLASSES" $(find "$PROJ/src" -name '*.java'); then
    echo "[build] ERRO na compilação." >&2
    exit 1
  fi
  echo "[build] OK."
}

# -----------------------------------------------------------------------------
# abrir(): abre um componente em uma janela de terminal nova.
#          Se não houver terminal gráfico, roda em segundo plano e grava a
#          saída em logs/<slug>.log.
#   uso: abrir "<titulo>" <classe> [args...]
# -----------------------------------------------------------------------------
abrir() {
  local titulo="$1"; shift
  local slug; slug="$(echo "$titulo" | tr ' A-Z' '_a-z')"
  local runner="$LOG_DIR/runner_${slug}.sh"

  # Monta a linha de comando com aspas seguras (preserva args com espaço)
  local cmd; cmd="$(printf '%q' "$JAVA_BIN") -cp $(printf '%q' "$CLASSES")"
  local a
  for a in "$@"; do cmd+=" $(printf '%q' "$a")"; done

  # Cria um pequeno script "runner" para evitar problemas de aspas nos terminais
  {
    echo '#!/usr/bin/env bash'
    echo "cd $(printf '%q' "$PROJ")"
    echo "$cmd"
  } > "$runner"
  chmod +x "$runner"

  if command -v gnome-terminal >/dev/null 2>&1; then
    gnome-terminal --title="$titulo" -- bash -c "bash $(printf '%q' "$runner"); echo; echo '[encerrado — ENTER para fechar]'; exec bash"
  elif command -v xfce4-terminal >/dev/null 2>&1; then
    xfce4-terminal --title="$titulo" -x bash -c "bash $(printf '%q' "$runner"); exec bash" &
  elif command -v konsole >/dev/null 2>&1; then
    konsole -p tabtitle="$titulo" -e bash -c "bash $(printf '%q' "$runner"); exec bash" &
  elif command -v x-terminal-emulator >/dev/null 2>&1; then
    x-terminal-emulator -T "$titulo" -e bash -c "bash $(printf '%q' "$runner"); exec bash" &
  elif command -v xterm >/dev/null 2>&1; then
    xterm -T "$titulo" -e bash -c "bash $(printf '%q' "$runner"); exec bash" &
  else
    echo "[start] Sem terminal gráfico: rodando '$titulo' em background -> logs/${slug}.log"
    echo "        (componentes interativos precisam de terminal; veja o README)"
    ( nohup bash "$runner" >"$LOG_DIR/${slug}.log" 2>&1 & )
  fi
}

# -----------------------------------------------------------------------------
# esperar(): pausa simples, usada para dar tempo de subir um componente.
# -----------------------------------------------------------------------------
esperar() {
  sleep "${1:-2}"
}
