#!/usr/bin/env bash
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLASSES="$PROJ/bin"
LOG_DIR="$PROJ/logs"
JAVA_BIN="${JAVA:-java}"

compilar() {
  echo "[build] Compilando o projeto para $CLASSES ..."
  mkdir -p "$CLASSES" "$LOG_DIR"
  if ! find "$PROJ/src" -name '*.java' -print0 | xargs -0 javac -d "$CLASSES"; then
    echo "[build] ERRO na compilação." >&2
    exit 1
  fi
  echo "[build] OK."
}

abrir() {
  local titulo="$1"; shift
  local slug; slug="$(echo "$titulo" | tr ' A-Z' '_a-z')"
  local runner="$LOG_DIR/runner_${slug}.sh"

  local cmd; cmd="$(printf '%q' "$JAVA_BIN") -cp $(printf '%q' "$CLASSES")"
  local a
  for a in "$@"; do cmd+=" $(printf '%q' "$a")"; done

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

esperar() {
  sleep "${1:-2}"
}
