#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

compilar

echo "[q3] Subindo os 6 nós P0..P5 (o anel se forma conforme conectam)."
for i in 0 1 2 3 4 5; do
  abrir "Q3 - NoP2P P$i" q3_p2p.NoP2P "$i"
  esperar 1
done

echo "[q3] Pronto. Console de P0: 'buscar arquivo35.ext' (Caso 1) ou 'fraude arquivo35.ext' (Caso 3)."
echo "      Caso 2 (entrada inválida): 'buscar arquivo99.ext' ou 'buscar arquivoABC.ext'."
