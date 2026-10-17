#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

compilar

N="${1:-3}"
echo "[q1] Subindo 1 ServidorDNS, $N ClienteComum (C1..C$N) e 1 ClienteRegistrador."

abrir "Q1 - ServidorDNS" q1_minidns.ServidorDNS
esperar 3

for i in $(seq 1 "$N"); do
  abrir "Q1 - ClienteComum C$i" q1_minidns.ClienteComum
done

esperar 2
abrir "Q1 - ClienteRegistrador" q1_minidns.ClienteRegistrador

echo "[q1] Pronto. Caso 2: o Registrador atualiza 'servidor1' e o DNS notifica C1..C$N."
