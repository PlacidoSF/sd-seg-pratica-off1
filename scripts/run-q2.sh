#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"

compilar

echo "[q2] Subindo Diretório, três calculadoras e o ClienteDiscovery."

abrir "Q2 - Diretorio" q2_discovery.ServidorDiretorio
esperar 3

abrir "Q2 - Calc S1 (8001 soma)" q2_discovery.ServidorCalculadora 8001 "Calcular soma"
abrir "Q2 - Calc S2 (8002 soma)" q2_discovery.ServidorCalculadora 8002 "Calcular soma"
abrir "Q2 - Calc S3 (8003 multiplicacao)" q2_discovery.ServidorCalculadora 8003 "Calcular multiplicação"

esperar 3
abrir "Q2 - ClienteDiscovery" q2_discovery.ClienteDiscovery

echo "[q2] Pronto. Round-robin alterna entre S1 (8001) e S2 (8002)."
