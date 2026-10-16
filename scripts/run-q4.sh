#!/usr/bin/env bash
# Questão 4 — CDN (Origin + Edges + GeoDNS + Cliente).
source "$(dirname "$0")/lib.sh"

compilar

echo "[q4] Subindo Origem, 3 Edges, GeoDNS e o ClienteCDN."

abrir "Q4 - OriginServer" q4_cdn.OriginServer
esperar 3

abrir "Q4 - Edge 8001" q4_cdn.EdgeServer 8001
abrir "Q4 - Edge 8002" q4_cdn.EdgeServer 8002
abrir "Q4 - Edge 8003" q4_cdn.EdgeServer 8003
esperar 3

abrir "Q4 - GeoDNS" q4_cdn.GeoDNS
esperar 1

abrir "Q4 - ClienteCDN" q4_cdn.ClienteCDN

echo "[q4] Pronto. 'BRASIL' -> Edge 8001; 'EUROPA' -> 8002; 'AMERICA/EUA' -> 8003."
echo "      Caso 2 (INVALIDATE): digite 'invalidate arquivo20.ext' no console da Origem."
