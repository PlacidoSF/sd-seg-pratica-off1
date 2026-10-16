# Prática Offline 1 — Segurança Computacional (UFERSA)

Projeto da disciplina **Segurança Computacional** que
implementa, com **Sockets TCP/UDP e Threads**, os quatro enunciados da *Prática Offline 1* sempre com **criptografia híbrida** em todas as
mensagens.

- **Disciplina:** Segurança Computacional — 2026.2
- **Trabalho:** Prática Offline 1
- **Tecnologias:** Java (JDK 17+), Sockets TCP/UDP, Threads, JCA/JCE (`javax.crypto`, `java.security`)

---

## 1. Visão geral

Cada componente roda como um **processo independente** (todos possuem `main`), e toda
comunicação entre processos trafega **cifrada e autenticada**. O envelope de rede é o mesmo
para todas as questões (`shared/Pacote`).

| Questão | Tema | Sockets | Componentes |
|---|---|---|---|
| **Q1** | Mini-DNS (resolução de nomes) | UDP | `ServidorDNS`, `ClienteComum`, `ClienteRegistrador` |
| **Q2** | Descoberta de serviços + load balancing | TCP | `ServidorDiretorio`, `ServidorCalculadora`, `ClienteDiscovery` |
| **Q3** | Nomeação P2P (anel P0–P5) | TCP | `NoP2P` (6 processos) |
| **Q4** | CDN (Origin / Edge / GeoDNS / Cliente) | TCP + UDP | `OriginServer`, `EdgeServer`, `GeoDNS`, `ClienteCDN` |

### Estrutura de pastas

```
sd-seg-pratica-off1/
├── src/
│   ├── crypto/        Núcleo criptográfico compartilhado (AES, RSA, SHA-256, CryptoManager)
│   ├── shared/        Pacote.java — envelope de rede (texto cifrado + assinatura)
│   ├── q1_minidns/    Questão 1
│   ├── q2_discovery/  Questão 2
│   ├── q3_p2p/        Questão 3
│   └── q4_cdn/        Questão 4
├── bin/               Classes compiladas (`.class`)
├── scripts/           Scripts de compilação e inicialização
```

---

## 2. Arquitetura de segurança

Toda mensagem de aplicação usa **criptografia híbrida**, no formato do envelope `Pacote`:

```
Pacote = [ textoCifrado (AES-256-CBC) , assinatura (RSA-2048) ]
```

**Fluxo de envio** (`CryptoManager.gerarPacote`):
1. A mensagem em claro é cifrada com **AES-256/CBC/PKCS5Padding** (IV aleatório anexado ao texto cifrado).
2. Calcula-se o **hash SHA-256** do texto cifrado.
3. O hash é **assinado com a chave privada RSA** do remetente.

**Fluxo de recebimento** (`CryptoManager.abrirPacote`):
1. Recalcula o hash SHA-256 do texto cifrado recebido.
2. Decifra a assinatura com a **chave pública RSA** do remetente.
3. Compara os dois valores com `MessageDigest.isEqual` (comparação em tempo constante).
4. Se houver divergência, dispara `SecurityException` e a mensagem é descartada.
5. Só então decifra o texto com AES.

**Handshake de sessão** (todas as questões):
1. O servidor envia sua **chave pública RSA** ao cliente.
2. O cliente gera uma **chave simétrica AES de sessão**, cifra-a com a chave pública RSA do
   servidor e envia (chave pública do cliente + chave AES cifrada).
3. A partir daí, os dois lados compartilham a mesma chave AES e conhecem a chave pública do
   outro, permitindo cifrar e verificar assinaturas.


---

## 3. Como compilar

Pré-requisito: **JDK 17 ou superior** (`java -version`).

```bash
# A partir da raiz do projeto
./scripts/compilar.sh
```

O `compilar.sh` executa o equivalente a:

```bash
javac -d bin $(find src -name '*.java')
```

---

## 4. Como executar

Há um script por questão, que compila e sobe todos os processos na ordem correta. Cada
componente abre em uma **janela de terminal** própria (quando há terminal gráfico disponível);
caso contrário, o processo roda em segundo plano e a saída vai para `logs/`.

```bash
./scripts/run-q1.sh     # Mini-DNS
./scripts/run-q2.sh     # Descoberta de serviços
./scripts/run-q3.sh     # Anel P2P
./scripts/run-q4.sh     # CDN
```

Para encerrar tudo de uma vez:

```bash
./scripts/parar.sh
```

> **Importante:** as questões **não devem rodar ao mesmo tempo**, pois Q2 e Q4 utilizam as
> mesmas portas (8001–8003) para papéis diferentes.

### Execução manual (referência)

Caso prefira rodar cada processo manualmente, use `java -cp bin <Classe>`. A tabela abaixo
resume portas e argumentos.

| Questão | Ordem de inicialização | Comando |
|---|---|---|
| Q1 | 1) DNS 2) clientes 3) registrador | `java -cp bin q1_minidns.ServidorDNS` / `...ClienteComum` / `...ClienteRegistrador` |
| Q2 | 1) Diretório 2) calculadoras 3) cliente | `java -cp bin q2_discovery.ServidorDiretorio` / `java -cp bin q2_discovery.ServidorCalculadora <porta> "<serviço>"` / `...ClienteDiscovery` |
| Q3 | nós de P0 a P5 | `java -cp bin q3_p2p.NoP2P <0..5>` |
| Q4 | 1) Origem 2) Edges 3) GeoDNS 4) Cliente | `java -cp bin q4_cdn.OriginServer` / `...EdgeServer <porta>` / `...GeoDNS` / `...ClienteCDN` |

---

## 5. Questão 1 — Mini-DNS (UDP)

**Servidor:** `q1_minidns.ServidorDNS` — porta UDP **5000**. Mantém o mapa *nome → IP*:

```
servidor1 → 192.168.0.10   ...   servidor10 → 192.168.0.100
```

**Protocolo (UDP):** um inteiro de operação seguido de objetos serializados.

| Op | Significado |
|---|---|
| `0` | Cliente pede a chave pública RSA do DNS |
| `1` | Handshake: cliente envia sua chave pública + chave AES cifrada |
| `2` | Mensagem de dados (consulta/atualização/erro), dentro de um `Pacote` |
| `3` | Notificação de atualização (binding dinâmico) enviada pelo DNS |

**Comandos:** `CONSULTAR <nome>` e `ATUALIZAR <nome> <ip>`.

**Casos de teste demonstrados pelo `ClienteComum`:**
- **Caso 1** — consulta `servidor1` → DNS responde `192.168.0.10` (cifrado e assinado).
- **Caso 3.A** — consulta `servidor99` → `Erro na entrada de dados. Tente outra vez!`.
- **Caso 3.B** — pacote com assinatura adulterada → DNS descarta silenciosamente (timeout no cliente).
- **Caso 2** — `ClienteRegistrador` envia `ATUALIZAR servidor1 192.168.0.111`; o DNS atualiza o
  binding e **notifica todos os clientes conectados**, que validam e atualizam a tabela local.

---

## 6. Questão 2 — Descoberta de serviços (TCP)

**Diretório:** `q2_discovery.ServidorDiretorio` — TCP **6001**. Guarda o catálogo
*serviço → lista de `ip:porta`*.

**Servidores de calculadora:** `q2_discovery.ServidorCalculadora <porta> "<serviço>"`.
Ao subir, cada um se **registra** no Diretório por um canal seguro. Serviços suportados:
`Calcular soma`, `Calcular subtração`, `Calcular multiplicação`, `Calcular divisão`.

**Comandos:** `REGISTRAR <servico_com_underscore> <ip:porta>` e `BUSCAR <servico_com_underscore>`.

**Cliente:** `q2_discovery.ClienteDiscovery` faz:
- **Caso 1** — consulta o Diretório e descobre os servidores ativos (dois serviços).
- **Caso 2** — **load balancing round-robin**: as requisições (`10+20`, `5*4`, …) alternam
  entre os servidores, cada chamada abrindo uma sessão AES+RSA própria.
- **Caso 3** — entrada inválida (`Calcular modulo`) e pacote adulterado (o servidor corta a conexão).

Por padrão, o `run-q2.sh` sobe **S1 (8001, soma)**, **S2 (8002, soma)** e **S3 (8003, multiplicação)**.

---

## 7. Questão 3 — Anel P2P (TCP)

`q3_p2p.NoP2P <id>` cria um nó do anel. Portas: **9000 + id** (P0→9000 … P5→9005).
Cada nó conhece seu **sucessor** e **antecessor** e guarda uma faixa de 10 arquivos:

```
P0: 1–10 | P1: 11–20 | P2: 21–30 | P3: 31–40 | P4: 41–50 | P5: 51–60
```

**Protocolo de aplicação:** mensagens em texto (`BUSCA|<alvo>|<origem>` e
`RESPOSTA|<destino>|<conteudo>`), transportadas cifradas salto a salto.

**Comandos do menu:** `buscar arquivoX.ext`, `fraude arquivoX.ext`, `sair`.
- **Caso 1** — `buscar arquivo35.ext` (em P0): a busca salta P0→P1→P2→P3; P3 encontra o arquivo
  e devolve a resposta cifrada até P0.
- **Caso 2** — entrada inválida (`arquivo99.ext`, `arquivoABC.ext`): validada **antes** de
  qualquer criptografia/conexão; imprime o erro sem propagar.
- **Caso 3** — `fraude arquivoX.ext`: a assinatura do pacote é corrompida; o nó seguinte
  detecta a falha de integridade, descarta e **interrompe o repasse**, registrando no log.

---

## 8. Questão 4 — CDN (TCP + UDP)

| Componente | Classe | Porta | Papel |
|---|---|---|---|
| Servidor de Origem | `q4_cdn.OriginServer` | TCP **8000** | Base mestre com 1000 arquivos; empurra `INVALIDATE` |
| Edge Servers | `q4_cdn.EdgeServer` | TCP **8001/8002/8003** | Cache LRU com **TTL de 15s**; cache hit/miss |
| Router / GeoDNS | `q4_cdn.GeoDNS` | UDP **5453** | Avalia a região fictícia e indica o Edge mais próximo |
| Cliente | `q4_cdn.ClienteCDN` | — | Consulta a rota e baixa o arquivo do Edge |

**Protocolo de aplicação (texto dentro do `Pacote`):**
- `ONDE <arquivo> <região>` — consulta de rota ao GeoDNS (ex.: `ONDE arquivo20.ext BRASIL`).
- `GET /arquivoN.ext` — requisição do cliente ao Edge.
- Resposta do Edge: `200 OK | Cache: HIT|MISS | Length: N` seguido do conteúdo.
- `INVALIDATE /arquivoN.ext` — comando da Origem para os Edges (invalidação ativa).

**Regiões atendidas pelo GeoDNS:** `BRASIL → 8001`, `EUROPA → 8002`, `AMERICA/EUA → 8003`;
regiões desconhecidas caem no Edge padrão `127.0.0.1:8001`.

**Casos de teste demonstrados pelo `ClienteCDN`:**
- **Caso 1** — primeiro `GET /arquivo20.ext` = **MISS** (busca na Origem); segundo = **HIT** (mais rápido).
- **Caso 2** — expiração por **TTL** (aguarda 16s e repete → MISS) e **INVALIDATE** ativo
  (digite `invalidate arquivo20.ext` no console da Origem).
- **Caso 3** — nome inválido (`GET arquivo20`, `GET /arquivoXYZ.ext`) e pacote com assinatura
  adulterada (o Edge encerra a conexão sem corromper o cache).

---

## 9. Portas (resumo)

| Porta | Protocolo | Componente |
|---|---|---|
| 5000 | UDP | Mini-DNS (Q1) |
| 5453 | UDP | GeoDNS (Q4) |
| 6001 | TCP | Diretório de serviços (Q2) |
| 8000 | TCP | Servidor de Origem (Q4) |
| 8001–8003 | TCP | Calculadoras (Q2) / Edges (Q4) |
| 9000–9005 | TCP | Nós P2P P0–P5 (Q3) |
