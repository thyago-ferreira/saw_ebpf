# SAW_eBPF — Monitoramento Passivo de Rede via eBPF

Agente de captura de pacotes de alta performance utilizando **eBPF socket_filter** e **Ring Buffer**, projetado para alimentar o sistema SAW com dados brutos de rede em tempo real.

## Arquitetura

```
┌──────────────────────────────────────────────────────┐
│                    Kernel Space                       │
│                                                       │
│  NIC → Socket Filter (eBPF) → Ring Buffer (1 MiB)    │
│          ↓ captura passiva        ↓ zero-copy         │
└──────────────────────────┬───────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────┐
│                    User Space                         │
│                                                       │
│  saw_ebpf.py (Loader)                                 │
│    ├── CLI (argparse) → injeta parâmetros no código C │
│    ├── Compilação JIT via BCC                         │
│    └── Leitura do Ring Buffer → saída HEX + UTF-8    │
└──────────────────────────────────────────────────────┘
```

## Instalação

Copie e cole os 3 comandos abaixo no terminal da máquina monitorada:

```bash
git clone https://github.com/thyago-ferreira/saw_ebpf.git
cd saw_ebpf
sudo bash install.sh
```

O instalador automático detecta a distribuição (Debian/Ubuntu), instala os cabeçalhos do kernel corretos, o BCC com o nome de pacote certo para o seu sistema, e valida tudo antes de finalizar.

> **Nota:** Se o kernel estiver desatualizado, o instalador oferece atualizar e reiniciar automaticamente. Após o reboot, execute `sudo bash install.sh` novamente para concluir.

### Instalação manual (alternativa)

```bash
git clone https://github.com/thyago-ferreira/saw_ebpf.git
cd saw_ebpf
sudo apt update && sudo apt upgrade -y
sudo reboot  # se o kernel foi atualizado
sudo apt install -y linux-headers-$(uname -r) python3-bpfcc bpfcc-tools  # Debian
# ou: sudo apt install -y linux-headers-$(uname -r) python3-bcc bpfcc-tools  # Ubuntu
python3 -c "from bcc import BPF; print('BCC OK')"
```

## Requisitos

| Componente         | Versão Mínima        |
|--------------------|----------------------|
| **Kernel Linux**   | 5.10+                |
| **Distribuição**   | Debian (recomendado) |
| **Python**         | 3.8+                 |
| **BCC**            | 0.18+                |

## Como Rodar

### Modo Interativo (recomendado para primeira vez)

Basta executar sem argumentos. O SAW_eBPF detecta as interfaces do sistema e guia o usuário passo a passo:

```bash
sudo python3 saw_ebpf.py
```

O assistente interativo apresenta:

```
============================================================
  SAW_eBPF — Configuração Interativa
============================================================

[Passo 1/4] Selecione a interface de rede
------------------------------------------------------------
  #    Interface        Estado     Endereço IP
  ———— ———————————————— —————————— ————————————————————
  1    eth0             UP         192.168.1.10/24  (ativa)
  2    lo               UNKNOWN    127.0.0.1/8  (loopback — testes locais)
  3    docker0          DOWN       172.17.0.1/16

  Digite o numero da interface [1-3]: 1

[Passo 2/4] Filtrar por porta?
------------------------------------------------------------
  Portas comuns:
    80/443  — HTTP/HTTPS (trafego web)
    8080    — APIs e proxies reversos
    9090    — Prometheus / GPS / servicos customizados
    5432    — PostgreSQL
    3306    — MySQL
    0       — Todas as portas (modo generico)

  Digite a porta para filtrar [0 = todas]: 9090

[Passo 3/4] Tamanho maximo do payload
------------------------------------------------------------
  Valores recomendados:
    256   — Leve (apenas cabecalhos HTTP, ideal para alto volume)
    1024  — Padrao (captura a maioria dos payloads de APIs REST)
    2048  — Completo (requisicoes/respostas maiores, JSON extenso)
    4096  — Maximo (protocolos binarios, arquivos em transito)

  Tamanho em bytes [padrao: 1024]: 2048

[Passo 4/4] Transmissao remota
------------------------------------------------------------
  Os eventos capturados serao enviados via TCP para sua maquina.
  Use 127.0.0.1 para tunel SSH local (bypass de firewall).

  IP do destino (ex: 127.0.0.1): 127.0.0.1
  Porta do destino [padrao: 9999]: 9999
  -> Transmitindo para: 127.0.0.1:9999

============================================================
  Resumo da configuracao:
    Interface:  eth0
    Filtro:     porta 9090
    Payload:    2048 bytes
    Remoto:     127.0.0.1:9999
============================================================
  Iniciar captura? [S/n]: S
```

### Modo Direto (CLI)

Para automação ou uso avançado, passe os argumentos diretamente:

```bash
# Capturar tudo na loopback e transmitir para localhost
sudo python3 saw_ebpf.py -i lo -s 2048 --remote-host 127.0.0.1

# Monitorar porta 9090 e transmitir via túnel SSH
sudo python3 saw_ebpf.py -i eth0 -p 9090 --remote-host 127.0.0.1

# Monitorar HTTP com payload reduzido, porta remota customizada
sudo python3 saw_ebpf.py -i eth0 -p 80 -s 512 --remote-host 192.168.1.5 --remote-port 8888
```

### Opções da CLI

```
uso: saw_ebpf.py [-h] [-i INTERFACE] [-p PORT] [-s SIZE]
                 [--remote-host HOST] [--remote-port PORT]

  -i, --interface     Interface de rede. Sem este argumento, entra no modo interativo.
  -p, --port          Porta para filtrar (padrão: 0 = todas as portas)
  -s, --size          Tamanho máximo do payload em bytes (padrão: 1024)
  --remote-host       IP de destino para transmissão TCP (obrigatório no modo CLI)
  --remote-port       Porta de destino para transmissão TCP (padrão: 9999)
```

## Transmissão Remota

O SAW_eBPF pode enviar cada evento capturado via **TCP** em formato **JSON** para uma máquina remota.

### Como funciona

```
┌─ Máquina Monitorada ─────────────────────┐     ┌─ Sua Máquina ──────────┐
│                                           │     │                        │
│  saw_ebpf.py ──TCP──► 127.0.0.1:9999 ────────► │  Receptor (nc/script)  │
│     │                (túnel SSH)          │     │                        │
│     └── saída local (terminal)            │     └────────────────────────┘
└───────────────────────────────────────────┘
```

### Receber eventos na sua máquina

**Opção 1 — netcat (teste rápido):**

```bash
nc -lk 9999
```

**Opção 2 — via túnel SSH (bypass de firewall):**

```bash
# Na sua máquina: cria túnel reverso
ssh -R 9999:localhost:9999 root@IP_DO_SERVIDOR

# No servidor (dentro do SSH): inicia captura
cd saw_ebpf
sudo python3 saw_ebpf.py -i eth0 --remote-host 127.0.0.1

# Na sua máquina (outro terminal): recebe os eventos
nc -lk 9999
```

### Formato JSON transmitido

Cada linha enviada é um JSON independente (NDJSON):

```json
{
  "timestamp": "2026-03-25T15:30:45-0300",
  "pkt_number": 1,
  "protocol": "TCP",
  "src_ip": "192.168.1.10",
  "src_port": 45832,
  "dst_ip": "192.168.1.1",
  "dst_port": 9090,
  "payload_size": 128,
  "payload_hex": "474554202f6170692f76312f67707320...",
  "payload_string": "GET /api/v1/gps HTTP/1.1..."
}
```

### Resiliência

- Se o destino remoto não estiver acessível, o SAW_eBPF **continua capturando localmente**.
- Exibe `[REDE] Falha ao transmitir` e tenta reconectar automaticamente a cada evento.
- A captura no kernel **nunca é interrompida** por falha de rede.

## Formato de Saída

Cada pacote capturado é exibido em dois formatos simultâneos:

```
==============================================================================
  PKT #1  |  TCP  192.168.1.10:45832 -> 192.168.1.1:9090  |  128 bytes
==============================================================================

  [HEX]
  0000  47 45 54 20 2f 61 70 69 2f 76 31 2f 67 70 73 20  |GET /api/v1/gps |
  0010  48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20  |HTTP/1.1..Host: |

  [UTF-8/STRING]
  GET /api/v1/gps HTTP/1.1..Host: ...
```

- **HEX**: Debug técnico — visualização byte a byte com offsets e representação ASCII.
- **UTF-8/STRING**: Interpretação semântica — texto legível para consumo pelo SLM.

## Comportamento Fail-Open

Ao encerrar o agente (`Ctrl+C` ou `SIGTERM`), o SAW_eBPF:

1. Captura o sinal e interrompe o loop de polling.
2. Chama `bpf.cleanup()` para remover todos os programas eBPF do kernel.
3. O tráfego de rede **não é afetado** — a captura é 100% passiva (socket filter, não XDP drop).

O sistema legado continua operando normalmente após a remoção do agente.

## Notas Técnicas

- O **Ring Buffer** (`BPF_MAP_TYPE_RINGBUF`) substitui `BPF_PERF_OUTPUT` com melhor performance e sem perda por contention entre CPUs.
- O tamanho do payload (`-s`) é ajustado automaticamente para a potência de 2 mais próxima (exigência do operador bitmask no verificador eBPF).
- O código C é compilado em JIT pelo BCC a cada execução, permitindo parametrização dinâmica sem recompilação manual.

## Licença

Uso interno — Projeto SAW.
