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

### 1. Clonar o repositório

```bash
git clone https://github.com/thyago-ferreira/saw_ebpf.git
cd saw_ebpf
```

### 2. Instalar dependências (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y linux-headers-$(uname -r) python3-bcc bpfcc-tools
```

### 3. Verificar instalação

```bash
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

[Passo 1/3] Selecione a interface de rede
------------------------------------------------------------
  #    Interface        Estado     Endereço IP
  ———— ———————————————— —————————— ————————————————————
  1    eth0             UP         192.168.1.10/24  (ativa)
  2    lo               UNKNOWN    127.0.0.1/8  (loopback — testes locais)
  3    docker0          DOWN       172.17.0.1/16

  Digite o numero da interface [1-3]: 1

[Passo 2/3] Filtrar por porta?
------------------------------------------------------------
  Portas comuns:
    80/443  — HTTP/HTTPS (trafego web)
    8080    — APIs e proxies reversos
    9090    — Prometheus / GPS / servicos customizados
    5432    — PostgreSQL
    3306    — MySQL
    0       — Todas as portas (modo generico)

  Digite a porta para filtrar [0 = todas]: 9090

[Passo 3/3] Tamanho maximo do payload
------------------------------------------------------------
  Valores recomendados:
    256   — Leve (apenas cabecalhos HTTP, ideal para alto volume)
    1024  — Padrao (captura a maioria dos payloads de APIs REST)
    2048  — Completo (requisicoes/respostas maiores, JSON extenso)
    4096  — Maximo (protocolos binarios, arquivos em transito)

  Tamanho em bytes [padrao: 1024]: 2048

============================================================
  Resumo da configuracao:
    Interface:  eth0
    Filtro:     porta 9090
    Payload:    2048 bytes
============================================================
  Iniciar captura? [S/n]: S
```

### Modo Direto (CLI)

Para automação ou uso avançado, passe os argumentos diretamente:

```bash
# Capturar tudo na loopback (APIs locais de teste)
sudo python3 saw_ebpf.py -i lo -s 2048

# Monitorar uma porta específica (ex: GPS na porta 9090)
sudo python3 saw_ebpf.py -i eth0 -p 9090

# Monitorar HTTP com payload reduzido
sudo python3 saw_ebpf.py -i eth0 -p 80 -s 512
```

### Opções da CLI

```
uso: saw_ebpf.py [-h] [-i INTERFACE] [-p PORT] [-s SIZE]

  -i, --interface   Interface de rede. Sem este argumento, entra no modo interativo.
  -p, --port        Porta para filtrar (padrão: 0 = todas as portas)
  -s, --size        Tamanho máximo do payload em bytes (padrão: 1024)
```

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
