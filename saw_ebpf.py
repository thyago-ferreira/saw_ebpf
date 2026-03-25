#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SAW_eBPF — Monitoramento Passivo de Rede via eBPF (Kernel 5.10+)

Utiliza socket_filter + BPF_MAP_TYPE_RINGBUF para captura de payloads
TCP/UDP com saída simultânea em hexadecimal e UTF-8.

Requisitos: Debian com Kernel >=5.10, BCC (python3-bcc), privilégios root.
"""

import argparse
import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Código eBPF (C) — compilado em JIT pelo BCC
# Os placeholders __MAX_PAYLOAD_SIZE__ e __TARGET_PORT__ são substituídos
# pelo loader antes da compilação.
# ---------------------------------------------------------------------------
BPF_C_SOURCE = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define MAX_PAYLOAD_SIZE __MAX_PAYLOAD_SIZE__
#define TARGET_PORT      __TARGET_PORT__

/* Estrutura enviada ao user-space via ring buffer */
struct pkt_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;       /* IPPROTO_TCP ou IPPROTO_UDP */
    u16 payload_len;
    u8  payload[MAX_PAYLOAD_SIZE];
};

/* Ring buffer — alta performance, sem perda por contention */
BPF_RINGBUF_OUTPUT(events, 1 << 20);  /* 1 MiB */

int saw_socket_filter(struct __sk_buff *skb)
{
    /* --- Cabeçalho Ethernet --- */
    u16 eth_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &eth_proto, 2);

    /* Aceitar apenas IPv4 */
    if (eth_proto != htons(ETH_P_IP))
        return 0;

    /* --- Cabeçalho IP --- */
    struct iphdr iph;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph, sizeof(iph));

    u8 protocol = iph.protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    u32 ip_hdr_len = iph.ihl << 2;
    u32 l4_offset  = sizeof(struct ethhdr) + ip_hdr_len;

    /* --- Cabeçalho L4 (TCP / UDP) --- */
    u16 src_port = 0, dst_port = 0;
    u32 payload_offset = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        bpf_skb_load_bytes(skb, l4_offset, &tcph, sizeof(tcph));
        src_port = ntohs(tcph.source);
        dst_port = ntohs(tcph.dest);
        u32 tcp_hdr_len = tcph.doff << 2;
        payload_offset = l4_offset + tcp_hdr_len;
    } else {
        struct udphdr udph;
        bpf_skb_load_bytes(skb, l4_offset, &udph, sizeof(udph));
        src_port = ntohs(udph.source);
        dst_port = ntohs(udph.dest);
        payload_offset = l4_offset + sizeof(struct udphdr);
    }

    /* --- Filtro de porta (0 = captura tudo) --- */
    #if TARGET_PORT != 0
    if (src_port != TARGET_PORT && dst_port != TARGET_PORT)
        return 0;
    #endif

    /* --- Calcular tamanho do payload --- */
    u32 pkt_len = skb->len;
    if (payload_offset >= pkt_len)
        return 0;

    u32 payload_len = pkt_len - payload_offset;
    if (payload_len > MAX_PAYLOAD_SIZE)
        payload_len = MAX_PAYLOAD_SIZE;

    /* --- Reservar espaço no ring buffer --- */
    struct pkt_event *evt = events.ringbuf_reserve(sizeof(struct pkt_event));
    if (!evt)
        return 0;

    evt->src_ip    = iph.saddr;
    evt->dst_ip    = iph.daddr;
    evt->src_port  = src_port;
    evt->dst_port  = dst_port;
    evt->protocol  = protocol;
    evt->payload_len = payload_len;

    /* Zerar payload e copiar dados disponíveis */
    __builtin_memset(evt->payload, 0, MAX_PAYLOAD_SIZE);
    /* O verificador do 5.10+ aceita o limite se payload_len for validado antes */
    bpf_skb_load_bytes(skb, payload_offset, evt->payload, payload_len);

    events.ringbuf_submit(evt, 0);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# ---------------------------------------------------------------------------
# SAWPublisher — Transmissão TCP não-bloqueante
# ---------------------------------------------------------------------------

class SAWPublisher:
    """Envia eventos capturados via TCP socket para um host remoto.

    Resiliência: se a conexão falhar, exibe aviso e continua capturando.
    Reconecta automaticamente a cada tentativa de envio.
    """

    def __init__(self, host, port, timeout=2):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None
        self._connected = False
        self._fail_count = 0

    def _connect(self):
        """Tenta estabelecer conexão TCP. Não bloqueia em caso de falha."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
            self._connected = True
            self._fail_count = 0
            print(f"[REDE] Conectado a {self.host}:{self.port}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self._connected = False
            self._cleanup_socket()
            if self._fail_count == 0:
                print(f"[REDE] Falha ao conectar em {self.host}:{self.port} — {e}")
                print(f"[REDE] Continuando captura local. Tentando reconectar a cada evento.")
            self._fail_count += 1

    def send(self, event_dict):
        """Envia um evento JSON via TCP. Não-bloqueante em caso de falha."""
        if not self._connected:
            self._connect()
        if not self._connected:
            return False
        try:
            payload = json.dumps(event_dict, ensure_ascii=False) + "\n"
            self._sock.sendall(payload.encode("utf-8"))
            return True
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError) as e:
            self._connected = False
            self._cleanup_socket()
            if self._fail_count == 0:
                print(f"[REDE] Falha ao transmitir — {e}")
            self._fail_count += 1
            return False

    def _cleanup_socket(self):
        """Fecha socket de forma segura."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def close(self):
        """Encerra conexão."""
        self._cleanup_socket()
        self._connected = False
        if self._fail_count > 0:
            print(f"[REDE] Total de falhas de transmissão: {self._fail_count}")
        else:
            print(f"[REDE] Conexão com {self.host}:{self.port} encerrada.")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_root():
    """Verifica se o processo roda como root."""
    if os.geteuid() != 0:
        print("[ERRO] SAW_eBPF requer privilégios de root.")
        print("       Execute: sudo python3 saw_ebpf.py ...")
        sys.exit(1)


def check_kernel_headers():
    """Verifica se os cabeçalhos do kernel estão instalados."""
    uname = os.uname()
    kver = uname.release
    header_path = f"/lib/modules/{kver}/build"
    if not os.path.isdir(header_path):
        print(f"[AVISO] Cabeçalhos do kernel não encontrados em {header_path}")
        print(f"        Execute o instalador automático: sudo bash install.sh")
        print(f"        Ou instale manualmente:")
        print(f"          sudo apt update && sudo apt upgrade -y && sudo reboot")
        print(f"          sudo apt install linux-headers-$(uname -r)")
        sys.exit(1)
    print(f"[OK] Kernel {kver} — cabeçalhos encontrados.")


def list_interfaces():
    """Detecta interfaces de rede disponíveis no sistema via /sys/class/net."""
    ifaces = []
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return ifaces
    for name in sorted(os.listdir(net_dir)):
        info = {"name": name, "state": "UNKNOWN", "ip": "—"}
        # Estado operacional (UP/DOWN)
        state_file = os.path.join(net_dir, name, "operstate")
        if os.path.isfile(state_file):
            with open(state_file) as f:
                info["state"] = f.read().strip().upper()
        # Endereço IP (via ip addr)
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", name],
                stderr=subprocess.DEVNULL, text=True,
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    info["ip"] = line.split()[1]
                    break
        except Exception:
            pass
        ifaces.append(info)
    return ifaces


def interactive_setup():
    """Modo interativo: guia o usuário passo a passo para configurar a captura."""
    print("=" * 60)
    print("  SAW_eBPF — Configuração Interativa")
    print("=" * 60)

    # --- Passo 1: Interface ---
    print("\n[Passo 1/4] Selecione a interface de rede")
    print("-" * 60)
    ifaces = list_interfaces()
    if not ifaces:
        print("[ERRO] Nenhuma interface de rede encontrada.")
        sys.exit(1)

    print(f"  {'#':<4} {'Interface':<16} {'Estado':<10} {'Endereço IP'}")
    print(f"  {'—'*4} {'—'*16} {'—'*10} {'—'*20}")
    for idx, iface in enumerate(ifaces, 1):
        label = ""
        if iface["name"] == "lo":
            label = "  (loopback — testes locais)"
        elif iface["state"] == "UP":
            label = "  (ativa)"
        print(f"  {idx:<4} {iface['name']:<16} {iface['state']:<10} {iface['ip']}{label}")

    while True:
        choice = input(f"\n  Digite o numero da interface [1-{len(ifaces)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
            interface = ifaces[int(choice) - 1]["name"]
            break
        print("  Opcao invalida. Tente novamente.")

    print(f"  -> Selecionado: {interface}")

    # --- Passo 2: Porta ---
    print(f"\n[Passo 2/4] Filtrar por porta?")
    print("-" * 60)
    print("  Portas comuns:")
    print("    80/443  — HTTP/HTTPS (trafego web)")
    print("    8080    — APIs e proxies reversos")
    print("    9090    — Prometheus / GPS / servicos customizados")
    print("    5432    — PostgreSQL")
    print("    3306    — MySQL")
    print("    0       — Todas as portas (modo generico)")

    while True:
        choice = input("\n  Digite a porta para filtrar [0 = todas]: ").strip()
        if choice == "":
            port = 0
            break
        if choice.isdigit() and 0 <= int(choice) <= 65535:
            port = int(choice)
            break
        print("  Porta invalida. Use um valor entre 0 e 65535.")

    if port:
        print(f"  -> Filtrando porta: {port}")
    else:
        print(f"  -> Modo generico: capturando todas as portas")

    # --- Passo 3: Tamanho do payload ---
    print(f"\n[Passo 3/4] Tamanho maximo do payload")
    print("-" * 60)
    print("  Valores recomendados:")
    print("    256   — Leve (apenas cabecalhos HTTP, ideal para alto volume)")
    print("    1024  — Padrao (captura a maioria dos payloads de APIs REST)")
    print("    2048  — Completo (requisicoes/respostas maiores, JSON extenso)")
    print("    4096  — Maximo (protocolos binarios, arquivos em transito)")

    while True:
        choice = input("\n  Tamanho em bytes [padrao: 1024]: ").strip()
        if choice == "":
            size = 1024
            break
        if choice.isdigit() and 1 <= int(choice) <= 65536:
            size = int(choice)
            break
        print("  Valor invalido. Use um numero entre 1 e 65536.")

    print(f"  -> Payload maximo: {size} bytes")

    # --- Passo 4: Transmissão remota ---
    print(f"\n[Passo 4/4] Transmissao remota")
    print("-" * 60)
    print("  Os eventos capturados serao enviados via TCP para sua maquina.")
    print("  Use 127.0.0.1 para tunel SSH local (bypass de firewall).")
    print("")

    while True:
        remote_host = input("  IP do destino (ex: 127.0.0.1): ").strip()
        if remote_host:
            break
        print("  IP obrigatorio. Informe o endereco de destino.")

    remote_port = 9999
    while True:
        choice = input(f"  Porta do destino [padrao: 9999]: ").strip()
        if choice == "":
            break
        if choice.isdigit() and 1 <= int(choice) <= 65535:
            remote_port = int(choice)
            break
        print("  Porta invalida. Use um valor entre 1 e 65535.")
    print(f"  -> Transmitindo para: {remote_host}:{remote_port}")

    # --- Resumo ---
    mode = f"porta {port}" if port else "todas as portas"
    remote_label = f"{remote_host}:{remote_port}"
    print(f"\n{'=' * 60}")
    print(f"  Resumo da configuracao:")
    print(f"    Interface:  {interface}")
    print(f"    Filtro:     {mode}")
    print(f"    Payload:    {size} bytes")
    print(f"    Remoto:     {remote_label}")
    print(f"{'=' * 60}")
    confirm = input("  Iniciar captura? [S/n]: ").strip().lower()
    if confirm in ("n", "nao", "no"):
        print("  Captura cancelada.")
        sys.exit(0)

    return interface, port, size, remote_host, remote_port


def ip_to_str(ip_int):
    """Converte u32 (network byte order) para string IPv4."""
    return "{}.{}.{}.{}".format(
        ip_int & 0xFF,
        (ip_int >> 8) & 0xFF,
        (ip_int >> 16) & 0xFF,
        (ip_int >> 24) & 0xFF,
    )


def format_hex(data, width=16):
    """Formata bytes em linhas hexadecimais estilo hexdump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def build_event_struct(max_payload_size):
    """Cria ctypes struct alinhada com a struct pkt_event do eBPF."""

    class PktEvent(ctypes.Structure):
        _fields_ = [
            ("src_ip",      ctypes.c_uint32),
            ("dst_ip",      ctypes.c_uint32),
            ("src_port",    ctypes.c_uint16),
            ("dst_port",    ctypes.c_uint16),
            ("protocol",    ctypes.c_uint8),
            ("_pad",        ctypes.c_uint8),       # padding natural
            ("payload_len", ctypes.c_uint16),
            ("payload",     ctypes.c_uint8 * max_payload_size),
        ]

    return PktEvent


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SAW_eBPF — Monitoramento passivo de rede via eBPF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Exemplos:
  sudo python3 saw_ebpf.py                                    # Modo interativo (guiado)
  sudo python3 saw_ebpf.py -i lo -s 2048                      # Captura tudo na loopback
  sudo python3 saw_ebpf.py -i eth0 -p 9090                    # Filtra porta 9090
  sudo python3 saw_ebpf.py -i lo --remote-host 127.0.0.1      # Transmite via TCP
  sudo python3 saw_ebpf.py -i eth0 -p 80 -s 512               # HTTP, payload até 512 bytes
""",
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Interface de rede (ex: lo, eth0). Sem este argumento, entra no modo interativo.",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=0,
        help="Porta para filtrar (default: 0 = todas)",
    )
    parser.add_argument(
        "-s", "--size", type=int, default=1024,
        help="Tamanho máximo do payload capturado em bytes (default: 1024)",
    )
    parser.add_argument(
        "--remote-host", default=None,
        help="IP de destino para transmissão TCP dos eventos (obrigatório no modo CLI)",
    )
    parser.add_argument(
        "--remote-port", type=int, default=9999,
        help="Porta de destino para transmissão TCP (default: 9999)",
    )
    args = parser.parse_args()

    # --- Validações de ambiente ---
    check_root()
    check_kernel_headers()

    # --- Modo interativo ou CLI direto ---
    if args.interface is None:
        interface, port, size, remote_host, remote_port = interactive_setup()
    else:
        if args.remote_host is None:
            parser.error("--remote-host é obrigatório. Ex: --remote-host 127.0.0.1")
        interface = args.interface
        port = args.port
        size = args.size
        remote_host = args.remote_host
        remote_port = args.remote_port

    # Garantir que o tamanho seja potência de 2 (exigência do mask no eBPF)
    payload_size = 1
    while payload_size < size:
        payload_size <<= 1
    if payload_size != size:
        print(f"[INFO] Tamanho ajustado para {payload_size} (potência de 2 mais próxima).")

    # --- Injeção de variáveis no código C ---
    c_code = BPF_C_SOURCE
    c_code = c_code.replace("__MAX_PAYLOAD_SIZE__", str(payload_size))
    c_code = c_code.replace("__TARGET_PORT__", str(port))

    # --- Inicializar publisher remoto ---
    publisher = SAWPublisher(remote_host, remote_port)
    print(f"[*] Transmissão remota: {remote_host}:{remote_port} (TCP)")

    mode = f"porta {port}" if port else "todas as portas (modo genérico)"
    print(f"[*] Interface: {interface}")
    print(f"[*] Filtro: {mode}")
    print(f"[*] Payload máximo: {payload_size} bytes")
    print(f"[*] Compilando programa eBPF...")

    # --- Importar BCC aqui para dar erro legível se não estiver instalado ---
    try:
        from bcc import BPF
    except ImportError:
        print("[ERRO] Biblioteca BCC não encontrada.")
        print("       Execute o instalador automático: sudo bash install.sh")
        print("       Ou instale manualmente:")
        print("         Debian: sudo apt install python3-bpfcc bpfcc-tools")
        print("         Ubuntu: sudo apt install python3-bcc bpfcc-tools")
        sys.exit(1)

    # --- Compilar e anexar ao socket ---
    bpf = BPF(text=c_code)
    fn = bpf.load_func("saw_socket_filter", BPF.SOCKET_FILTER)

    BPF.attach_raw_socket(fn, interface)

    print(f"[*] Socket filter anexado a '{interface}'. Capturando...")
    print("-" * 78)

    # --- Estrutura de evento ---
    PktEvent = build_event_struct(payload_size)
    pkt_count = 0

    # --- Callback do ring buffer ---
    def handle_event(ctx, data, size):
        nonlocal pkt_count
        pkt_count += 1
        evt = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents

        proto_name = "TCP" if evt.protocol == IPPROTO_TCP else "UDP"
        src_ip = ip_to_str(evt.src_ip)
        dst_ip = ip_to_str(evt.dst_ip)
        src = f"{src_ip}:{evt.src_port}"
        dst = f"{dst_ip}:{evt.dst_port}"
        plen = evt.payload_len

        payload_bytes = bytes(evt.payload[:plen])
        payload_hex = payload_bytes.hex()

        # UTF-8 / String (substitui bytes não-imprimíveis por '.')
        try:
            text = payload_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = payload_bytes.decode("latin-1", errors="replace")
        clean = "".join(c if c.isprintable() or c in ("\n", "\r", "\t") else "." for c in text)

        # --- Saída local formatada ---
        print(f"\n{'='*78}")
        print(f"  PKT #{pkt_count}  |  {proto_name}  {src} -> {dst}  |  {plen} bytes")
        print(f"{'='*78}")

        print("\n  [HEX]")
        print(format_hex(payload_bytes))

        print(f"\n  [UTF-8/STRING]")
        print(f"  {clean}")

        # --- Transmissão remota ---
        event_json = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "pkt_number": pkt_count,
            "protocol": proto_name,
            "src_ip": src_ip,
            "src_port": evt.src_port,
            "dst_ip": dst_ip,
            "dst_port": evt.dst_port,
            "payload_size": plen,
            "payload_hex": payload_hex,
            "payload_string": clean,
        }
        publisher.send(event_json)

    # --- Registrar callback no ring buffer ---
    bpf["events"].open_ring_buffer(handle_event)

    # --- Tratamento de sinal para Fail-Open ---
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        print(f"\n\n[!] Sinal recebido ({sig}). Removendo ganchos do kernel (Fail-Open)...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- Loop principal ---
    try:
        while running:
            bpf.ring_buffer_poll(timeout=100)
    except Exception as e:
        print(f"\n[ERRO] Exceção no loop principal: {e}")
    finally:
        # Fail-Open: BCC remove automaticamente os programas eBPF ao sair,
        # garantindo que o sistema legado não seja afetado.
        publisher.close()
        print(f"\n[*] Total de pacotes capturados: {pkt_count}")
        print("[*] Programa eBPF removido. Sistema limpo (Fail-Open).")
        bpf.cleanup()
        print("[*] SAW_eBPF encerrado.")


if __name__ == "__main__":
    main()
