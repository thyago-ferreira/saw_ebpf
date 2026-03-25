#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SAW Receiver — Receptor TCP para eventos do SAW_eBPF

Escuta na porta configurada, recebe eventos JSON do SAW_eBPF
e grava em arquivo JSON-lines (.jsonl) para leitura pelo saw_slm.

Uso:
  python saw_receiver.py
  python saw_receiver.py -p 9999 -o saw_events.jsonl
"""

import argparse
import json
import os
import signal
import socket
import sys
import time


def main():
    parser = argparse.ArgumentParser(
        description="SAW Receiver — Receptor TCP para eventos do SAW_eBPF",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=9999,
        help="Porta TCP para escutar (default: 9999)",
    )
    parser.add_argument(
        "-o", "--output", default="saw_events.jsonl",
        help="Arquivo de saída JSON-lines (default: saw_events.jsonl)",
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Endereço para escutar (default: 0.0.0.0 = todas as interfaces)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  SAW Receiver")
    print("=" * 60)
    print(f"  Porta:   {args.port}")
    print(f"  Arquivo: {os.path.abspath(args.output)}")
    print(f"  Host:    {args.host}")
    print("=" * 60)

    # --- Tratamento de sinal ---
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        print(f"\n[!] Encerrando receiver...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- Servidor TCP ---
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    server.bind((args.host, args.port))
    server.listen(1)

    print(f"\n[*] Aguardando conexão do SAW_eBPF na porta {args.port}...")

    event_count = 0

    while running:
        # Aceitar conexão
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        print(f"[*] Conectado: {addr[0]}:{addr[1]}")
        client.settimeout(1.0)
        buffer = ""

        with open(args.output, "a", encoding="utf-8") as f:
            while running:
                try:
                    data = client.recv(65536)
                    if not data:
                        print(f"[*] Conexão encerrada por {addr[0]}")
                        break
                    buffer += data.decode("utf-8", errors="replace")

                    # Processar linhas completas (NDJSON)
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue

                        event_count += 1
                        f.write(line + "\n")
                        f.flush()

                        # Exibir resumo no terminal
                        try:
                            evt = json.loads(line)
                            proto = evt.get("protocol", "?")
                            src = f"{evt.get('src_ip', '?')}:{evt.get('src_port', '?')}"
                            dst = f"{evt.get('dst_ip', '?')}:{evt.get('dst_port', '?')}"
                            size = evt.get("payload_size", 0)
                            print(f"  [{event_count}] {proto} {src} -> {dst} ({size}B)")
                        except json.JSONDecodeError:
                            print(f"  [{event_count}] (JSON inválido, gravado mesmo assim)")

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    print(f"[*] Conexão perdida com {addr[0]}")
                    break

        client.close()
        if running:
            print(f"[*] Aguardando nova conexão...")

    server.close()
    print(f"\n[*] Total de eventos gravados: {event_count}")
    print(f"[*] Arquivo: {os.path.abspath(args.output)}")
    print("[*] SAW Receiver encerrado.")


if __name__ == "__main__":
    main()
