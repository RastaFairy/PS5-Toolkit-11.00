#!/usr/bin/env python3
"""
tools/listen_log.py — Receptor de logs UDP desde la PS5

El ELF loader envía mensajes de diagnóstico por UDP broadcast al puerto 9998.
Este script los recibe y los muestra con timestamp y color.

Uso:
    python3 tools/listen_log.py
    python3 tools/listen_log.py --port 9998 --interface 0.0.0.0
"""

import argparse
import datetime
import socket
import sys


COLORS = {
    "ERROR":   "\033[91m",   # Rojo
    "ADVERTENCIA": "\033[93m",  # Amarillo
    "OK":      "\033[92m",   # Verde
    "INFO":    "\033[94m",   # Azul
    "RESET":   "\033[0m",
}


def colorize(msg: str) -> str:
    msg_upper = msg.upper()
    for key, color in COLORS.items():
        if key in msg_upper:
            return f"{color}{msg}{COLORS['RESET']}"
    return msg


def main():
    parser = argparse.ArgumentParser(description="Receptor de logs UDP de la PS5")
    parser.add_argument("--port",      default=9998, type=int, help="Puerto UDP (default: 9998)")
    parser.add_argument("--interface", default="0.0.0.0", help="Interfaz de escucha")
    parser.add_argument("--no-color",  action="store_true", help="Desactivar colores")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Habilitar recepción de broadcasts
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind((args.interface, args.port))
    except OSError as e:
        print(f"ERROR: No se pudo abrir {args.interface}:{args.port} → {e}")
        sys.exit(1)

    print(f"Escuchando logs UDP en {args.interface}:{args.port}")
    print("Ctrl+C para salir\n")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            msg = data.decode("utf-8", errors="replace").strip()
            ts  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            src = f"{addr[0]}:{addr[1]}"

            line = f"[{ts}] [{src}] {msg}"
            if not args.no_color:
                line = colorize(line)
            print(line)

    except KeyboardInterrupt:
        print("\nDetenido.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
