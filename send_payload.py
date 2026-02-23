#!/usr/bin/env python3
"""
tools/send_payload.py — Envía payloads al ELF loader de la PS5

Soporta:
  • .elf  — ELF64 nativo (magic: \x7fELF)
  • .self — SELF firmado de Sony (magic: \x00PSF)
  • .bin  — Binario raw (cualquier otro)

El ELF loader (puerto 9021) acepta dos modos de envío:
  1. Modo simple (raw): enviar los bytes directamente (compatible con netcat)
  2. Modo con header: 4 bytes de tamaño LE seguidos del payload

Este script usa el modo con header para envíos grandes y reliable.

Uso:
    python3 tools/send_payload.py --host 192.168.1.50 --file payload.elf
    python3 tools/send_payload.py --host 192.168.1.50 --file payload.bin --port 9021
    python3 tools/send_payload.py --host 192.168.1.50 --list-payloads
"""

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path

# ── Constantes ────────────────────────────────────────────────────────────

DEFAULT_PORT     = 9021
CONNECT_TIMEOUT  = 5.0    # segundos para establecer la conexión
SEND_TIMEOUT     = 30.0   # segundos para enviar el payload completo
CHUNK_SIZE       = 64 * 1024  # 64 KiB por chunk

# Magic bytes para detección de tipo
MAGIC_ELF  = b"\x7fELF"
MAGIC_SELF = b"\x00PSF"

# ── Tipos de payload ──────────────────────────────────────────────────────

PAYLOAD_TYPES = {
    MAGIC_ELF:  "ELF64",
    MAGIC_SELF: "SELF",
}


def detect_payload_type(data: bytes) -> str:
    """Detecta el tipo de payload por sus magic bytes."""
    if data[:4] == MAGIC_ELF:  return "ELF"
    if data[:4] == MAGIC_SELF: return "SELF"
    return "RAW"


def validate_elf(data: bytes) -> bool:
    """Valida que el buffer sea un ELF64 LE x86-64 válido."""
    if len(data) < 64: return False
    if data[:4] != MAGIC_ELF: return False
    if data[4]  != 2: return False   # ELFCLASS64
    if data[5]  != 1: return False   # ELFDATA2LSB
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 0x3E: return False  # EM_X86_64
    return True


# ── Envío ─────────────────────────────────────────────────────────────────

def send_payload(host: str, port: int, data: bytes,
                 use_header: bool = True, verbose: bool = True) -> bool:
    """
    Envía el payload al ELF loader de la PS5.

    Args:
        host:        IP de la PS5
        port:        Puerto del ELF loader (default 9021)
        data:        Bytes del payload
        use_header:  True → enviar header de 4 bytes con el tamaño
        verbose:     True → mostrar progreso

    Returns:
        True si el envío fue exitoso
    """
    total = len(data)
    ptype = detect_payload_type(data)

    if verbose:
        print(f"  Tipo detectado : {ptype}")
        print(f"  Tamaño         : {total:,} bytes ({total / 1024:.1f} KiB)")
        print(f"  Destino        : {host}:{port}")
        print()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)

        if verbose: print(f"  Conectando a {host}:{port}...", end=" ", flush=True)
        sock.connect((host, port))
        sock.settimeout(SEND_TIMEOUT)
        if verbose: print("OK")

    except ConnectionRefusedError:
        print(f"\n  ERROR: Conexión rechazada en {host}:{port}")
        print("  ¿Está el ELF loader activo? (ejecuta el exploit primero)")
        return False
    except socket.timeout:
        print(f"\n  ERROR: Timeout conectando a {host}:{port}")
        return False
    except OSError as e:
        print(f"\n  ERROR: {e}")
        return False

    try:
        # Enviar header de tamaño si se pidió
        if use_header:
            header = struct.pack("<I", total)
            sock.sendall(header)

        # Enviar el payload en chunks con barra de progreso
        sent = 0
        t_start = time.time()

        while sent < total:
            chunk = data[sent:sent + CHUNK_SIZE]
            sock.sendall(chunk)
            sent += len(chunk)

            if verbose:
                pct      = sent / total * 100
                elapsed  = time.time() - t_start
                speed    = sent / elapsed / 1024 if elapsed > 0 else 0
                bar      = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                print(f"\r  [{bar}] {pct:5.1f}%  {speed:6.1f} KiB/s", end="", flush=True)

        elapsed = time.time() - t_start
        if verbose:
            print(f"\r  [{'█' * 20}] 100.0%  {total/elapsed/1024:.1f} KiB/s")
            print()
            print(f"  ✓ Enviado en {elapsed:.2f}s")

        sock.close()
        return True

    except socket.timeout:
        print(f"\n  ERROR: Timeout enviando datos")
        sock.close()
        return False
    except BrokenPipeError:
        print(f"\n  ERROR: La PS5 cerró la conexión inesperadamente")
        sock.close()
        return False
    except OSError as e:
        print(f"\n  ERROR: {e}")
        sock.close()
        return False


# ── Utilidades ─────────────────────────────────────────────────────────────

def list_local_payloads() -> list[Path]:
    """Lista los payloads disponibles en la carpeta payloads/ del proyecto."""
    payload_dir = Path(__file__).parent.parent / "payloads"
    if not payload_dir.exists():
        return []
    extensions = {".elf", ".bin", ".self"}
    return sorted(p for p in payload_dir.iterdir()
                  if p.is_file() and p.suffix.lower() in extensions)


def check_ps5_reachable(host: str, port: int) -> bool:
    """Verifica si la PS5 es alcanzable en el puerto dado."""
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except (OSError, socket.timeout):
        return False


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Envía payloads al ELF loader de la PS5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s --host 192.168.1.50 --file payload.elf
  %(prog)s --host 192.168.1.50 --file payload.bin
  %(prog)s --host 192.168.1.50 --file payload.self --port 9021
  %(prog)s --host 192.168.1.50 --list-payloads
        """,
    )

    parser.add_argument("--host",          required=False, help="IP de la PS5")
    parser.add_argument("--port",          default=DEFAULT_PORT, type=int,
                        help=f"Puerto del ELF loader (default: {DEFAULT_PORT})")
    parser.add_argument("--file",          help="Ruta del payload a enviar")
    parser.add_argument("--no-header",     action="store_true",
                        help="No enviar header de 4 bytes de tamaño (modo raw/netcat)")
    parser.add_argument("--list-payloads", action="store_true",
                        help="Listar payloads disponibles localmente")
    parser.add_argument("--quiet",         action="store_true",
                        help="Reducir output")

    args = parser.parse_args()
    verbose = not args.quiet

    # ── Listar payloads ──────────────────────────────────────────────────
    if args.list_payloads:
        payloads = list_local_payloads()
        if not payloads:
            print("  No hay payloads en la carpeta payloads/")
        else:
            print("  Payloads disponibles:")
            for p in payloads:
                size = p.stat().st_size
                ptype = detect_payload_type(p.read_bytes()[:4])
                print(f"    {p.name:<40} {size:>10,} bytes  [{ptype}]")
        return

    # ── Validar argumentos ───────────────────────────────────────────────
    if not args.host:
        parser.error("--host es obligatorio")
    if not args.file:
        parser.error("--file es obligatorio (o usa --list-payloads)")

    payload_path = Path(args.file)
    if not payload_path.exists():
        # Intentar en la carpeta payloads/
        alt = Path(__file__).parent.parent / "payloads" / args.file
        if alt.exists():
            payload_path = alt
        else:
            print(f"  ERROR: No se encontró el archivo: {args.file}")
            sys.exit(1)

    # ── Leer y validar el payload ────────────────────────────────────────
    data = payload_path.read_bytes()
    if len(data) == 0:
        print("  ERROR: El archivo está vacío")
        sys.exit(1)

    ptype = detect_payload_type(data)

    if verbose:
        print()
        print("=" * 50)
        print("  PS5 Toolkit — Payload Sender")
        print("=" * 50)
        print(f"  Archivo : {payload_path.name}")

    # Validación extra para ELF
    if ptype == "ELF" and not validate_elf(data):
        print("  ADVERTENCIA: El ELF no pasó la validación básica")
        print("               (podría no ser compatible con PS5)")

    # ── Verificar conectividad ───────────────────────────────────────────
    if verbose:
        print(f"  Verificando {args.host}:{args.port}... ", end="", flush=True)
    reachable = check_ps5_reachable(args.host, args.port)
    if not reachable:
        print("NO RESPONDE")
        print()
        print("  El ELF loader no está activo.")
        print("  Pasos:")
        print("    1. Abre el exploit en el browser de la PS5")
        print("    2. Espera a que complete las 5 fases")
        print("    3. Vuelve a ejecutar este script")
        sys.exit(1)
    if verbose:
        print("OK")
        print()

    # ── Enviar ──────────────────────────────────────────────────────────
    success = send_payload(
        host=args.host,
        port=args.port,
        data=data,
        use_header=not args.no_header,
        verbose=verbose,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
