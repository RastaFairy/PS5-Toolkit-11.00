#!/usr/bin/env python3
"""
send_payload.py — Send ELF/BIN/SELF payloads to the PS5 ELF loader

Usage:
    python3 send_payload.py --host 192.168.1.50 --file my_payload.elf
    python3 send_payload.py --host 192.168.1.50 --file hello.bin --port 9021

Supported formats (auto-detected by magic bytes):
    .elf   ELF64 native     magic: \\x7fELF
    .self  Sony signed SELF magic: \\x00PSF  (or \\x4F\\x15\\x3D\\x1D)
    .bin   Raw binary       (any other — loaded at a fixed address)

The ELF loader on the PS5 (elfldr.c) handles all three formats.
"""

import argparse
import os
import socket
import struct
import sys

DEFAULT_PORT    = 9021
CONNECT_TIMEOUT = 10   # seconds
SEND_CHUNK      = 4096

# ─── Magic byte detection ─────────────────────────────────────────────────────

ELF_MAGIC  = b'\x7fELF'
SELF_MAGIC = b'\x00PSF\x01'
SELF_MAGIC2 = b'\x4f\x15\x3d\x1d'   # alternative SELF header seen on some FWs

def detect_format(data: bytes) -> str:
    if data[:4] == ELF_MAGIC:
        # Verify ELF64 (e_ident[EI_CLASS] == 2 == ELFCLASS64)
        if len(data) > 4 and data[4] == 2:
            return 'ELF64'
        return 'ELF (unknown class)'
    if data[:5] == SELF_MAGIC or data[:4] == SELF_MAGIC2:
        return 'SELF'
    return 'RAW'

# ─── ELF basic validation ─────────────────────────────────────────────────────

def validate_elf64(data: bytes):
    """Raise ValueError if data is not a plausible ELF64 for FreeBSD AMD64."""
    if len(data) < 64:
        raise ValueError('File too small to be a valid ELF64')
    if data[:4] != ELF_MAGIC:
        raise ValueError('Missing ELF magic bytes')
    if data[4] != 2:
        raise ValueError('Not ELF64 (EI_CLASS != 2)')
    if data[5] != 1:
        raise ValueError('Not little-endian (EI_DATA != 1)')
    # e_machine at offset 18, 2 bytes LE — should be 62 (EM_X86_64)
    e_machine = struct.unpack_from('<H', data, 18)[0]
    if e_machine != 62:
        raise ValueError(f'Unexpected e_machine: {e_machine} (expected 62 = EM_X86_64)')

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Send a payload to the PS5 ELF loader over TCP'
    )
    parser.add_argument('--host', required=True,
                        help='PS5 IP address (e.g. 192.168.1.50)')
    parser.add_argument('--file', required=True,
                        help='Path to .elf, .bin, or .self file')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'Loader port (default: {DEFAULT_PORT})')
    args = parser.parse_args()

    # ─── Load file ────────────────────────────────────────────────────────────
    path = os.path.expanduser(args.file)
    if not os.path.isfile(path):
        print(f'[error] File not found: {path}', file=sys.stderr)
        sys.exit(1)

    with open(path, 'rb') as f:
        data = f.read()

    fmt = detect_format(data)
    size_kb = len(data) / 1024

    print(f'[payload] File  : {path}')
    print(f'[payload] Format: {fmt}')
    print(f'[payload] Size  : {size_kb:.1f} KB ({len(data)} bytes)')

    if fmt == 'ELF64':
        try:
            validate_elf64(data)
            print('[payload] ELF64 validation: OK')
        except ValueError as e:
            print(f'[warn] ELF64 validation warning: {e}')

    # ─── Connect ──────────────────────────────────────────────────────────────
    print(f'\n[connect] Connecting to {args.host}:{args.port}...')

    try:
        sock = socket.create_connection(
            (args.host, args.port),
            timeout=CONNECT_TIMEOUT
        )
    except ConnectionRefusedError:
        print('[error] Connection refused — is the ELF loader running on PS5?')
        print('[hint]  Run the exploit first (all 5 phases must complete)')
        sys.exit(1)
    except socket.timeout:
        print(f'[error] Connection timed out after {CONNECT_TIMEOUT}s')
        print('[hint]  Check the PS5 IP address and that it is on the same network')
        sys.exit(1)
    except OSError as e:
        print(f'[error] Network error: {e}')
        sys.exit(1)

    print('[connect] Connected!')

    # ─── Send ────────────────────────────────────────────────────────────────
    try:
        sent  = 0
        total = len(data)

        print(f'[send] Sending {total} bytes...')

        while sent < total:
            chunk = data[sent:sent + SEND_CHUNK]
            n = sock.send(chunk)
            sent += n
            pct = sent / total * 100
            bar = '█' * int(pct / 4) + '░' * (25 - int(pct / 4))
            print(f'\r[send] [{bar}] {pct:5.1f}%  {sent}/{total} B', end='', flush=True)

        print(f'\n[send] Done.')

    except BrokenPipeError:
        print('\n[error] Connection broken during send')
        sys.exit(1)
    finally:
        sock.close()

    print(f'\n[ok] Payload delivered. Check PS5 output or listen_log.py for results.')

if __name__ == '__main__':
    main()
