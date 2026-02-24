#!/usr/bin/env python3
"""
listen_log.py — Receive and display UDP log messages from the PS5

The PS5 loader (elfldr/main.c) and the JS exploit chain broadcast log
messages over UDP to port 9998 on the host PC. This script listens for
those messages and prints them with timestamps and colour coding.

Usage:
    python3 listen_log.py [--port 9998] [--bind 0.0.0.0]

Press Ctrl+C to stop.
"""

import argparse
import datetime
import signal
import socket
import sys

DEFAULT_PORT = 9998
DEFAULT_BIND = '0.0.0.0'
MAX_MSG_SIZE = 4096

# ─── ANSI colour codes ────────────────────────────────────────────────────────

RESET  = '\033[0m'
GREY   = '\033[90m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
CYAN   = '\033[96m'
WHITE  = '\033[97m'

def colourise(msg: str) -> str:
    """Apply colour based on log level prefix."""
    m = msg.strip()
    if m.startswith('[ok]')    or m.startswith('[done]'):    return GREEN  + m + RESET
    if m.startswith('[error]') or m.startswith('[FATAL]'):   return RED    + m + RESET
    if m.startswith('[warn]')  or m.startswith('[TODO]'):    return YELLOW + m + RESET
    if m.startswith('[phase')  or m.startswith('[kernel]'):  return CYAN   + m + RESET
    if m.startswith('[PS5]'):                                return WHITE  + m + RESET
    return GREY + m + RESET

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Receive UDP log messages from the PS5 exploit chain'
    )
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'UDP port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--bind', default=DEFAULT_BIND,
                        help=f'Interface to bind (default: {DEFAULT_BIND})')
    parser.add_argument('--no-colour', action='store_true',
                        help='Disable ANSI colour output')
    args = parser.parse_args()

    use_colour = not args.no_colour and sys.stdout.isatty()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((args.bind, args.port))
    except OSError as e:
        print(f'[error] Cannot bind to {args.bind}:{args.port} — {e}', file=sys.stderr)
        sys.exit(1)

    print(f'[listen_log] Listening for PS5 UDP logs on {args.bind}:{args.port}')
    print(f'[listen_log] Press Ctrl+C to stop\n')

    def _shutdown(sig, frame):
        print('\n[listen_log] Stopped.')
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        try:
            data, addr = sock.recvfrom(MAX_MSG_SIZE)
        except OSError:
            break

        msg = data.decode('utf-8', errors='replace').rstrip('\n\r\x00')
        ts  = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

        if use_colour:
            line = f'{GREY}{ts}{RESET}  {colourise(msg)}'
        else:
            line = f'{ts}  {msg}'

        print(line, flush=True)

if __name__ == '__main__':
    main()
