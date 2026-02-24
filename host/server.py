#!/usr/bin/env python3
"""
server.py — HTTP server for PS5 exploit scaffold

Serves the exploit/ directory to the PS5 browser with the required
Cross-Origin headers (COOP + COEP) needed for SharedArrayBuffer.

NOTE: SharedArrayBuffer is disabled on the PS5 browser regardless of
these headers. They are included because:
  1. They are part of the standard WebKit exploit delivery pattern
  2. They may be required for other browser APIs used by the exploit
  3. They do no harm on PS5 even though SAB itself is unavailable

Usage:
    python3 server.py [--port 8000] [--host 0.0.0.0]

Then on PS5 browser navigate to:
    http://<YOUR_PC_IP>:8000/exploit/index.html
"""

import argparse
import http.server
import os
import socket
import sys
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).resolve().parent.parent  # project root
SERVE_DIR    = SCRIPT_DIR                               # serve whole project
DEFAULT_PORT = 8000
DEFAULT_HOST = '0.0.0.0'

# ─── Request handler ─────────────────────────────────────────────────────────

class PS5Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SERVE_DIR), **kwargs)

    # ─── Headers ─────────────────────────────────────────────────────────────

    def end_headers(self):
        # Cross-Origin Opener Policy + Embedder Policy
        # Required by some browser APIs; included for compatibility.
        self.send_header('Cross-Origin-Opener-Policy',   'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        # Cache control: no caching so the PS5 always gets fresh JS files
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        super().end_headers()

    # ─── Special endpoints ───────────────────────────────────────────────────

    def do_POST(self):
        if self.path == '/log':
            # Receive log messages from the PS5 and print them locally
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length).decode('utf-8', errors='replace')
            print(f'[PS5] {body}')
            self.send_response(200)
            self.end_headers()
            return

        if self.path == '/probe':
            # Heartbeat endpoint: JS polls this to check server is alive
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
            return

        self.send_response(404)
        self.end_headers()

    # ─── Quiet logging ───────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        # Only print non-asset requests to keep output readable
        path = args[0] if args else ''
        if any(ext in path for ext in ['.js', '.html', '/log', '/probe']):
            print(f'[http] {self.client_address[0]} → {path}')

# ─── Entry point ─────────────────────────────────────────────────────────────

def get_local_ip():
    """Best-effort local LAN IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()

def main():
    parser = argparse.ArgumentParser(description='PS5 exploit HTTP server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--host', default=DEFAULT_HOST)
    args = parser.parse_args()

    local_ip = get_local_ip()

    print('═' * 56)
    print('  PS5-Toolkit HTTP Server')
    print('═' * 56)
    print(f'  Serving:  {SERVE_DIR}')
    print(f'  Binding:  {args.host}:{args.port}')
    print()
    print(f'  ► Open on PS5 browser:')
    print(f'    http://{local_ip}:{args.port}/exploit/index.html')
    print()
    print('  ► Remember to set HOST_IP in exploit/index.html:')
    print(f'    const HOST_IP = \'{local_ip}\';')
    print('═' * 56)
    print()
    print('  Waiting for PS5 connection... (Ctrl+C to stop)')
    print()

    server = http.server.HTTPServer((args.host, args.port), PS5Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[server] Stopped.')
        sys.exit(0)

if __name__ == '__main__':
    main()
