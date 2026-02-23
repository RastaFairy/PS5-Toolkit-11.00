#!/usr/bin/env python3
"""
host/server.py — Servidor HTTP para servir el exploit al browser de PS5

Sirve la carpeta exploit/ con los headers HTTP necesarios:
  • CORS permisivo (la PS5 hace cross-origin requests)
  • Sin cache (para que el browser siempre cargue la versión fresca)
  • SharedArrayBuffer habilitado (Cross-Origin-Opener/Embedder-Policy)

También expone:
  • GET  /probe?host=IP&port=N  → verifica si un TCP port está abierto
  • GET  /payloads/<file>        → sirve payloads desde la carpeta payloads/

Uso:
    python3 host/server.py [--port 8000] [--host 0.0.0.0]
"""

import argparse
import http.server
import os
import socket
import sys
import urllib.parse
from pathlib import Path

# Directorio raíz del proyecto (un nivel arriba de host/)
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
EXPLOIT_DIR  = PROJECT_ROOT / "exploit"
PAYLOAD_DIR  = PROJECT_ROOT / "payloads"


class PS5Handler(http.server.SimpleHTTPRequestHandler):
    """Handler que añade headers necesarios y maneja rutas especiales."""

    # Headers que la PS5 necesita para SharedArrayBuffer y CORS
    SECURITY_HEADERS = {
        "Cross-Origin-Opener-Policy":   "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Cache-Control":                "no-store, no-cache, must-revalidate",
        "Pragma":                       "no-cache",
    }

    def __init__(self, *args, **kwargs):
        # Servir desde la raíz del proyecto para poder acceder a exploit/ y payloads/
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)

    def end_headers(self):
        for key, value in self.SECURITY_HEADERS.items():
            self.send_header(key, value)
        super().end_headers()

    def do_OPTIONS(self):
        """Responder a preflight CORS."""
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # ── Ruta especial: /probe ──────────────────────────────────────────
        if path == "/probe":
            self._handle_probe(params)
            return

        # ── Ruta especial: /status ─────────────────────────────────────────
        if path == "/status":
            self._handle_status()
            return

        # ── Archivos estáticos normales ────────────────────────────────────
        super().do_GET()

    def _handle_probe(self, params):
        """
        Verifica si un puerto TCP está abierto en el host indicado.
        Responde con 200 si está abierto, 503 si no lo está.

        Parámetros de query:
            host  — IP o hostname a probar (default: PS5 detectada)
            port  — Puerto TCP a probar
        """
        host = params.get("host", ["127.0.0.1"])[0]
        try:
            port = int(params.get("port", ["9021"])[0])
        except ValueError:
            self._json_response(400, {"error": "puerto inválido"})
            return

        open_flag = self._tcp_ping(host, port, timeout=0.4)
        status    = 200 if open_flag else 503
        self._json_response(status, {
            "host":   host,
            "port":   port,
            "open":   open_flag,
        })

    def _handle_status(self):
        """Retorna el estado del servidor (útil para debugging)."""
        self._json_response(200, {
            "server":      "ps5-toolkit-host",
            "exploit_dir": str(EXPLOIT_DIR),
            "payload_dir": str(PAYLOAD_DIR),
            "payloads":    self._list_payloads(),
        })

    @staticmethod
    def _tcp_ping(host: str, port: int, timeout: float) -> bool:
        """Devuelve True si el puerto TCP está abierto."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, ConnectionRefusedError, socket.timeout):
            return False

    @staticmethod
    def _list_payloads() -> list:
        """Lista los archivos .elf, .bin y .self en la carpeta payloads/."""
        if not PAYLOAD_DIR.exists():
            return []
        extensions = {".elf", ".bin", ".self"}
        return [
            p.name for p in PAYLOAD_DIR.iterdir()
            if p.is_file() and p.suffix.lower() in extensions
        ]

    def _json_response(self, code: int, data: dict):
        import json
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        """Formato de log más limpio."""
        print(f"  {self.address_string()}  {fmt % args}")


def detect_local_ip() -> str:
    """Detecta la IP local que la PS5 usaría para llegar al PC."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser(description="Servidor HTTP para PS5 exploit toolkit")
    parser.add_argument("--host",  default="0.0.0.0", help="IP de escucha (default: 0.0.0.0)")
    parser.add_argument("--port",  default=8000, type=int, help="Puerto HTTP (default: 8000)")
    parser.add_argument("--quiet", action="store_true", help="Reducir output de log")
    args = parser.parse_args()

    local_ip = detect_local_ip()

    # Crear carpeta de payloads si no existe
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  PS5 Toolkit — Servidor HTTP")
    print("=" * 60)
    print(f"  Escuchando en: http://{args.host}:{args.port}")
    print(f"  IP local detectada: {local_ip}")
    print()
    print("  En el browser de la PS5, abre:")
    print(f"  → http://{local_ip}:{args.port}/exploit/index.html")
    print()
    print("  Antes de lanzar el exploit, edita:")
    print(f"  → exploit/js/loader.js  (HOST_IP = \"{local_ip}\")")
    print("=" * 60)
    print()

    handler = PS5Handler
    if args.quiet:
        handler.log_message = lambda *_: None

    with http.server.ThreadingHTTPServer((args.host, args.port), handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n  Servidor detenido.")
            sys.exit(0)


if __name__ == "__main__":
    main()
