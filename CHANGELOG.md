# Changelog — PS5 Toolkit 11.xx

Todos los cambios relevantes del proyecto se documentan aquí.

---

## [0.1.0] — 2025

### Añadido
- Scaffold completo del proyecto con todos los módulos
- `exploit/js/int64.js` — Clase Int64 con aritmética de 64 bits y conversión float↔int64
- `exploit/js/offsets_1100.js` — Offsets para FW 11.00 (libkernel, WebKit, kernel)
- `exploit/js/primitives.js` — Clase Primitives con read8/write8/readBytes/writeBytes
- `exploit/js/rop.js` — Clase ROPChain y funciones findWorkerStack / launchROPChain
- `exploit/js/rop_worker.js` — Script del Web Worker víctima del stack pivot
- `exploit/js/kernel.js` — KernelExploit: kbase leak, kernel R/W, jailbreak, root
- `exploit/js/loader.js` — PayloadLoader: descarga y envío del ELF loader
- `exploit/index.html` — UI con progreso de 5 fases y orquestador del exploit
- `elfldr/main.c` — ELF loader persistente con socket TCP en :9021
- `elfldr/elfldr.c` — Parser ELF64/SELF/RAW con relocations y permisos correctos
- `elfldr/pt.c` — Bootstrap vía ptrace en SceRedisServer
- `host/server.py` — Servidor HTTP con COOP/COEP/CORS y endpoint /probe
- `tools/send_payload.py` — Envío de payloads con detección automática de tipo
- `tools/listen_log.py` — Receptor de logs UDP con colores
- `payload/example/hello.c` — Payload de ejemplo mínimo
- `setup.sh` — Instalador automático del entorno
- `docs/architecture.md` — Análisis técnico de la cadena de explotación
- `docs/offsets_guide.md` — Guía para encontrar offsets con Ghidra
- `CONTRIBUTING.md` — Guía de contribución
- `LICENSE` — GPLv3

### Pendiente
- `triggerWebKitBug()` — Implementación del trigger del bug para FW 11.00
- `leakLibKernelBase()` — Leak de libkBase desde el proceso WebKit
- Verificación de offsets en `offsets_1100.js` con dump real del FW
- Tests unitarios para las herramientas Python
