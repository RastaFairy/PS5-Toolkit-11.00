# PS5 Toolkit 11.xx — Arbitrary Code Execution & Payload Injector

> **Target firmware:** 11.00 · **Architecture:** FreeBSD/AMD64 · **Entry point:** WebKit browser

Un toolkit completo, modular y fácil de entender para ejecutar código arbitrario en PS5 firmware 11.00 e inyectar payloads `.bin`, `.elf` y `.self`.

---

## Índice

- [Arquitectura general](#arquitectura-general)
- [Cadena de explotación](#cadena-de-explotación)
- [Requisitos](#requisitos)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Guía rápida](#guía-rápida)
- [Módulos](#módulos)
- [Compilar el ELF Loader](#compilar-el-elf-loader)
- [Enviar payloads](#enviar-payloads)
- [FAQ](#faq)
- [Créditos](#créditos)

---

## Arquitectura general

```
┌─────────────────────────────────────────────────────────────┐
│  PC (host)                         PS5 (FW 11.00)           │
│                                                             │
│  host/server.py ──HTTP:8000──► WebKit Browser               │
│       │                              │                       │
│       │                         exploit.js                   │
│       │                         (R/W primitives)             │
│       │                              │                       │
│       │                         kernel_exploit.js            │
│       │                         (privilege escalation)       │
│       │                              │                       │
│       │                         elfldr payload               │
│       │                         (SceRedisServer ptrace)      │
│       │                              │                       │
│  tools/send_payload.py ─TCP:9021──► ELF Loader              │
│                                      │                       │
│                                 Tu payload (.elf/.bin/.self) │
└─────────────────────────────────────────────────────────────┘
```

## Cadena de explotación

| Paso | Componente | Descripción |
|------|-----------|-------------|
| 1 | `exploit/index.html` | Página servida al browser de la PS5 |
| 2 | `exploit/js/primitives.js` | Bug WebKit → primitivas `read8` / `write8` / `leakobj` / `fakeobj` |
| 3 | `exploit/js/rop.js` | ROP chain via Web Worker (bypass CFI backward-edge) |
| 4 | `exploit/js/kernel.js` | Escalada de kernel (umtx/PSFree adaptado a 11.00) |
| 5 | `exploit/js/loader.js` | Envío del ELF loader al puerto 9020 bootstrap |
| 6 | `elfldr/` | ELF loader persistente vía ptrace en SceRedisServer |
| 7 | `tools/send_payload.py` | Envía `.elf`, `.bin` o `.self` al puerto 9021 |

---

## Requisitos

**En el PC (host):**
- Python 3.8+
- `pip install requests` (para el sender)
- Compilador LLVM/Clang cross para FreeBSD AMD64 (para recompilar el ELF loader)
- Misma red Wi-Fi / LAN que la PS5

**En la PS5:**
- Firmware **11.00** exactamente
- Conexión de red activa
- Acceso al navegador web integrado

---

## Estructura del proyecto

```
ps5-toolkit-11xx/
│
├── README.md                    ← Este archivo
│
├── exploit/                     ← Exploit WebKit (se sirve al browser PS5)
│   ├── index.html               ← Página de entrada
│   └── js/
│       ├── int64.js             ← Clase Int64 para aritmética de 64 bits
│       ├── primitives.js        ← Primitivas de lectura/escritura arbitraria
│       ├── rop.js               ← Constructor de cadenas ROP
│       ├── rop_worker.js        ← Worker JS para el pivot de stack
│       ├── offsets_1100.js      ← Offsets de libkernel/WebKit para FW 11.00
│       ├── kernel.js            ← Escalada de privilegios en kernel
│       └── loader.js            ← Carga el ELF loader en el proceso WebKit
│
├── elfldr/                      ← ELF Loader (C, compila con ps5-payload-sdk)
│   ├── Makefile
│   ├── main.c                   ← Punto de entrada, socket listener 9021
│   ├── elfldr.c                 ← Parser ELF + mmap + relocation
│   ├── elfldr.h
│   ├── pt.c                     ← ptrace helpers (bootstrap a SceRedisServer)
│   └── pt.h
│
├── payload/                     ← Payloads de ejemplo
│   └── example/
│       ├── hello.c              ← Payload mínimo: abre socket y saluda
│       └── Makefile
│
├── host/                        ← Servidor HTTP en el PC
│   └── server.py                ← Sirve exploit/ con headers correctos
│
├── tools/                       ← Utilidades de línea de comandos
│   ├── send_payload.py          ← Envía .elf / .bin / .self al ELF loader
│   └── listen_log.py            ← Recibe logs del PS5 por UDP 9998
│
└── docs/
    ├── architecture.md          ← Análisis técnico detallado
    └── offsets_guide.md         ← Cómo encontrar offsets para otras FWs
```

---

## Guía rápida

### 1. Levantar el servidor en el PC

```bash
# Clona el proyecto
git clone https://github.com/TU_USUARIO/ps5-toolkit-11xx
cd ps5-toolkit-11xx

# Edita la IP de tu PC en exploit/js/loader.js
# HOST_IP = "192.168.1.X"   ← cambia esto

# Levanta el servidor HTTP (necesita estar en el mismo segmento de red)
python3 host/server.py --port 8000
```

### 2. Abrir la página en la PS5

En el navegador web de la PS5, ve a:
```
http://192.168.1.X:8000/exploit/index.html
```

Espera a que el exploit complete las 5 fases (barra de progreso en pantalla).

### 3. Enviar un payload

```bash
# Enviar un ELF precompilado
python3 tools/send_payload.py --host PS5_IP --port 9021 --file mi_payload.elf

# Enviar un binario raw (.bin)
python3 tools/send_payload.py --host PS5_IP --port 9021 --file payload.bin --type bin

# Enviar un SELF (firmado, experimental)
python3 tools/send_payload.py --host PS5_IP --port 9021 --file payload.self --type self
```

---

## Compilar el ELF Loader

```bash
# Requiere ps5-payload-sdk instalado en /opt/ps5-payload-sdk
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
cd elfldr/
make
# Genera: elfldr.elf
```

---

## Enviar payloads

El script `tools/send_payload.py` detecta automáticamente el tipo de archivo por su magic bytes:

| Magic | Tipo |
|-------|------|
| `\x7fELF` | ELF nativo |
| `\x00PSF` | SELF firmado |
| cualquier otro | RAW binario |

---

## FAQ

**¿El exploit funciona en modo avión?**  
No, necesitas red para servir la página del exploit y enviar payloads.

**¿El ELF loader sobrevive al rest mode?**  
Sí. Al inyectarse en `SceRedisServer` vía ptrace, el loader persiste y se reactiva automáticamente.

**¿Qué pasa si el exploit falla?**  
Recarga la página. La barra de estado mostrará en qué fase falló. Los fallos más comunes son en el heap spray (fase 2); un segundo intento suele funcionar.

**¿Puedo cargar payloads de PS4?**  
No directamente. Los ELFs deben compilarse con el ps5-payload-sdk para la ABI correcta.

---

## Créditos

Este toolkit integra técnicas y conocimiento documentado públicamente por:

- **ChendoChap & Znullptr** — WebKit ROP execution / PS5 CFI analysis
- **john-tornblom** — ps5-payload-elfldr / ps5-payload-sdk
- **SpecterDev** — PS5-IPV6-Kernel-Exploit / PSFree
- **sleirsgoevy** — WebKit bug PoC original
- **idlesauce** — umtx2 webkit jailbreak framework
- **abc** — PSFree 150b
- **shahrilnet & n0llptr** — umtx lua implementation

> Este proyecto es **solo para fines educativos y de investigación de seguridad**.  
> Úsalo únicamente en hardware de tu propiedad y bajo tu propia responsabilidad.

---

*Licencia: GPLv3*
