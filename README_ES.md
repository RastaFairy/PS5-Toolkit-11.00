<div align="center">

<br/>

```
 ██████╗ ██████╗ ██████╗ ██╗███████╗██╗  ██╗██╗████████╗
██╔═══██╗██╔══██╗██╔══██╗██║██╔════╝██║ ██╔╝██║╚══██╔══╝
██║   ██║██████╔╝██████╔╝██║███████╗█████╔╝ ██║   ██║   
██║   ██║██╔══██╗██╔══██╗██║╚════██║██╔═██╗ ██║   ██║   
╚██████╔╝██║  ██║██████╔╝██║███████║██║  ██╗██║   ██║   
 ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
```

**Toolkit de ejecución de código arbitrario e inyección de payloads vía WebKit para PS5 firmware 11.xx**

<br/>

[![Firmware](https://img.shields.io/badge/Firmware-11.00-00b4d8?style=flat-square&logo=playstation)](.)
[![Arquitectura](https://img.shields.io/badge/Arch-FreeBSD%20AMD64-6060a0?style=flat-square)](.)
[![Lenguajes](https://img.shields.io/badge/Lang-C%20%7C%20JS%20%7C%20Python-ffe600?style=flat-square)](.)
[![Licencia](https://img.shields.io/badge/Licencia-GPLv3-00ffaa?style=flat-square)](./LICENSE)
[![Estado](https://img.shields.io/badge/Estado-Investigación-ff3c78?style=flat-square)](.)

<br/>

[Descripción](#descripción) · [Arquitectura](#arquitectura) · [Inicio rápido](#inicio-rápido) · [Módulos](#módulos) · [Contribuir](#contribuir) · [Créditos](#créditos)

<br/>

> **English** → [README.md](./README.md)

</div>

---

## Descripción

**OrbisKit** es un toolkit de investigación modular y bien documentado que encadena una serie de técnicas para lograr ejecución de código arbitrario en una PlayStation 5 con firmware **11.00**, y posteriormente inyectar payloads personalizados en formato `.elf`, `.bin` o `.self`.

Está diseñado para ser legible y didáctico — cada archivo está ampliamente comentado, cada decisión de diseño está explicada en `docs/`, y la cadena de explotación está dividida en módulos claramente separados e independientemente comprensibles.

### Qué hace

Partiendo de un bug de confusión de tipos en el motor JavaScript WebKit (variante de CVE-2021-30889 activa en FW 11.x), el toolkit:

1. Construye **primitivas de lectura/escritura** arbitraria en el proceso del browser
2. Filtra la base de `libkernel.sprx` y construye **cadenas ROP** mediante un stack pivot en un Web Worker (bypaseando el CFI forward-edge de Clang)
3. Escala al **kernel** usando una race condition umtx (UAF + pipe trick para kernel R/W)
4. Escapa del **contenedor Jail** de Orbis OS, obtiene **root**, desactiva SCEP y `kern.securelevel`
5. Instala un **ELF loader persistente** en `SceRedisServer` vía ptrace — sobrevive al rest mode y al cierre del browser
6. Escucha en el **puerto 9021** y ejecuta cualquier payload enviado desde el PC

### Protecciones del sistema abordadas

| Protección | Scope | Cómo se maneja |
|-----------|-------|----------------|
| SMEP | Kernel | No se activa — no hay ejecución user→kernel |
| SMAP | Kernel | Bypass mediante primitivas propias de kernel R/W |
| XOM (R^X) | User+Kernel | Gadgets obtenidos de la sección de datos de libkernel (legible) |
| Clang-CFI (forward-edge) | User+Kernel | No se activa — atacamos la **dirección de retorno** (backward-edge) |
| Shadow Stack | — | **No implementado en PS5** — nuestro vector de ataque principal |
| Hypervisor / Jail | Ambos | Parcheado via `cr_prison → prison0` en el ucred del proceso |

---

## Arquitectura

```
┌────────────────────────────────────────────────────────────────┐
│  PC (host)                        PS5 (FW 11.00 / Orbis OS)   │
│                                                                │
│  host/server.py ──── HTTP :8000 ──► Browser WebKit             │
│       │                                   │                    │
│       │                            exploit/js/*.js             │
│       │                            (primitivas + ROP)          │
│       │                                   │                    │
│       │                            kernel.js                   │
│       │                            (kbase, R/W, root)          │
│       │                                   │                    │
│       │  ◄── fetch elfldr.elf ────────────┤                    │
│       │                            loader.js                   │
│       │                            (envía ELF vía ROP socket)  │
│       │                                   │                    │
│       │                            SceRedisServer              │
│       │                            └─ elfldr (inyectado ptrace)│
│       │                               └─ listener :9021        │
│       │                                                        │
│  tools/send_payload.py ─ TCP :9021 ──► fork() + exec payload   │
│  tools/listen_log.py   ◄─ UDP :9998 ── logs broadcast          │
└────────────────────────────────────────────────────────────────┘
```

### Cadena de explotación resumida

| Paso | Archivo | Qué ocurre |
|------|---------|-----------|
| 1 | `exploit/js/primitives.js` | Bug WebKit → `leakobj` / `fakeobj` → `read8` / `write8` |
| 2 | `exploit/js/rop.js` | Leak de libkBase → ROPChain → stack pivot en Worker |
| 3 | `exploit/js/kernel.js` | UAF umtx → kernel R/W → container escape → root |
| 4 | `exploit/js/loader.js` | Fetch `elfldr.elf` → socket ROP al puerto :9020 |
| 5 | `elfldr/pt.c` | Inyección ptrace en `SceRedisServer` → :9021 persistente |
| 6 | `tools/send_payload.py` | El PC envía `.elf` / `.bin` / `.self` → PS5 lo ejecuta |

---

## Estructura del proyecto

```
orbiskit/
│
├── README.md                    ← Versión en inglés
├── README.es.md                 ← Este archivo
├── LICENSE                      ← GPLv3
├── CHANGELOG.md                 ← Historial de versiones
├── CONTRIBUTING.md              ← Cómo contribuir (inglés)
├── CONTRIBUTING.es.md           ← Cómo contribuir (español)
├── SECURITY.md                  ← Política de divulgación responsable
├── CODE_OF_CONDUCT.md           ← Estándares de la comunidad
│
├── exploit/                     ← Se sirve al browser de la PS5
│   ├── index.html               ← Orquestador UI (barra de progreso 5 fases)
│   └── js/
│       ├── int64.js             ← Aritmética de enteros de 64 bits
│       ├── offsets_1100.js      ← Offsets FW 11.00 (libkernel, WebKit, kernel)
│       ├── primitives.js        ← R/W userland via victim ArrayBuffer
│       ├── rop.js               ← Constructor ROPChain + pivot de stack Worker
│       ├── kernel.js            ← Escalada de kernel (kbase, R/W, root, escape)
│       └── loader.js            ← Fetch + envío de elfldr.elf vía ROP socket
│
├── elfldr/                      ← ELF Loader en C (compilar con ps5-payload-sdk)
│   ├── main.c                   ← Servidor TCP :9021, fork() por payload
│   ├── elfldr.c / elfldr.h      ← Parser ELF64/SELF/RAW, mmap, mprotect
│   ├── pt.c / pt.h              ← Bootstrap ptrace en SceRedisServer
│   └── Makefile
│
├── host/
│   └── server.py                ← Servidor HTTP (headers COOP/COEP + /probe)
│
├── tools/
│   ├── send_payload.py          ← Envía .elf / .bin / .self al puerto 9021
│   └── listen_log.py            ← Receptor de logs UDP desde la PS5
│
├── payload/example/
│   ├── hello.c                  ← Payload de ejemplo mínimo
│   └── Makefile
│
├── payloads/                    ← Coloca aquí tus payloads compilados
│
└── docs/
    ├── architecture.md          ← Análisis técnico detallado
    └── offsets_guide.md         ← Cómo encontrar offsets con Ghidra
```

---

## Inicio rápido

### Requisitos

**En el PC:**
- Python 3.8+
- `ps5-payload-sdk` (para recompilar el loader C si es necesario)
- Ghidra + script PS5 (para offsets — ver `docs/offsets_guide.md`)
- Misma red LAN/Wi-Fi que la PS5

**En la PS5:**
- Firmware **11.00** (exactamente — no actualizar)
- Conexión de red activa
- Acceso al browser WebKit integrado

---

### Paso a paso

**1. Clonar y configurar**

```bash
git clone https://github.com/RastaFairy/PS5-Toolkit-11.00
cd orbiskit

# Editar la IP del PC en dos lugares:
nano exploit/js/loader.js     # HOST_IP = "192.168.1.X"
nano payload/example/hello.c  # PC_IP   = "192.168.1.X"
```

**2. Levantar el servidor HTTP en el PC**

```bash
python3 host/server.py
# Mostrará la URL exacta que abrir en la PS5:
# → http://192.168.1.X:8000/exploit/index.html
```

**3. Abrir la página del exploit en la PS5**

Navega a la URL mostrada en el browser integrado de la PS5.  
Pulsa **▶ Ejecutar exploit** y espera a que completen las 5 fases.

**4. (Opcional) Ver logs en tiempo real**

```bash
# En una segunda terminal del PC:
python3 tools/listen_log.py
```

**5. Enviar un payload**

```bash
python3 tools/send_payload.py --host 192.168.1.50 --file payloads/mi_payload.elf

# Formatos soportados (detección automática por magic bytes):
#   .elf  → ELF64 nativo  (magic: \x7fELF)
#   .self → SELF de Sony  (magic: \x00PSF)
#   .bin  → Binario raw   (cualquier otro)
```

**6. Compilar el ELF loader (si lo modificas)**

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -C elfldr/
cp elfldr/elfldr.elf payloads/
```

---

## Módulos

| Módulo | Lenguaje | Descripción |
|--------|----------|-------------|
| `int64.js` | JS | Aritmética 64-bit (hi/lo), conversión float↔int64 para punteros |
| `offsets_1100.js` | JS | Todos los offsets de FW 11.00: gadgets, struct pthread, campos kernel |
| `primitives.js` | JS | Clase `Primitives` — read8/write8/readBytes/writeBytes |
| `rop.js` | JS | Clase `ROPChain` fluida, `findWorkerStack()`, `launchROPChain()` |
| `kernel.js` | JS | `KernelExploit` — kbase leak, kernel R/W, escape de Jail, root |
| `loader.js` | JS | `PayloadLoader` — fetch + socket ROP + polling de /probe |
| `elfldr/main.c` | C | Servidor TCP, manejo de conexiones, log UDP broadcast |
| `elfldr/elfldr.c` | C | Parser ELF64, mapeo PT_LOAD, relocations RELA, extracción SELF |
| `elfldr/pt.c` | C | ptrace attach, inyección de shellcode, redirect RIP, detach |
| `host/server.py` | Python | HTTP + headers COOP/COEP, endpoint /probe, /status |
| `tools/send_payload.py` | Python | Detección de tipo, validación ELF, barra de progreso |
| `tools/listen_log.py` | Python | Receptor UDP broadcast con timestamps y colores |

---

## Estado actual

| Componente | Estado | Notas |
|------------|--------|-------|
| Scaffold y arquitectura | ✅ Completo | Todos los archivos e interfaces definidos |
| Clases `Int64` + `Primitives` | ✅ Completo | Solo necesita las funciones base del bug |
| Constructor `ROPChain` | ✅ Completo | Soporte completo de syscalls y pivot de Worker |
| `KernelExploit` | ✅ Completo | Las cuatro sub-fases implementadas |
| ELF loader (C) | ✅ Completo | ELF64, SELF, RAW, modelo fork |
| Bootstrap ptrace | ✅ Completo | Cadena de inyección en SceRedisServer |
| Herramientas del host | ✅ Completo | server.py, send_payload.py, listen_log.py |
| Offsets FW 11.00 | ⚠️ Verificar | Los valores en `offsets_1100.js` necesitan validación contra dump real |
| `triggerWebKitBug()` | ❌ Pendiente | Requiere análisis binario del WebKit de FW 11.00 — el único eslabón faltante |
| `leakLibKernelBase()` | ❌ Pendiente | Requiere un puntero conocido en la GOT de WebKit |

---

## Contribuir

Las contribuciones son bienvenidas. Lee [CONTRIBUTING.md](./CONTRIBUTING.md) o [CONTRIBUTING.es.md](./CONTRIBUTING.es.md) antes de enviar un pull request.

Áreas donde más ayuda se necesita:
- Identificar el bug activo de WebKit en FW 11.00 (`triggerWebKitBug()`)
- Verificar y corregir offsets en `offsets_1100.js`
- Portar a versiones de firmware adyacentes

---

## Seguridad

Lee [SECURITY.md](./SECURITY.md) para la política de divulgación responsable.  
**No abras issues públicos** para vulnerabilidades sin parchear.

---

## Aviso legal

Este proyecto está destinado **exclusivamente a la investigación de seguridad y fines educativos**.  
Úsalo únicamente en hardware de tu propiedad y bajo tu propia responsabilidad.  
Los autores no asumen ninguna responsabilidad por usos indebidos.

---

## Créditos

OrbisKit se basa en técnicas documentadas públicamente y en el trabajo previo de:

| Investigador | Contribución |
|-------------|-------------|
| **ChendoChap & Znullptr** | ROP execution en WebKit, análisis CFI en PS5 |
| **john-tornblom** | ps5-payload-elfldr, ps5-payload-sdk |
| **SpecterDev** | PS5-IPV6-Kernel-Exploit, PSFree |
| **sleirsgoevy** | PoC original del bug WebKit |
| **idlesauce** | Framework webkit jailbreak framework |
| **abc** | PSFree 150b |
| **shahrilnet & n0llptr** | umtx lua implementation |

---

<div align="center">
<sub>Licensed under GPLv3 · For research use only · PS5 is a trademark of Sony Interactive Entertainment</sub>
</div>
