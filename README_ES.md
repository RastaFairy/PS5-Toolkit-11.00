# PS5-Toolkit — Scaffold de Investigación WebKit para FW 11.xx

> **English** → [README.md](README.md)  
> **Para no desarrolladores** → [docs/GUIDE_NONTECHNICAL.md](docs/GUIDE_NONTECHNICAL.md)  
> **Honestidad técnica completa** → [HONEST_LIMITATIONS.md](HONEST_LIMITATIONS.md)

---

## Antes de nada

Este proyecto **no es un exploit funcional**. Es un scaffold de investigación documentado.

Varios proyectos que circulan en la comunidad PS5 presentan código estructurado como este
como exploits funcionales. No lo son, y este tampoco. La diferencia aquí es que
documentamos exactamente qué falta y por qué, en lugar de ocultarlo.

**Si un proyecto afirma ser un exploit WebKit funcional para FW 11.xx y no te muestra
un vídeo ejecutándose en hardware real — asume que tiene los mismos huecos que este.**

El desglose completo de qué está roto y por qué está en [HONEST_LIMITATIONS.md](HONEST_LIMITATIONS.md).

---

## Qué contiene realmente este proyecto

Un scaffold arquitecturalmente correcto y completo para una cadena de explotación basada
en WebKit en PlayStation 5 firmware 11.xx. Cada módulo está implementado **excepto las
piezas que requieren análisis binario de un dump real de FW 11.00**:

| Componente | Estado | Qué lo bloquea |
|---|---|---|
| `triggerWebKitBug()` | ❌ TODO | Análisis del binario WebKit de FW 11.00 |
| `leakLibKernelBase()` | ❌ TODO | Puntero GOT del binario WebKit de FW 11.00 |
| Todos los offsets de gadgets ROP | ❌ `0x0` | Extracción de `libkernel_web.sprx` + ROPgadget |
| `_pipeRead8/Write8` | ❌ Stubs vacíos | Layout de `pipe_buffer` del binario del kernel |
| `_ropMmap()` | ❌ Devuelve `0x0` | Offset del gadget `mov [mem], rax` |
| Spin-wait en `pt.c` | ⚠️ No fiable | Offsets de `nanosleep`/`sched_yield` |
| Parser ELF64 (`elfldr.c`) | ✅ Funcional | Sin dependencia de firmware |
| `int64.js` | ✅ Funcional | Sin dependencia de firmware |
| Herramientas de host | ✅ Funcional | Sin dependencia de firmware |
| Lógica del constructor ROP | ✅ Correcta | Bloqueada solo por offsets que faltan |
| Lógica de escalada de kernel | ✅ Correcta | Bloqueada solo por primitivas que faltan |

La causa raíz única de todo lo de esa tabla es la misma:
**`offsets_1100.js` tiene cada valor crítico a `0x00000000`** porque esos valores
requieren un dump de firmware desencriptado que este proyecto no tiene.

---

## Correcciones técnicas vs. código previo en circulación

### ❌ No hay JIT en el browser de PS5

El browser de PS5 lanza WebKit con `ENABLE_JIT=OFF`. No hay compilador JIT,
no hay tier DFG, no hay tier FTL. Cualquier proyecto que describa un exploit de
"DFG JIT type confusion" apuntando al browser de PS5 es técnicamente incorrecto
por definición.

> Confirmado en el código fuente de PS4 en ps4-oss.com desde FW 6.00 en adelante.

### ❌ SharedArrayBuffer está deshabilitado

`new SharedArrayBuffer()` lanza una excepción en el browser de PS5. Este proyecto
usa objetos `ArrayBuffer` normales y `performance.now()` para temporización.
No hay `Atomics` en ningún sitio.

### ❌ No es V8

La PS5 usa JavaScriptCore (JSC), no V8. Las técnicas específicas de V8 —
TurboFan, Liftoff, Sparkplug, layout del heap de V8 — son irrelevantes aquí.

### ✅ Lo que sí es correcto

- Motor: JavaScriptCore (JSC), solo intérprete (LLInt)
- Primitiva de explotación: corrupción de longitud/puntero de ArrayBuffer vía type confusion en JSC
- Ejecución de código: solo ROP, gadgets de `libkernel_web.sprx`
- Temporización: bucles delta con `performance.now()` / `Date.now()`
- Arquitectura: FreeBSD AMD64 (Orbis OS)

---

## Qué hace la cadena de explotación (cuando esté completa)

Partiendo de una type confusion en JSC (misma clase que CVE-2021-30889, activa en FW 11.x):

1. **R/W en userland** — corromper el puntero del backing store de un ArrayBuffer → `read8`/`write8`
2. **Leak de base de libkernel** — leer una entrada GOT en WebKit que apunta a libkernel
3. **Cadena ROP** — cadena de gadgets vía pivote de stack en Web Worker, saltándose Clang CFI de borde directo
4. **Escalada al kernel** — UAF umtx → truco del pipe para R/W de kernel → root → escape de jail
5. **Cargador persistente** — inyección ptrace en `SceRedisServer` → listener TCP en puerto 9021
6. **Ejecución de payloads** — enviar `.elf`/`.bin`/`.self` desde el PC, la PS5 lo ejecuta

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│  PC HOST                         PS5 (FW 11.00 / Orbis OS) │
│                                                             │
│  host/server.py ─── HTTP :8000 ──► Browser WebKit          │
│       │                                  │                  │
│       │                           exploit/js/*.js           │
│       │                                  │                  │
│       │                           kernel.js                 │
│       │                           (kbase, R/W, root)        │
│       │                                  │                  │
│       │  ◄── fetch elfldr.elf ───────────┤                  │
│       │                           loader.js                 │
│       │                                  │                  │
│       │                           SceRedisServer            │
│       │                           └─ elfldr :9021           │
│       │                                                      │
│  tools/send_payload.py ─ TCP :9021 ──► fork() + exec        │
│  tools/listen_log.py   ◄─ UDP :9998 ── logs broadcast       │
└──────────────────────────────────────────────────────────────┘
```

---

## Estructura del proyecto

```
PS5-Toolkit/
│
├── README.md                     ← Versión inglesa
├── README_ES.md                  ← Este archivo (Español)
├── HONEST_LIMITATIONS.md         ← Desglose detallado de qué está roto y por qué
│
├── docs/
│   ├── GUIDE_NONTECHNICAL.md     ← Para no desarrolladores (EN/ES)
│   ├── architecture.md           ← Descripción técnica profunda (EN/ES)
│   └── offsets_guide.md          ← Cómo encontrar offsets con Ghidra (EN/ES)
│
├── exploit/
│   ├── index.html                ← UI del exploit servida al browser de PS5
│   └── js/
│       ├── int64.js              ← Helpers de enteros de 64 bits           ✅
│       ├── offsets_1100.js       ← Offsets FW 11.00 (todos a 0x0)         ❌
│       ├── primitives.js         ← Stub triggerWebKitBug()                 ❌
│       ├── rop.js                ← Stub leakLibKernelBase()                ❌
│       ├── kernel.js             ← Lógica kernel ✅ — stubs pipe R/W       ❌
│       └── loader.js             ← Entrega ELF — gadgets que faltan        ❌
│
├── elfldr/
│   ├── main.c                    ← Listener TCP :9021                      ✅
│   ├── elfldr.c / elfldr.h       ← Parser ELF64/SELF/RAW                  ✅
│   ├── pt.c / pt.h               ← Inyección ptrace ✅  spin-wait          ⚠️
│   └── Makefile
│
├── host/
│   └── server.py                 ← Servidor HTTP                           ✅
│
└── tools/
    ├── send_payload.py           ← Enviar payloads a la PS5                ✅
    └── listen_log.py             ← Recibir logs UDP                        ✅
```

---

## Cómo contribuir

La contribución más valiosa es rellenar `offsets_1100.js`.

Si tienes acceso a un dump de FW 11.00 y has hecho alguno de estos pasos,
una pull request con valores verificados es más útil que cualquier otra cosa:

- Identificado un bug de type confusion en JSC activo en WebKit de FW 11.00
- Encontrado un puntero GOT de `libkernel_web.sprx` en el binario WebKit
- Ejecutado ROPgadget contra `libkernel_web.sprx` de FW 11.00
- Identificado los offsets de la struct `pipe_buffer` en el kernel de FW 11.00
- Encontrado offsets de las structs `proc`/`ucred`/`prison` en FW 11.00

Ver [docs/offsets_guide.md](docs/offsets_guide.md) para el flujo paso a paso con Ghidra.

---

## Créditos

| Investigador | Contribución |
|---|---|
| ChendoChap & Znullptr | Ejecución ROP en WebKit, análisis CFI en PS5 |
| john-tornblom | ps5-payload-elfldr, ps5-payload-sdk |
| SpecterDev | PS5-IPV6-Kernel-Exploit, PSFree |
| sleirsgoevy | PoC original del bug WebKit |
| idlesauce | Framework umtx2 webkit jailbreak |
| abc | PSFree 150b |
| shahrilnet & n0llptr | Implementación umtx lua |

---

*Licencia GPLv3 · Solo para uso de investigación · PlayStation 5 es marca registrada de Sony Interactive Entertainment*
