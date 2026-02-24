# Changelog — PS5 Toolkit 11.xx

## [Unreleased]

### Pendiente

- **Verificar offsets contra binarios reales del FW 11.00**
  Ejecutar `python3 tools/gen_offsets.py --libkernel libkernel.elf --webkit WebKit.elf --kernel mini-syscore.elf`.
  Los valores actuales son estimaciones derivadas de análisis estático y versiones previas del firmware.
  Campos marcados con `// ⚠ VERIFICAR` en `offsets_1100.js`.

- **`prison0` offset en `kernel.js`**
  El campo `kernel.kbase_placeholder` en `offsets_1100.js` es un marcador.
  `analyze_kernel.py` extrae el offset real automáticamente al recibir el `.elf` del kernel.

- **Verificación empírica de `worker_ret_offset`**
  El valor `0x7FB88` es una estimación basada en FW anteriores.
  Debe verificarse en hardware una vez el bug esté disparando.
  Ver `docs/offsets_guide.md → Verificación empírica del Worker`.

- **Tests unitarios para `tools/send_payload.py` y `tools/server.py`**
  Suite pytest pendiente: detección de tipo de payload por magic bytes,
  validación ELF64, gestión de errores de red y timeout.

---

## [0.3.0]

### Añadido

#### `exploit/js/webkit_bug.js` — nuevo, 827 líneas

- **`triggerWebKitBug()`** implementada sobre CVE-2023-41993 (DFG JIT type confusion en JavaScriptCore)
  - *Fase 1 — Heap spray:* 0x800 `ArrayBuffer` de 64 bytes posicionan el bump pointer del allocator de JSC
  - *Fase 2 — Objetos de confusión:* par `confused/container` con 3 transiciones de estructura controladas
    que activan el path vulnerable de `clobberize()` en el compilador DFG
  - *Fase 3 — Warmup JIT:* 100 iteraciones graban la especulación de tipo "double" en el código compilado
  - *Fase 4 — Trigger:* rompe la invariante colocando un `JSObject*` donde el JIT espera double;
    hasta 3 reintentos automáticos con validación de rango de dirección en cada intento
  - Constantes de tuning documentadas: `JIT_WARMUP_ITERS`, `SPRAY_COUNT`, `SPRAY_AB_SIZE`,
    `STRUCTURE_TRANSITION_COUNT`, `FAKE_AB_SIZE`
  - `jitCompiledRead` / `jitCompiledWrite` en scope global (no closure) para garantizar compilación DFG
  - `leakobj(obj)` — coloca objeto en slot double, JIT lo lee sin type-check → fuga del puntero
  - `fakeobj(addr)` — escribe addr via JIT, lee por ruta no-JIT como objeto → fake JSObject
  - `corrupt()` — utilidad de bootstrapping para escrituras de offset directo
  - `detectJSEngine()` — verifica que estamos en JavaScriptCore antes de ejecutar
  - `patchOffset(path, value)` — ajusta cualquier offset en `OFFSETS` desde la consola
    de WebInspector sin recargar la página

- **`leakLibKernelBase(p)`** implementada en `webkit_bug.js`
  - `addrof(new RegExp('a'))` → lee `JSRegExp*` en slot inline +0x10 → lee vtable C++
    → resta `vtable_jsregexp_offset` → `webkit_base`
  - Lee `GOT[pthread_create]` en `webkit_base + got_pthread_create`
    → resta offset del símbolo en libkernel → `libkBase`
  - Verificación de page-alignment en el resultado final; mensajes de error accionables en cada paso

#### `exploit/js/offsets_1100.js` — nuevos campos

- Sección `webkit` ampliada con: `vtable_jsregexp_offset`, `regexp_internal_offset`,
  `got_pthread_create`, `got_mmap`, `got_write`
- Nueva sección `libkernel_syms` con offsets de funciones individuales para el GOT read:
  `pthread_create`, `pthread_self`, `mmap`, `write`
- Todos los campos nuevos anotados con `// ⚠ VERIFICAR` y comentarios de cómo obtenerlos

#### `exploit/index.html`

- Añadida carga de `webkit_bug.js` en el orden correcto de scripts
- Eliminados los stubs `triggerWebKitBug()` y `leakLibKernelBase()` que lanzaban excepciones

#### `tools/` — suite de análisis automático de binarios (5 scripts nuevos)

- **`self2elf.py`** — convierte SELF/SPRX de PS5 a ELF puro sin dependencias pip
  - Modo individual, batch de directorio (`--dir`/`--out`) y verificación (`--check`)
  - Detecta SELF cifrado vs descifrado; pasa transparentemente los archivos que ya son ELF
  - Verifica clase ELF64 y arquitectura x86-64 en el output

- **`analyze_libkernel.py`** — extrae offsets de `libkernel.elf` con 4 análisis
  - Gadgets ROP (pop rdi/rsi/rdx/rcx/r8/r9/rax/rsp; ret, syscall; ret, xchg rax,rsp)
    via disassembly completo con objdump y búsqueda de ventanas de 1-4 instrucciones
  - Símbolos de 20 funciones vía nm; thread_list por búsqueda de hints conocidos
  - Offsets de `pthread_t` por análisis de funciones `pthread_attr_getstack` en disassembly
  - GOT entries para el leak de libkBase; genera fragmento JS listo para `offsets_1100.js`

- **`analyze_webkit.py`** — extrae offsets de `WebKit.elf` con 3 análisis
  - Lee tabla de relocaciones dinámicas (`readelf -r`) para enumerar entradas GOT
  - Cruza con `libkernel.elf` (opcional) para calcular el offset final del símbolo
  - Selección automática del mejor candidato por lista de preferencia
  - Busca strings de Worker y referencias a `0x80000` en el disassembly

- **`analyze_kernel.py`** — extrae offsets del kernel ELF con 3 análisis
  - Símbolos: `allproc`, `prison0`, `kern_securelevel`, `rootvnode`, `nproc`
  - Offsets de `struct proc` por análisis de `pfind()` con heurísticas de rango
  - Offsets de `struct ucred` con valores FreeBSD 11 como fallback documentado

- **`gen_offsets.py`** — orquestador maestro
  - Invoca los tres analizadores; conversión automática SPRX→ELF si se pasan `.sprx`
  - Genera `offsets_1100.js` completo con indicadores de confianza por sección
    (ALTA / MEDIA / BAJA), constantes de syscalls de Orbis y objeto `OFFSETS_1100` de exports
  - Flags: `--libkernel`, `--webkit`, `--kernel`, `--out`, `--tmp`, `--verbose`,
    `--libkernel-sprx`, `--webkit-sprx`

- **`tools/ANALYSIS_README.md`** — guía de uso completa de las herramientas de análisis

---

## [0.2.0]

### Añadido

#### Documentación visual en español

- **`ps5-toolkit-descripcion.html`** — guía visual interactiva en español
  - Diseño cyberpunk oscuro (Space Mono, Syne, IBM Plex Mono); paleta PS5 azul/cyan
  - 9 secciones: hero, resumen, tabla de mitigaciones (SMEP/SMAP/XOM/CFI/Hypervisor),
    diagrama de la cadena de explotación en 7 pasos, arquitectura PC↔PS5,
    descripción de 12 módulos, árbol de archivos, pasos paralelos usuario/sistema,
    checklist de estado del proyecto

- **`ps5-toolkit-plan-tutorial.html`** — plan de acción y tutorial técnico completo
  - 4 tareas priorizadas por impacto con niveles BLOCKER / CRÍTICO / MEDIO / BAJO
  - Plan de 3 fases con estimaciones de tiempo por fase
  - Tutorial T1–T5 con comandos exactos, snippets de código comentados, fuentes
    y notas de herramientas

#### Archivos del proyecto completados

- **`LICENSE`** — texto completo de GPLv3 (17 secciones completas)
- **`CONTRIBUTING.md`** — guía de contribución con tabla de áreas prioritarias,
  convenciones de commits (`feat/fix/docs/offset/refactor`), estándares de código
  JS/C/Python, guías de seguridad para contribuidores
- **`setup.sh`** — instalador automático multi-OS
  - Detección: Debian/Ubuntu, macOS, Arch Linux
  - Verificación: Python ≥3.8, git, netcat, clang/make (con `--sdk`)
  - Auto-detección de IP local y parcheo de `HOST_IP` en `loader.js` y `hello.c`
  - Flag `--sdk`: clona `ps5-payload-dev/sdk` a `/opt/ps5-payload-sdk` y compila
  - Output coloreado con banner ASCII
- **`exploit/js/rop_worker.js`** — Web Worker víctima con handler `onmessage`,
  lógica de warmup/trigger y mensajes de confirmación de carga
- **`.github/ISSUE_TEMPLATE/bug_report.md`** — plantilla de reporte con campos
  de firmware/OS, checkboxes de fase y sección de logs
- **`.github/ISSUE_TEMPLATE/offsets.md`** — plantilla de contribución de offsets
  con tablas de `libkernel`/`WebKit`/`kernel` y campos de método de verificación

---

## [0.1.0]

### Añadido

Scaffold completo del proyecto — 30 archivos.

#### `exploit/` — cadena de explotación WebKit

- **`exploit/index.html`** — UI de 5 fases con barra de progreso, logs coloreados
  en tiempo real y botón de reintento. Incluye todos los módulos JS en orden.

- **`exploit/js/int64.js`** — aritmética de enteros de 64 bits para JavaScript
  - Clase `Int64`: constructores por `(lo, hi)`, `fromDouble()`, `toDouble()`
  - `add32()`, `sub()`, `add()` con carry correcto
  - Comparación, `.hi` / `.lo` accessors, `.toString()` en hex

- **`exploit/js/offsets_1100.js`** — tabla de offsets del FW 11.00
  - Secciones: `libkernel` (syscall stubs, gadgets ROP, pthread),
    `webkit` (worker offsets, gadgets), `kernel` (proc/ucred/prison estructuras)

- **`exploit/js/primitives.js`** — clase `Primitives`
  - `addrof(obj)` → `Int64`; `read8/write8/read4/write4`; `readBytes/writeBytes/readCString`
  - `_setVictimPointer(addr)` — sobreescribe campo `vector` (+0x10) del `Float64Array` víctima

- **`exploit/js/rop.js`** — ROPChain builder + Worker stack pivot
  - Clase `ROPChain` con `push()`, `pushAddr()`, `build()` y resolución de gadgets
  - `createROPWorker()` — crea el Worker y espera confirmación de carga
  - `findWorkerStack(p, libkBase)` — itera `thread_list`, filtra por `stack_size == 0x80000`
  - `executeROPChain()` — sobreescribe `worker_ret_offset` y envía mensaje trigger

- **`exploit/js/kernel.js`** — clase `KernelExploit`
  - `leakKbase()` — fuga `kbase` via syscall `umtx_op`
  - `findCurrentProcess(allproc)` — itera `allproc` por PID
  - `escalatePrivileges(proc)` — modifica `p_ucred`: UIDs a 0
  - `escapeJail(ucred)` — pone `cr_prison = &prison0`

- **`exploit/js/loader.js`** — clase `PayloadLoader`
  - `downloadELF(url)` → descarga `elfldr.elf`
  - `injectIntoRedis(elfData)` → inyecta en `SceRedisServer` via ptrace
  - `waitForLoader()` → polling TCP :9021 con timeout

#### `elfldr/` — ELF Loader nativo en C

- **`elfldr.c`** — parser ELF64: PHDRs PT_LOAD con mmap/mprotect, relocaciones
  `R_X86_64_RELATIVE/GLOB_DAT/JUMP_SLOT/64`, llamada a `DT_INIT`/`DT_INIT_ARRAY`/entry
- **`main.c`** — servidor TCP :9021: recepción de payload, detección de tipo por magic bytes,
  log UDP :9998
- **`pt.c`** — bootstrap vía ptrace: attach, inyección de shellcode, find `SceRedisServer`,
  execute, detach
- **`elfldr.h`** / **`pt.h`** / **`Makefile`**

#### `payload/example/`

- **`hello.c`** — envía "Hello from PS5!" via UDP y sale limpiamente
- **`Makefile`** — compilación con ps5-payload-sdk

#### `host/` y `tools/`

- **`host/server.py`** — HTTP con cabeceras COOP/COEP/CORS para SharedArrayBuffer
- **`tools/send_payload.py`** — cliente TCP para payloads: detección de tipo, progreso
- **`tools/listen_log.py`** — receptor UDP de logs con colores y timestamp

#### `docs/`

- **`docs/architecture.md`** — análisis técnico de la cadena completa
- **`docs/offsets_guide.md`** — guía de extracción de offsets con Ghidra y ROPgadget

#### Configuración

- **`README.md`** — documentación completa del proyecto
- **`.gitignore`** — ignora dumps del FW, `.elf`, `.bin`, `__pycache__`, artefactos de build
- **`payloads/.gitkeep`** — directorio para payloads del usuario

---

## Resumen de completitud

| Componente | v0.1.0 | v0.2.0 | v0.3.0 |
|---|:---:|:---:|:---:|
| `triggerWebKitBug()` | ✗ stub | ✗ stub | ✅ CVE-2023-41993 |
| `leakLibKernelBase()` | ✗ stub | ✗ stub | ✅ GOT+vtable leak |
| `primitives.js` | ✅ | ✅ | ✅ |
| `rop.js` | ✅ | ✅ | ✅ |
| `kernel.js` | ✅ | ✅ | ✅ |
| `loader.js` + `elfldr/` | ✅ | ✅ | ✅ |
| `offsets_1100.js` | ⚠ parcial | ⚠ parcial | ⚠ verificar |
| Herramientas análisis | 2 scripts | 2 scripts | 7 scripts |
| Documentación ES | — | ✅ | ✅ |
| Instalador | — | ✅ | ✅ |
| GitHub templates | — | ✅ | ✅ |
