# HONEST_LIMITATIONS.md

> **English** · [Español](#español)

---

## What this project actually is

This is a **documented scaffold**. The architecture is real, the concepts are correct,
and the code structure reflects how a working chain would be organized. But several
critical pieces are **not implemented** — not because they are conceptually difficult,
but because they require something this project does not have:

**A decrypted FW 11.00 binary dump analyzed in Ghidra.**

Everything below explains exactly where the code breaks and why.

---

## The single root cause

Every unimplemented piece in this project converges on the same blocker:

```
offsets_1100.js — every critical value is 0x00000000
```

These are not placeholder aesthetics. A zero offset means the code will
compute `libkernelBase + 0x0` and either crash, hang, or silently corrupt
memory. Code with invented addresses is **worse than a stub** — it fails
without a clear error instead of failing loudly.

To fill in these values you need:
1. A PS5 on FW 11.00 (do not update)
2. An existing kernel exploit for an older firmware to dump memory
3. The extracted `libkernel_web.sprx` and `WebKit` binaries
4. Ghidra + ps5 community scripts to analyze them
5. ROPgadget or a similar tool to find gadget offsets

Nobody on this project has done that analysis yet. That is the honest state.

---

## Broken piece #1 — `kernel.js`

### What is marked "complete" but is empty

```js
_pipeRead8()       { /* reads 8 bytes from slave rfd  */ }
_pipeWrite8()      { /* writes 8 bytes to slave wfd   */ }
_masterPipeWrite8(){ /* writes via master pipe         */ }
```

These three methods are the **entire kernel R/W primitive**. Without them,
nothing in Phase 4 works. The rest of `KernelExploit` (`_escalate`,
`_disableSecurityChecks`, `_findProcSelf`) is logically correct but
completely unreachable.

### What the real implementation needs

The pipe trick works like this conceptually:

```
1. Allocate two pipe pairs (master, slave) via SYS_PIPE2
2. Use umtx UAF to corrupt the slave pipe's internal pipe_buffer.buffer
   pointer so it points to the kernel address you want to read/write
3. write(slave_wfd, userBuf, 8)  → kernel copies 8 bytes FROM userBuf
                                    TO the address you pointed at
4. read(slave_rfd,  userBuf, 8)  → kernel copies 8 bytes FROM that address
                                    TO userBuf
```

The blocker is step 2. `pipe_buffer` is a kernel struct. Its layout in
FW 11.00 is unknown without the decrypted kernel binary. Any offset
written here without that analysis is invented.

---

## Broken piece #2 — `_ropMmap()` in `kernel.js`

### What it currently does

```js
async _ropMmap(size) {
    log(`[kernel] _ropMmap(0x${size.toString(16)}) — placeholder`);
    return new Int64(0);  // ← returns null address every time
}
```

Every call to `_ropMmap()` in the codebase gets back address `0x0`.
Every subsequent `primitives.writeBytes(0x0, ...)` is writing into
the zero page, which will segfault the renderer process.

### What the real implementation needs

Conceptually straightforward — the syscall numbers are stable across
firmware versions:

```
SYS_MMAP    = 197
PROT_RW     = 3    (PROT_READ | PROT_WRITE)
MAP_PRIVATE | MAP_ANONYMOUS = 0x1002
```

The blocker is **capturing the return value**. After `syscall`, the
allocated address is in `rax`. To use it, you need a gadget like:

```asm
mov [rbx], rax
ret
```

or equivalent — that writes `rax` into a known memory location so the
JS side can read it back. That gadget's offset within `libkernel_web.sprx`
is FW-specific. It is `0x0` in `offsets_1100.js`.

---

## Broken piece #3 — `loader.js`

### The missing offsets

`_sendViaRopSocket()` references two gadgets that do not exist in `offsets_1100.js`:

```js
chain.gadget(OFFSETS.GADGET_MOV_MEM_RAX || 0)  // ← falls back to 0x0
chain.gadget(OFFSETS.GADGET_MOV_RDI_MEM || 0)  // ← falls back to 0x0
```

These gadgets are real and exist in any sufficiently large x86-64 binary.
The `||0` fallback means the chain silently uses address `libkernelBase + 0x0`
as a gadget — which is not a gadget, it is the start of the binary — and
execution immediately goes wrong.

### What the real implementation needs

Run ROPgadget against the extracted `libkernel_web.sprx`:

```bash
ROPgadget --binary libkernel_web.sprx --rop --depth 4 | grep "mov qword ptr"
ROPgadget --binary libkernel_web.sprx --rop --depth 3 | grep "mov rdi"
```

Record the offsets of suitable sequences and put them in `offsets_1100.js`.
Without the binary, these are unknowable.

---

## Broken piece #4 — `pt.c`

### The spin-wait problem

```c
volatile int spin = 1000000;
while (spin-- > 0) { /* busy wait */ }
```

This is wrong for a ptrace injection context. The injected shellcode is
running inside a thread borrowed from `SceRedisServer`. Busy-waiting
in a borrowed thread:

- Consumes 100% of that core for the duration
- Can trigger Orbis OS's watchdog (the system may kill the process)
- Has no guaranteed minimum duration — the scheduler can preempt it
  before the listener thread is ready

### What the correct implementation needs

```c
// Option A: yield and retry
struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; // 10ms
nanosleep(&ts, NULL);

// Option B: use a shared flag
// elfldr_main() sets a volatile flag when the listener is bound.
// The shellcode spins on that flag with a yield each iteration.
volatile int *ready_flag = (volatile int *)SCRATCH_ADDR;
while (!*ready_flag) sched_yield();
```

Both `nanosleep` and `sched_yield` are libkernel functions.
Their offsets in FW 11.00 `libkernel_web.sprx` are — again — unknown
without the binary.

---

## What this means practically

| Component | State | Blocker |
|---|---|---|
| `triggerWebKitBug()` | ❌ TODO | FW 11.00 WebKit binary analysis |
| `leakLibKernelBase()` | ❌ TODO | GOT pointer from FW 11.00 WebKit |
| All ROP gadget offsets | ❌ 0x0 | `libkernel_web.sprx` binary analysis |
| `_pipeRead8/Write8` | ❌ Empty | `pipe_buffer` layout from kernel binary |
| `_ropMmap()` | ❌ Returns 0 | `mov [mem], rax` gadget offset |
| `pt.c` spin-wait | ⚠️ Unreliable | `nanosleep`/`sched_yield` offsets |
| ELF64 parser (`elfldr.c`) | ✅ Real | No firmware dependency |
| `int64.js` | ✅ Real | No firmware dependency |
| Tools (`server.py`, etc.) | ✅ Real | No firmware dependency |
| ROP chain builder logic | ✅ Real | Blocked only by missing offsets |
| Kernel escalation logic | ✅ Real | Blocked only by missing primitives |

---

## How to actually complete this

The path is linear and well-understood. It has been done for previous
firmware versions by the researchers credited in README.md. For FW 11.00
specifically, the work has not been published.

```
1. Obtain FW 11.00 system firmware dump
   └─ Requires a working exploit on an older firmware

2. Decrypt and extract binaries
   ├─ WebKit (renderer process)
   └─ libkernel_web.sprx

3. Analyze WebKit in Ghidra
   ├─ Find a type confusion bug in JSC (CVE-2021-30889 class)
   ├─ Identify the GOT entry pointing into libkernel
   └─ → fills triggerWebKitBug() and leakLibKernelBase()

4. Run ROPgadget on libkernel_web.sprx
   └─ → fills all OFFSETS.GADGET_* values

5. Analyze kernel binary in Ghidra
   ├─ Find pipe_buffer struct layout
   ├─ Find proc/ucred/prison struct offsets
   └─ → fills all OFFSETS.KERN_* values

6. Test on hardware iteratively
```

If you have completed any of these steps for FW 11.00, contributions to
`offsets_1100.js` are the single most valuable thing you can add to this project.

---

## Why this document exists

Several projects circulating in the PS5 research community present scaffolds
like this one as working exploits. They are not. The gaps described above
are the same gaps in all of them. Publishing this honestly is more useful
to the community than maintaining the appearance of completeness.

If a project claims to be a working FW 11.00 WebKit exploit and does not
show you a video of it running on real hardware, assume it has the same
holes documented here.

---

---

<a id="español"></a>

## ESPAÑOL — Lo que este proyecto realmente es

Este es un **scaffold documentado**. La arquitectura es real, los conceptos
son correctos, y la estructura del código refleja cómo se organizaría una
cadena funcional. Pero varias piezas críticas **no están implementadas** —
no porque sean conceptualmente difíciles, sino porque requieren algo que
este proyecto no tiene:

**Un dump de firmware FW 11.00 desencriptado y analizado en Ghidra.**

---

## La causa raíz única

Cada pieza no implementada converge en el mismo bloqueo:

```
offsets_1100.js — cada valor crítico es 0x00000000
```

Estos no son placeholders estéticos. Un offset a cero significa que el
código calculará `libkernelBase + 0x0` y o bien crasheará, se colgará,
o corromperá memoria silenciosamente. Código con direcciones inventadas
es **peor que un stub** — falla sin error claro en lugar de fallar con
un mensaje explícito.

Para rellenar estos valores necesitas:
1. Una PS5 en FW 11.00 (no actualizar)
2. Un exploit de kernel para firmware anterior para volcar memoria
3. Los binarios extraídos `libkernel_web.sprx` y `WebKit`
4. Ghidra + scripts de la comunidad PS5 para analizarlos
5. ROPgadget u herramienta similar para encontrar offsets de gadgets

Nadie en este proyecto ha hecho ese análisis todavía. Ese es el estado honesto.

---

## Pieza rota #1 — `kernel.js`

### Lo que está marcado como "completo" pero está vacío

```js
_pipeRead8()       { /* reads 8 bytes from slave rfd  */ }
_pipeWrite8()      { /* writes 8 bytes to slave wfd   */ }
_masterPipeWrite8(){ /* writes via master pipe         */ }
```

Estos tres métodos son **toda la primitiva de R/W del kernel**. Sin ellos,
nada en la Fase 4 funciona. El resto de `KernelExploit` es lógicamente
correcto pero completamente inalcanzable.

### Lo que la implementación real necesita

El truco del pipe funciona así conceptualmente:

```
1. Asignar dos pares de pipe (master, slave) vía SYS_PIPE2
2. Usar el UAF umtx para corromper el puntero pipe_buffer.buffer del
   pipe slave para que apunte a la dirección de kernel que queremos
3. write(slave_wfd, userBuf, 8)  → el kernel copia 8 bytes DESDE userBuf
                                    A la dirección apuntada
4. read(slave_rfd,  userBuf, 8)  → el kernel copia 8 bytes DESDE esa dirección
                                    A userBuf
```

El bloqueo está en el paso 2. `pipe_buffer` es una struct del kernel.
Su layout en FW 11.00 es desconocido sin el binario del kernel desencriptado.
Cualquier offset escrito aquí sin ese análisis es inventado.

---

## Pieza rota #2 — `_ropMmap()` en `kernel.js`

### Lo que hace actualmente

```js
async _ropMmap(size) {
    log(`[kernel] _ropMmap(0x${size.toString(16)}) — placeholder`);
    return new Int64(0);  // ← devuelve dirección nula siempre
}
```

Cada llamada a `_ropMmap()` devuelve la dirección `0x0`. Cada
`primitives.writeBytes(0x0, ...)` posterior escribe en la página cero,
lo que provocará un segfault en el proceso del renderizador.

### Lo que la implementación real necesita

Los números de syscall son estables entre versiones de firmware:

```
SYS_MMAP    = 197
PROT_RW     = 3    (PROT_READ | PROT_WRITE)
MAP_PRIVATE | MAP_ANONYMOUS = 0x1002
```

El bloqueo es **capturar el valor de retorno**. Después del `syscall`,
la dirección asignada está en `rax`. Para usarla necesitas un gadget como:

```asm
mov [rbx], rax
ret
```

Ese offset dentro de `libkernel_web.sprx` es específico del firmware.
Está a `0x0` en `offsets_1100.js`.

---

## Pieza rota #3 — `loader.js`

### Los offsets que faltan

`_sendViaRopSocket()` referencia dos gadgets que no existen en `offsets_1100.js`:

```js
chain.gadget(OFFSETS.GADGET_MOV_MEM_RAX || 0)  // ← cae a 0x0
chain.gadget(OFFSETS.GADGET_MOV_RDI_MEM || 0)  // ← cae a 0x0
```

El fallback `||0` hace que la cadena use silenciosamente `libkernelBase + 0x0`
como gadget — que no es un gadget, es el inicio del binario — y la ejecución
se rompe inmediatamente.

### Lo que la implementación real necesita

```bash
ROPgadget --binary libkernel_web.sprx --rop --depth 4 | grep "mov qword ptr"
ROPgadget --binary libkernel_web.sprx --rop --depth 3 | grep "mov rdi"
```

Sin el binario, estos valores son incognoscibles.

---

## Pieza rota #4 — `pt.c`

### El problema del spin-wait

```c
volatile int spin = 1000000;
while (spin-- > 0) { /* busy wait */ }
```

Esto es incorrecto en un contexto de inyección ptrace. El shellcode inyectado
corre en un hilo prestado de `SceRedisServer`. Un busy-wait en un hilo prestado:

- Consume el 100% del núcleo durante la espera
- Puede activar el watchdog de Orbis OS (el sistema puede matar el proceso)
- No tiene duración mínima garantizada — el scheduler puede interrumpirlo
  antes de que el hilo listener esté listo

### Lo que la implementación correcta necesita

```c
// Opción A: ceder y reintentar
struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; // 10ms
nanosleep(&ts, NULL);

// Opción B: flag compartido
volatile int *ready_flag = (volatile int *)SCRATCH_ADDR;
while (!*ready_flag) sched_yield();
```

Los offsets de `nanosleep` y `sched_yield` en `libkernel_web.sprx` de
FW 11.00 son — de nuevo — desconocidos sin el binario.

---

## Por qué existe este documento

Varios proyectos que circulan en la comunidad de investigación PS5 presentan
scaffolds como este como exploits funcionales. No lo son. Los huecos descritos
arriba son los mismos en todos ellos. Publicar esto honestamente es más útil
para la comunidad que mantener la apariencia de completitud.

**Si un proyecto afirma ser un exploit WebKit funcional para FW 11.00 y no
te muestra un vídeo ejecutándose en hardware real, asume que tiene los mismos
huecos documentados aquí.**
