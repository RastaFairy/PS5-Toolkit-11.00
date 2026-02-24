# Technical Architecture / Arquitectura Técnica

> [English](#english) · [Español](#español)

---

<a name="english"></a>
# ENGLISH

## Why No JIT?

The PS5 browser launches WebKit (used since PS4) with the environment variable
`ENABLE_JIT=OFF` for the renderer process. Confirmed in PS4 source code at ps4-oss.com
from as early as FW 6.00. Since the PS5 uses the same WebKit lineage, the same flag applies.

**Consequence:** No JIT compiler process exists. There is no DFG (Data Flow Graph) tier,
no FTL (Faster Than Light) tier, and no B3 backend. JavaScript runs purely through the
LLInt (Low-Level Interpreter) and, for hot code, the Baseline JIT... wait, no — with
ENABLE_JIT=OFF even the Baseline JIT is compiled out. Everything runs through LLInt only.

This means:
- No JIT spray (can't place shellcode in JIT-compiled memory)
- No DFG type confusion exploits
- No JIT heap manipulation
- Code execution **must** go through ROP exclusively

## Why No SharedArrayBuffer?

SharedArrayBuffer was disabled across all major browsers after the Spectre/Meltdown
disclosure in January 2018, because it enables high-resolution timing via Atomics.wait/notify
that can be used for side-channel attacks. Sony has not re-enabled it in the PS5 browser.

**Consequence:** No `new SharedArrayBuffer()`, no `Atomics.wait()`, no `Atomics.notify()`,
no cross-agent memory sharing. All primitives must use plain `ArrayBuffer` objects.
Timing must use `performance.now()` or `Date.now()` delta loops.

## Engine: JavaScriptCore, not V8

The PS5 browser uses WebKit, which bundles JavaScriptCore (JSC) as its JavaScript engine.
V8 is Google's engine, used in Chrome, Chromium-based browsers, and Node.js.
The PS5 has no Chromium, no V8, and no V8-specific primitives.

JSC and V8 differ significantly in their heap layout, object representation, and compiler
tiers. Any exploit technique described in terms of V8 internals (Maps, Hidden Classes as
V8 calls them, TurboFan, Liftoff, Sparkplug) is not applicable to the PS5.

## The Exploit Chain in Detail

### Stage 1: JSC Type Confusion → Userland R/W

A type confusion vulnerability in JSC causes the engine to misidentify the type of a
JavaScript value stored in the heap. This is the same *class* of vulnerability as
CVE-2021-30889 and its variants. The specific variant active in FW 11.00 needs to be
identified by analyzing the WebKit binary.

The type confusion is used to implement two primitive operations:
- `leakobj(obj)`: returns the raw 64-bit JSC cell pointer for a JS object
- `fakeobj(addr)`: returns a JS object whose internal cell pointer is at `addr`

With these two, the standard "victim ArrayBuffer" technique gives us:
- `read8(addr)`: read 8 bytes from any address in the WebKit process
- `write8(addr, val)`: write 8 bytes to any address in the WebKit process

### Stage 2: Leak libkernel Base

The WebKit binary's GOT (Global Offset Table) contains pointers to imported functions
from libkernel.sprx. We read one of these pointers using `read8()` and subtract the
known offset of that function within libkernel to get the library's base address.

This is needed because ASLR randomises library load addresses on every boot.

### Stage 3: ROP Chain via Worker Stack Pivot

With libkernel base known, we compute absolute addresses of gadgets (short instruction
sequences ending in `ret`) within libkernel. We:

1. Spin up a Web Worker (a background JavaScript thread)
2. Locate its native stack using JSC thread structure pointers (read via primitives)
3. Find the return address slot of a known stack frame
4. Overwrite that slot with a stack-pivot gadget address
5. Write our fake stack (the ROP chain) elsewhere in writable memory
6. The pivot gadget executes, moving `$rsp` to our fake stack
7. The CPU follows our chain of gadgets

This bypasses Clang forward-edge CFI because we attack the return address
(backward edge), not vtable or function pointer calls.

### Stage 4: Kernel Escalation

Via ROP we trigger a **umtx race condition** (a FreeBSD-specific use-after-free in the
userland threading library's mutexes). This gives us kernel read/write via the pipe trick:

- Allocate two pipe file descriptors
- Use the UAF to place a controlled kernel object where the pipe's internal buffer pointer is
- Read/write to the pipe fd now reads/writes arbitrary kernel memory

With kernel R/W we:
- Find our own `proc` structure in the kernel process list
- Read `proc→p_ucred` to get our credential structure
- Overwrite `ucred→cr_uid` to 0 (root)
- Overwrite `ucred→cr_prison` to point to `prison0` (escape jail)
- Disable `kern.securelevel` and SCEP kernel integrity checks

### Stage 5: Persistent ELF Loader

We use ptrace (now allowed because we have root and escaped the jail) to inject a small
shellcode stub into `SceRedisServer` — a background process that stays running across
browser restarts and rest mode. The stub sets up a TCP listener on port 9021.

When the host PC connects and sends an ELF binary, the loader parses it, maps segments
into memory, applies relocations, and calls the entry point in a forked child process.

---

<a name="español"></a>
# ESPAÑOL

## Por qué No Hay JIT

El navegador de PS5 lanza WebKit con la variable de entorno `ENABLE_JIT=OFF` para el proceso
del renderizador. Confirmado en el código fuente de PS4 en ps4-oss.com desde al menos FW 6.00.

**Consecuencia:** No existe ningún proceso compilador JIT. No hay tier DFG (Data Flow Graph),
no hay tier FTL (Faster Than Light), y no hay backend B3. JavaScript se ejecuta puramente
a través de LLInt (Low-Level Interpreter). Con ENABLE_JIT=OFF incluso el Baseline JIT está
compilado fuera. Todo pasa por LLInt únicamente.

Esto significa:
- No es posible JIT spray (no se puede colocar shellcode en memoria compilada por JIT)
- No funcionan los exploits de type confusion en DFG
- La ejecución de código **debe** ir exclusivamente por ROP

## Por qué No Hay SharedArrayBuffer

SharedArrayBuffer fue deshabilitado en todos los navegadores principales tras la divulgación
de Spectre/Meltdown en enero de 2018. Sony no lo ha rehabilitado en el navegador de PS5.

**Consecuencia:** No existe `new SharedArrayBuffer()`, ni `Atomics.wait()`, ni `Atomics.notify()`.
Todas las primitivas deben usar objetos `ArrayBuffer` normales. La temporización debe usar
bucles de delta con `performance.now()` o `Date.now()`.

## Motor: JavaScriptCore, no V8

El navegador de PS5 usa WebKit, que incluye JavaScriptCore (JSC) como motor JavaScript.
V8 es el motor de Google, usado en Chrome. La PS5 no tiene Chromium, no tiene V8, y no
tiene ninguna primitiva específica de V8.

Cualquier técnica de exploit descrita en términos de internos de V8 (Maps, TurboFan,
Liftoff, Sparkplug) no es aplicable en PS5.

## La Cadena de Explotación en Detalle

### Etapa 1: Type Confusion en JSC → R/W en Userland

Una vulnerabilidad de type confusion en JSC hace que el motor identifique mal el tipo de
un valor JavaScript almacenado en el heap. Esta es la misma *clase* de vulnerabilidad que
CVE-2021-30889 y sus variantes. La variante específica activa en FW 11.00 debe identificarse
analizando el binario de WebKit.

La type confusion se usa para implementar:
- `leakobj(obj)`: devuelve el puntero raw de 64 bits al cell JSC del objeto
- `fakeobj(addr)`: devuelve un objeto JS cuyo puntero interno está en `addr`

Con estos dos, la técnica estándar del "ArrayBuffer víctima" nos da:
- `read8(addr)`: leer 8 bytes de cualquier dirección en el proceso WebKit
- `write8(addr, val)`: escribir 8 bytes en cualquier dirección en el proceso WebKit

### Etapa 2: Leak de la Base de libkernel

La GOT (Global Offset Table) del binario WebKit contiene punteros a funciones importadas
de libkernel.sprx. Leemos uno de esos punteros con `read8()` y restamos el offset conocido
de esa función dentro de libkernel para obtener la dirección base de la biblioteca.

Esto es necesario porque ASLR aleatoriza las direcciones de carga en cada arranque.

### Etapa 3: Cadena ROP vía Pivote de Stack del Worker

Con la base de libkernel conocida, calculamos las direcciones absolutas de gadgets dentro
de libkernel. Luego:

1. Lanzamos un Web Worker (hilo JavaScript en segundo plano)
2. Localizamos su stack nativo usando punteros de estructura de hilo de JSC
3. Encontramos el slot de la dirección de retorno de un frame de stack conocido
4. Sobreescribimos ese slot con la dirección de un gadget de pivote de stack
5. Escribimos nuestro fake stack (la cadena ROP) en otra zona de memoria escribible
6. El gadget de pivote ejecuta, moviendo `$rsp` a nuestro fake stack
7. La CPU sigue nuestra cadena de gadgets

Esto bypasea el CFI de borde directo de Clang porque atacamos la dirección de retorno
(borde hacia atrás), no llamadas a vtable o punteros de función.

### Etapa 4: Escalada al Kernel

Vía ROP disparamos una **race condition umtx** (un use-after-free específico de FreeBSD
en los mutexes de la biblioteca de hilos de usuario). Esto nos da lectura/escritura de
kernel mediante el truco del pipe:

- Asignar dos descriptores de archivo pipe
- Usar el UAF para colocar un objeto de kernel controlado donde está el puntero del buffer interno del pipe
- Leer/escribir del fd del pipe ahora lee/escribe memoria arbitraria del kernel

Con R/W de kernel:
- Encontramos nuestra estructura `proc` en la lista de procesos del kernel
- Leemos `proc→p_ucred` para obtener nuestra estructura de credenciales
- Sobreescribimos `ucred→cr_uid` a 0 (root)
- Sobreescribimos `ucred→cr_prison` para apuntar a `prison0` (escape de jail)
- Deshabilitamos `kern.securelevel` y las comprobaciones de integridad del kernel SCEP

### Etapa 5: Cargador ELF Persistente

Usamos ptrace (ahora permitido porque tenemos root y escapamos de la jail) para inyectar
un pequeño stub de shellcode en `SceRedisServer` — un proceso en segundo plano que
permanece activo tras reinicios del navegador y modo reposo. El stub configura un
listener TCP en el puerto 9021.

Cuando el PC host se conecta y envía un binario ELF, el cargador lo parsea, mapea los
segmentos en memoria, aplica relocalizaciones y llama al punto de entrada en un proceso
hijo fork.
