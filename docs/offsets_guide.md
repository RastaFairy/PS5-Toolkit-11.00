# Offsets Guide — Finding FW 11.00 Values with Ghidra
# Guía de Offsets — Encontrar Valores de FW 11.00 con Ghidra

> [English](#english) · [Español](#español)

---

<a name="english"></a>
# ENGLISH

## Prerequisites

- Ghidra 11.x (free, from NSA/GitHub)
- ps5-ghidra-scripts (community scripts that add PS5 binary support)
- A dump of the FW 11.00 WebKit binary (`WebKit.sprx` / renderer process)
- A dump of FW 11.00 `libkernel_web.sprx`

> **How to obtain dumps:** You need a PS5 on FW 11.00 or earlier with a currently
> working kernel exploit (e.g., from SpecterDev's repository for older firmware).
> Dumping is outside the scope of this guide.

---

## Finding WEBKIT_GOT_LIBKERNEL

This offset tells us where in WebKit's binary a pointer to a libkernel function is stored.

**In Ghidra:**

1. Open `WebKit.sprx` (or the renderer binary). Apply the PS5 loader script.
2. Open **Symbol Tree → Imports**. Look for imports from `libkernel_web.sprx`.
3. Find a commonly imported function: `pthread_create`, `mmap`, `munmap`, or `write`.
4. Right-click the import symbol → **References → Show References to**.
5. Find the GOT entry (in the `.got` section) — it will have a data cross-reference.
6. Note the address of that GOT slot. Subtract the binary's load address (usually starts
   at `0x00000000` in Ghidra's default analysis) to get the offset.
7. Record this as `WEBKIT_GOT_LIBKERNEL` plus which function it points to, so you can
   compute: `libkernel_base = *WEBKIT_GOT_LIBKERNEL - LIBKERNEL_FUNC_OFFSET`

---

## Finding ROP Gadgets in libkernel_web.sprx

**Method 1: ROPgadget (command line)**
```bash
# Extract the binary from your dump first
ROPgadget --binary libkernel_web.sprx --rop --depth 3 | grep -E "pop rdi|pop rsi|syscall"
```

**Method 2: Ghidra Search**
1. Open `libkernel_web.sprx`
2. **Search → For Instruction Patterns**
3. Search for byte sequence: `5F C3` (pop rdi; ret on x86-64)
4. For each result: note the address, subtract the binary's base address → that's your offset

**Common gadget byte patterns (x86-64):**
| Gadget | Bytes |
|--------|-------|
| `pop rdi; ret` | `5F C3` |
| `pop rsi; ret` | `5E C3` |
| `pop rdx; ret` | `5A C3` |
| `pop rcx; ret` | `59 C3` |
| `pop r8; ret`  | `41 58 C3` |
| `pop r9; ret`  | `41 59 C3` |
| `pop rax; ret` | `58 C3` |
| `syscall; ret` | `0F 05 C3` |
| `ret`          | `C3` |

For the stack pivot, search for `xchg rsp,` sequences:
```
48 94 C3   (xchg rsp, rax; ret)
48 87 E3   (xchg rsp, rbx; ...)
```
Pick one that lands in a predictable state.

---

## Finding JSC ArrayBuffer Offsets

1. Open the WebKit binary in Ghidra
2. Search for the `JSArrayBuffer::create` function (search by name if symbols are present,
   or by pattern if stripped)
3. Examine how it initialises the object — the field write sequence reveals the struct layout
4. Alternatively, search for the string `"ArrayBuffer"` — it appears near the structure
   definition in JSC's type system

The backing store offset (currently `0x10` in our scaffold) is the most critical one.
Verify it by finding where `JSArrayBuffer` sets its `m_impl` or equivalent pointer field.

---

## Verifying Kernel Offsets

Kernel offsets are best verified using existing open-source PS5 kernel dumps/analyses:

- SpecterDev's kernel exploit releases include offset tables for each supported firmware
- The ps5-kernel-offsets community repository tracks per-firmware offsets
- Cross-reference with FreeBSD 9.0 source (PS4/PS5 Orbis OS is based on FreeBSD)

For FW 11.00 specifically, check whether any public kernel exploit already documents
the `proc`, `ucred`, and `prison` struct offsets.

---

<a name="español"></a>
# ESPAÑOL

## Requisitos

- Ghidra 11.x (gratuito, de NSA/GitHub)
- ps5-ghidra-scripts (scripts de la comunidad que añaden soporte de binarios PS5)
- Un dump del binario WebKit de FW 11.00 (`WebKit.sprx` / proceso renderizador)
- Un dump de `libkernel_web.sprx` de FW 11.00

> **Cómo obtener dumps:** Necesitas una PS5 en FW 11.00 o anterior con un exploit de kernel
> actualmente funcional (p.ej., del repositorio de SpecterDev para firmware anterior).
> El proceso de dump está fuera del alcance de esta guía.

---

## Encontrar WEBKIT_GOT_LIBKERNEL

Este offset indica dónde en el binario de WebKit está almacenado un puntero a una función de libkernel.

**En Ghidra:**

1. Abre `WebKit.sprx`. Aplica el script del cargador PS5.
2. Abre **Symbol Tree → Imports**. Busca importaciones de `libkernel_web.sprx`.
3. Encuentra una función importada habitual: `pthread_create`, `mmap`, `munmap`, o `write`.
4. Click derecho en el símbolo de importación → **References → Show References to**.
5. Encuentra la entrada de la GOT (en la sección `.got`) — tendrá una referencia cruzada de datos.
6. Anota la dirección de ese slot de la GOT. Resta la dirección de carga del binario para obtener el offset.
7. Registra esto como `WEBKIT_GOT_LIBKERNEL` más qué función apunta, para poder calcular:
   `base_libkernel = *WEBKIT_GOT_LIBKERNEL - LIBKERNEL_FUNC_OFFSET`

---

## Encontrar Gadgets ROP en libkernel_web.sprx

**Método 1: ROPgadget (línea de comandos)**
```bash
ROPgadget --binary libkernel_web.sprx --rop --depth 3 | grep -E "pop rdi|pop rsi|syscall"
```

**Método 2: Búsqueda en Ghidra**
1. Abre `libkernel_web.sprx`
2. **Search → For Instruction Patterns**
3. Busca la secuencia de bytes: `5F C3` (pop rdi; ret en x86-64)
4. Para cada resultado: anota la dirección, resta la dirección base del binario → ese es tu offset

**Patrones de bytes de gadgets habituales (x86-64):**
| Gadget | Bytes |
|--------|-------|
| `pop rdi; ret` | `5F C3` |
| `pop rsi; ret` | `5E C3` |
| `pop rdx; ret` | `5A C3` |
| `pop rcx; ret` | `59 C3` |
| `pop r8; ret`  | `41 58 C3` |
| `pop r9; ret`  | `41 59 C3` |
| `pop rax; ret` | `58 C3` |
| `syscall; ret` | `0F 05 C3` |
| `ret`          | `C3` |

Para el pivote de stack, busca secuencias `xchg rsp,`:
```
48 94 C3   (xchg rsp, rax; ret)
```

---

## Verificar Offsets de Kernel

Los offsets de kernel se verifican mejor usando análisis/dumps de kernel de PS5 de código abierto existentes:

- Los lanzamientos de exploits de kernel de SpecterDev incluyen tablas de offsets para cada firmware
- El repositorio de la comunidad ps5-kernel-offsets rastrea offsets por firmware
- Haz referencias cruzadas con el código fuente de FreeBSD 9.0 (Orbis OS está basado en FreeBSD)

Para FW 11.00 específicamente, comprueba si algún exploit de kernel público ya documenta
los offsets de las estructuras `proc`, `ucred` y `prison`.
