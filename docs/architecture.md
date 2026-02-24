# Arquitectura técnica — PS5 Toolkit 11.xx

## 1. Contexto del sistema

La PS5 corre un sistema operativo derivado de FreeBSD 11, llamado **Orbis OS**.
El hardware es AMD x86-64 (Zen 2). Las protecciones relevantes son:

| Protección | Scope | Descripción |
|-----------|-------|-------------|
| SMEP | Kernel | Impide ejecutar código de usuario desde el kernel |
| SMAP | Kernel | Complementa SMEP (lectura/escritura) |
| XOM (R^X) | User+Kernel | Las páginas ejecutables no son legibles |
| Clang-CFI | User+Kernel | Valida forward-edge en llamadas virtuales e indirectas |
| Hypervisor | Ambos | Contenedor de apps; restringe llamadas de sistema |

## 2. Cadena de explotación

```
WebKit Bug (heap corruption)
       │
       ▼
Primitivas userland (arb. read/write en el proceso WebKit)
       │
       ▼
Leak de libkernel base → construcción de cadena ROP
       │
       ▼
Web Worker ROP (backward-edge attack, bypasa CFI forward-edge)
       │
       ▼
Syscalls: socket/connect/mmap/... via ROP chain
       │
       ▼
Kernel exploit (umtx race / pipe UAF)
       │
       ▼
kbase leak + kernel R/W (via pipe trick)
       │
       ▼
Escape del Jail (allproc → ucred → cr_prison = prison0)
       │
       ▼
Root (ucred uid/ruid/svuid = 0)
       │
       ▼
Deshabilitar SCEP / kern.securelevel = -1
       │
       ▼
ELF loader instalado en SceRedisServer (vía ptrace)
       │
       ▼
Puerto 9021 activo — listo para payloads arbitrarios
```

## 3. El bug de WebKit

### CVE-2021-30889 (variante PS5 FW 11.x)

El bug original afecta al motor JavaScriptCore en su manejo de `FontFace`.
La explotación en PS5 FW 11.x usa una variante del mismo tipo de confusión
de tipos que permite obtener `leakobj()` y `fakeobj()`.

La técnica concreta para FW 11.00 requiere:
- Analizar el binario WebKit del firmware con Ghidra usando el código fuente
  de Sony (disponible en `neonmodder123/PS5-WebKit-11.x`)
- Identificar qué versión del bug (o una nueva variante) sigue presente
- Adaptar los offsets del heap spray

### Por qué funciona el bypass de CFI

El Clang-CFI de PS5 protege **forward-edge** (llamadas virtuales, punteros a función).
**No implementa shadow stack** (backward-edge). Por lo tanto:

- ✗ No podemos sobreescribir un vtable pointer → CFI lo detecta
- ✓ Sí podemos sobreescribir una **dirección de retorno** en el stack

Los Web Workers tienen un stack separado y determinístico. El offset del
return address dentro del stack del handler `onmessage` es fijo para cada
build del firmware.

## 4. ROP Chain

### 4.1 Obtención de libkBase

La base de libkernel se calcula leyendo un puntero desde la GOT de WebKit
que apunta a una función de libkernel, y restando el offset conocido
de esa función en el módulo.

### 4.2 Gadgets disponibles

XOM impide leer páginas ejecutables. Sin embargo, el módulo libkernel.sprx
tiene una sección de datos que sí es legible y contiene punteros a gadgets.
Esto nos permite construir la cadena sin leer directamente código.

Los gadgets usados en la cadena principal son:
- `pop rdi/rsi/rdx/rcx/r8/r9 ; ret` — seteo de argumentos
- `pop rsp ; ret` — pivot de stack
- `ret` — padding/align

### 4.3 Comunicación ROP → JavaScript

Para que los resultados de las syscalls en ROP lleguen de vuelta al JS,
usamos un `SharedArrayBuffer` como zona de intercambio. La cadena ROP
escribe el valor de retorno (RAX) en una dirección conocida del SAB,
y el JS lo lee con `Atomics.load()`.

## 5. Kernel exploit (FW 11.00)

Para FW 11.00, la técnica documentada es una variante del **umtx race condition**:

1. Spray de objetos `umutex` en el kernel heap
2. Race condition en `umtx_op(UMTX_OP_WAIT_UINT)` → UAF
3. Reutilización del objeto liberado como `pipe` buffer
4. Primitive kread8: `write(pipe_write_fd, target_addr, 8)` + `read(pipe_read_fd, buf, 8)`
5. Primitive kwrite8: manipular struct del pipe para que apunte a target_addr

**Nota**: Los offsets exactos del kernel heap para FW 11.00 deben determinarse
mediante análisis del firmware. Los valores en `offsets_1100.js` son
aproximaciones que requieren verificación con dumps reales.

## 6. Bootstrap via ptrace

La técnica de bootstrap en `SceRedisServer`:

1. `PT_ATTACH` al proceso (posible porque somos root post-jailbreak)
2. `PT_GETREGS` — guardar estado de registros
3. Localizar región RWX en el espacio de memoria del proceso
4. `PT_WRITE_D` — inyectar shellcode en esa región
5. `PT_SETREGS` — redirigir RIP al shellcode
6. `PT_CONTINUE` — el proceso ejecuta el shellcode
7. `PT_DETACH` — SceRedisServer continúa con el loader instalado

El shellcode instala un thread que hace `listen()` en el puerto 9021,
luego llama al RIP original para que SceRedisServer continúe normal.

## 7. Protocolo del ELF loader (puerto 9021)

```
Cliente (PC)                    PS5 (ELF loader)
    │                                    │
    │ ── [4 bytes LE: tamaño] ─────────► │
    │ ── [payload bytes...] ───────────► │
    │                                    │
    │                             fork() → hijo ejecuta payload
    │                             padre acepta siguiente conexión
    │
```

El loader detecta el tipo del payload por su magic y lo ejecuta
en un proceso hijo independiente. Si el hijo crashea, el loader
sigue funcionando.

## 8. Soporte de tipos de payload

### ELF64 estático (ET_EXEC)
Cargado en la dirección exacta definida en `e_entry`. No requiere relocations.

### ELF64 PIE (ET_DYN)
El loader aplica `R_X86_64_RELATIVE` relocations. Símbolos externos NO
se resuelven (sin dynamic linker). El payload debe resolver sus propias
importaciones usando la base de libkernel que el loader pasa como argumento.

### SELF (.self / .sprx)
El loader extrae el ELF embebido después de la cabecera SELF y lo trata
como un ELF normal. El descifrado de segmentos cifrados requiere acceso
a la clave del firmware — sólo funciona con SELFs sin cifrar o parcialmente.

### RAW (.bin)
Se copia a memoria RWX y se ejecuta desde el byte 0. No hay relocations.
Útil para shellcodes simples.
