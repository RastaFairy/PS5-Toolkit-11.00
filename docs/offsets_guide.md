# Guía de offsets — Cómo encontrar offsets para otros firmwares

Esta guía explica el proceso de encontrar y actualizar los offsets
necesarios cuando el toolkit se porta a un firmware diferente.

## Herramientas necesarias

- **Ghidra** (con el script PS5 de Specter para importar SPRX/PRX)
- **ps5-payload-sdk** para compilar herramientas de diagnóstico
- **radare2** o **IDA Pro** (opcional)
- Dump del firmware objetivo (extracción del disco de la PS5)

## 1. Obtener el dump del firmware

El firmware puede extraerse del disco de actualización `.PUP` con herramientas
como `pup_unpacker`. Los módulos relevantes están en:

```
/system/lib/libkernel.sprx
/system/priv/lib/libSceWebKit2.sprx
```

## 2. Offsets de libkernel

### Thread list (`OFFSETS.libkernel.thread_list`)

En Ghidra, busca la función `pthread_create`. Dentro de ella, hay una
instrucción que inserta el nuevo thread en una lista enlazada global.
El puntero a esa lista es `thread_list`.

También puedes buscarlo con el pattern `LIST_INSERT_HEAD` en el código
desensamblado.

### Offsets en `pthread_t` (`pthread_next`, `pthread_stack_addr`, etc.)

La estructura `pthread` de FreeBSD es pública. Sin embargo, los offsets
pueden cambiar entre versiones de Orbis. Para verificarlos:

1. Compila un payload que haga `pthread_create()` y duerma.
2. Adjúntate con ptrace y lee la estructura del thread.
3. Compara con los offsets esperados de la estructura `pthread_t` de FreeBSD 11.

### Gadgets ROP

Los gadgets se encuentran en las secciones ejecutables de libkernel.
En Ghidra, usa `Search → For Instruction Patterns`:

```
pop RDI ; RET               → pop_rdi_ret
pop RSP ; RET               → pop_rsp_ret
mov QWORD PTR [RDI], RAX   → escribir RAX en memoria
syscall ; RET               → entrada directa a syscall
```

Herramienta automatizada: `ROPgadget --binary libkernel.sprx --rop`

### Syscall stubs

En libkernel, cada syscall tiene un stub que contiene la instrucción
`syscall`. Busca la función por nombre (ej. `socket`, `mmap`) y anota
el offset desde el inicio del módulo.

## 3. Offsets de WebKit

### `worker_ret_offset`

Este es el offset más crítico y más difícil de encontrar.

**Método 1 (empírico):**
1. Crea un Web Worker con un handler `onmessage` que haga un sleep largo.
2. Adjúntate al proceso WebKit con ptrace.
3. Encuentra el stack del worker (tamaño = 0x80000).
4. Examina el stack cuando el handler está a punto de retornar.
5. Busca la dirección de retorno del handler `onmessage`.

**Método 2 (análisis estático):**
1. En Ghidra, busca la función `Worker::didReceiveMessageOnWorkerGlobalScope`.
2. Analiza el frame del stack de esa función.
3. El offset del return address se puede calcular del prologue.

### `gadget_pop_rsp_ret` en WebKit

Busca en la sección ejecutable de libSceWebKit2.sprx el patrón:
`5C 5C C3` (pop rsp ; ret en x64, puede variar).

## 4. Offsets del kernel

Los offsets del kernel son los más difíciles porque requieren un dump del
kernel (disponible sólo post-jailbreak de otra consola o de firmware similar).

### Proceso general:
1. Dumpea el kernel de una consola ya jailbroken con firmware cercano.
2. En Ghidra, importa el kernel (script de PS5 requerido).
3. Busca los símbolos por sus patrones de código:
   - `allproc`: lista enlazada de todos los procesos, accesible vía `sysctl kern.proc`
   - `kern.securelevel`: variable global patcheable
   - CPU info structs: se encuentran buscando referencias a MSR reads de Zen 2

### Verificación de offsets del kernel

Una vez jailbroken, puedes verificar offsets con un payload que:
1. Lea el kbase (ya conocido tras el exploit).
2. Lea la dirección de `allproc` en `kbase + offset_candidato`.
3. Verifique que sea un puntero válido al proceso actual.

## 5. Proceso de actualización de offsets_XXXX.js

1. Crea una copia de `offsets_1100.js` con el nuevo nombre de FW.
2. Actualiza cada offset con los valores encontrados.
3. En `exploit/index.html`, cambia el `<script src>` al nuevo archivo.
4. Prueba con un exploit que sólo haga el leak de libkBase y muestre el valor.
5. Verifica con el payload de hello que el ROP funciona.
6. Avanza fase por fase.

## 6. Herramienta de verificación

El toolkit incluye un modo de diagnóstico que se puede activar en el exploit:

```javascript
// En exploit/index.html, añadir antes del botón:
const DEBUG_MODE = true;  // Solo hace el leak, no escalada

// Si DEBUG_MODE, solo ejecutar fases 1-2 y mostrar:
console.log("libkBase:", libkBase.toString());
console.log("workerStack:", workerStack.toString());
```

Esto permite verificar que los offsets básicos son correctos antes de
intentar la escalada completa.
