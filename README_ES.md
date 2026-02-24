# PS5 Toolkit 11.xx

> **Firmware:** 11.00 · **Bug:** CVE-2023-41993 (DFG JIT type confusion) · **Plataforma:** FreeBSD/AMD64

Toolkit de investigación de seguridad para PS5 FW 11.00. Cubre la cadena de explotación completa desde el bug de WebKit hasta la ejecución de payloads ELF arbitrarios, con herramientas de análisis automático de binarios del firmware.

```
WebKit bug → addrof/fakeobj → R/W arbitrario → ROP chain → kernel jailbreak → ELF loader
```

---

## Estado del proyecto

| Componente | Estado | Notas |
|---|:---:|---|
| `webkit_bug.js` — CVE-2023-41993 | ✅ | DFG JIT type confusion, 4 fases, 3 reintentos automáticos |
| `leakLibKernelBase()` | ✅ | GOT read vía vtable de RegExpObject |
| `primitives.js` — R/W arbitrario | ✅ | Fake Float64Array, vector overwrite |
| `rop.js` — Worker stack pivot | ✅ | `thread_list` → Worker → pivot |
| `kernel.js` — jailbreak + root | ✅ | `allproc` → `ucred` → uid=0 + prison0 |
| `loader.js` + `elfldr/` | ✅ | ptrace en SceRedisServer, TCP :9021 |
| `tools/` — análisis de binarios | ✅ | 7 scripts Python, sin deps externas |
| `offsets_1100.js` | ⚠ | Ejecutar `gen_offsets.py` con los `.elf` reales para confirmar |

**Único paso manual:** obtener los binarios del FW 11.00 y ejecutar `tools/gen_offsets.py`.
Todo lo demás está implementado y conectado.

---

## Tabla de contenidos

1. [Requisitos](#requisitos)
2. [Inicio rápido](#inicio-rápido)
3. [Arquitectura](#arquitectura)
4. [El bug — CVE-2023-41993](#el-bug--cve-2023-41993)
5. [Cadena de explotación](#cadena-de-explotación)
6. [Estructura del proyecto](#estructura-del-proyecto)
7. [Herramientas de análisis](#herramientas-de-análisis)
8. [Compilar el ELF Loader](#compilar-el-elf-loader)
9. [Enviar payloads](#enviar-payloads)
10. [Verificar offsets](#verificar-offsets)
11. [Ajuste en runtime](#ajuste-en-runtime)
12. [Preguntas frecuentes](#preguntas-frecuentes)
13. [Créditos](#créditos)

---

## Requisitos

### PC / host

- Python 3.8+
- `binutils` (readelf, objdump, nm, strings) para las herramientas de análisis
- Red local con la PS5

```bash
# Instalación automática (detecta Debian/Ubuntu/macOS/Arch):
bash setup.sh

# Manual:
sudo apt install python3 binutils   # Debian/Ubuntu
brew install binutils               # macOS
```

### PS5

- Firmware **11.00** exactamente (no 10.xx, no 11.01+)
- Navegador de PS5 con conexión a la red local

---

## Inicio rápido

```bash
# 1. Configurar
git clone https://github.com/RastaFairy/PS5-Toolkit-11.00
cd PS5-Toolkit-11.00
bash setup.sh          # detecta IP, parchea HOST_IP en los fuentes

# 2. Levantar el servidor HTTP
python3 host/server.py --port 8000

# 3. En la PS5: navegador → http://IP_DEL_PC:8000/exploit/index.html

# 4. Logs en tiempo real (terminal separada)
python3 tools/listen_log.py

# 5. Enviar payloads una vez el loader esté activo
python3 tools/send_payload.py --host PS5_IP --file mi_payload.elf
```

---

## Arquitectura

```
PC (host)                                  PS5 (FW 11.00)
─────────────────────────────────────────────────────────
host/server.py ────── HTTP :8000 ──────► WebKit browser
                                                │
                                       exploit/index.html
                                                │
                                    ┌───────────▼───────────┐
                                    │  webkit_bug.js         │
                                    │  CVE-2023-41993        │
                                    │  → leakobj / fakeobj   │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  primitives.js         │
                                    │  → read8 / write8      │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  rop.js                │
                                    │  Worker stack pivot    │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  kernel.js             │
                                    │  allproc → ucred → 0   │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  loader.js             │
                                    │  ptrace → SceRedis     │
                                    └───────────┬───────────┘
                                                │
send_payload.py ───── TCP :9021 ───────────────►│
listen_log.py   ◄──── UDP :9998 ────────────────┘
```

| Puerto | Proto | Dirección | Uso |
|--------|-------|-----------|-----|
| 8000 | HTTP | PC → PS5 | Sirve `exploit/` al navegador |
| 9021 | TCP | PC → PS5 | Envío de payloads al ELF loader |
| 9998 | UDP | PS5 → PC | Logs del exploit en tiempo real |

---

## El bug — CVE-2023-41993

**Tipo:** Confusión de tipos en el compilador DFG de JavaScriptCore
**Afecta:** WebKit < iOS 17.0.3 / Safari 17.0.1 → PS5 FW 10.xx–11.02 (no parcheado)
**Ref:** [bugs.webkit.org/260664](https://bugs.webkit.org/show_bug.cgi?id=260664)

El compilador DFG mantiene un valor abstracto por cada nodo del grafo IR. Cuando ha visto una propiedad contener solo doubles, genera código que la lee directamente sin verificar el tipo (especulación). En rutas con `GetByOffset/PutByOffset` sobre objetos con estructura transitoria, `clobberize()` no marca esos reads como heap-reads. El compilador hoistea la lectura por encima de efectos secundarios que cambian el tipo del slot.

**Resultado:**

```
Warmup (100 iter)  →  confused.val = double    [JIT compila como double read]
Trigger            →  confused.val = JSObject*  [rompe la invariante]
jitCompiledRead()  →  devuelve JSObject* como double  →  leakobj(obj) ✓
jitCompiledWrite() →  escribe addr como double        →  fakeobj(addr) ✓
```

---

## Cadena de explotación

### Fase 1 — Bug WebKit → primitivas base

1. **Heap spray** — 0x800 `ArrayBuffer` de 64 bytes posicionan el bump pointer del allocator
2. **Objetos de confusión** — par `confused/container` con 3 transiciones de estructura controladas
3. **Warmup JIT** — 100 iteraciones graban la especulación de tipo en el código compilado del DFG
4. **Trigger** — JSObject\* en slot double → `leakobj` + `fakeobj`; hasta 3 reintentos automáticos

### Fase 2 — Primitivas de memoria completas

`fakeobj` construye un `Float64Array` falso. Sobreescribiendo su campo `vector` (+0x10) apuntamos la vista a cualquier dirección. API: `addrof`, `read8`, `write8`, `read4`, `write4`, `readBytes`, `writeBytes`, `readCString`.

### Fase 3 — Leak de libkBase y stack pivot

1. `addrof(new RegExp('a'))` → dirección del `RegExpObject`
2. Lee `JSRegExp*` interno (slot +0x10) → lee vtable C++ → resta `vtable_jsregexp_offset` → `webkit_base`
3. Lee `GOT[pthread_create]` en `webkit_base + got_pthread_create` → resta offset en libkernel → `libkBase`
4. Itera `thread_list` buscando el Web Worker por `stack_size == 0x80000`
5. Sobreescribe `worker_ret_offset` → pivot al ROP chain

### Fase 4 — Jailbreak del kernel

1. Leak de `kbase` via syscall `umtx_op`
2. Itera `allproc` para localizar el proceso WebKit por PID
3. Modifica `p_ucred`: `cr_uid = 0`, `cr_ruid = 0`, `cr_svuid = 0`, `cr_prison = &prison0`

### Fase 5 — ELF Loader persistente

1. Descarga `elfldr.elf` del servidor HTTP
2. Inyecta en `SceRedisServer` via ptrace (shellcode + detach)
3. El loader escucha en TCP :9021 mientras Redis siga corriendo

---

## Estructura del proyecto

```
PS5-Toolkit-11.00/
│
├── exploit/                        Exploit WebKit (servido como web)
│   ├── index.html                  UI de 5 fases con progreso y logs
│   └── js/
│       ├── int64.js                Aritmética 64-bit, NaN-boxing de JSC
│       ├── offsets_1100.js         Todos los offsets del firmware
│       ├── webkit_bug.js           CVE-2023-41993 + leakLibKernelBase()
│       ├── primitives.js           Clase Primitives: addrof/read8/write8
│       ├── rop.js                  ROPChain builder + Worker pivot
│       ├── rop_worker.js           Web Worker víctima (stack pivot target)
│       ├── kernel.js               KernelExploit: kbase leak + jailbreak
│       └── loader.js               PayloadLoader: ptrace + elfldr
│
├── elfldr/                         ELF Loader nativo en C
│   ├── elfldr.c / elfldr.h         Parser ELF64 + relocations
│   ├── main.c                      TCP :9021, bucle de recepción
│   ├── pt.c / pt.h                 Bootstrap via ptrace en SceRedisServer
│   └── Makefile
│
├── payload/example/                Payload de ejemplo
│   ├── hello.c                     Envía mensajes UDP al host
│   └── Makefile
│
├── host/
│   └── server.py                   HTTP con COOP/COEP/CORS para SharedArrayBuffer
│
├── tools/                          Análisis automático de binarios del firmware
│   ├── self2elf.py                 SELF/SPRX → ELF (individual o batch)
│   ├── analyze_libkernel.py        Gadgets ROP, símbolos, pthread offsets
│   ├── analyze_webkit.py           GOT entries para leak de libkBase
│   ├── analyze_kernel.py           allproc, ucred, prison0
│   ├── gen_offsets.py              Orquestador → offsets_1100.js completo
│   ├── send_payload.py             Envía payloads al ELF loader (TCP :9021)
│   ├── listen_log.py               Receptor UDP de logs con colores
│   └── ANALYSIS_README.md
│
├── docs/
│   ├── architecture.md             Análisis técnico de la cadena
│   └── offsets_guide.md            Guía de extracción y verificación de offsets
│
├── .github/ISSUE_TEMPLATE/
│   ├── bug_report.md
│   └── offsets.md
│
├── setup.sh                        Instalador automático multi-OS
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE                         GPLv3
```

---

## Herramientas de análisis

Cuando tengas los binarios del firmware, un solo comando genera el `offsets_1100.js` definitivo:

```bash
# Convertir SPRX → ELF (si aún tienes los .sprx)
python3 tools/self2elf.py libkernel.sprx libkernel.elf
python3 tools/self2elf.py WebKit.sprx    WebKit.elf
# o en batch:
python3 tools/self2elf.py --dir /ruta/priv/lib/ --out ./elfs/

# Generar offsets_1100.js completo
python3 tools/gen_offsets.py \
    --libkernel libkernel.elf \
    --webkit    WebKit.elf \
    --kernel    mini-syscore.elf \
    --out       exploit/js/offsets_1100.js
```

Scripts individuales para análisis más detallado:

```bash
python3 tools/analyze_libkernel.py libkernel.elf --verbose
python3 tools/analyze_webkit.py    WebKit.elf --libkernel libkernel.elf
python3 tools/analyze_kernel.py    mini-syscore.elf
```

Sin dependencias pip — solo `objdump`, `readelf`, `nm`, `strings` (binutils estándar).

---

## Compilar el ELF Loader

```bash
bash setup.sh --sdk          # clona ps5-payload-sdk en /opt/ps5-payload-sdk

cd elfldr/ && make           # compila elfldr.elf
cd payload/example/ && make  # compila hello.elf de ejemplo
```

---

## Enviar payloads

```bash
python3 tools/send_payload.py --host 192.168.1.50 --file mi_payload.elf
python3 tools/send_payload.py --host 192.168.1.50 --file shellcode.bin
```

El loader detecta el tipo por magic bytes:

| Magic | Tipo | Procesamiento |
|---|---|---|
| `\x7fELF` | ELF64 | PHDRs, mmap, relocations, call `_init` + entry |
| `\x4fSCE` | SELF | Desenvoltura del header + carga como ELF |
| Cualquier otro | RAW | Mapeo directo en memoria ejecutable |

---

## Verificar offsets

Los valores marcados `// ⚠ VERIFICAR` en `offsets_1100.js` son estimaciones. Pueden funcionar o causar crashes silenciosos. Para confirmarlos:

```bash
python3 tools/gen_offsets.py --libkernel libkernel.elf --webkit WebKit.elf
```

El único offset que siempre requiere verificación empírica en hardware es `worker_ret_offset` — ver `docs/offsets_guide.md`.

---

## Ajuste en runtime

Desde la consola de WebInspector de la PS5, sin recargar:

```javascript
// Ver todos los offsets actuales
console.log(JSON.stringify(OFFSETS, null, 2))

// Modificar un offset
patchOffset('webkit.got_pthread_create', 0x9B3C820)
patchOffset('webkit.worker_ret_offset',  0x7FB88)
patchOffset('libkernel.pthread_create',  0x9CBB0)
```

---

## Preguntas frecuentes

**El exploit falla en Fase 1**
El heap spray es no determinista. Recarga la página. Si falla sistemáticamente, aumenta `JIT_WARMUP_ITERS` o `SPRAY_COUNT` en `webkit_bug.js`.

**El navegador crashea en Fase 3**
`worker_ret_offset` probablemente es incorrecto. Usa `patchOffset` con valores ±0x8, ±0x10 y reitera.

**¿Los offsets ⚠ VERIFICAR son usables?**
Son estimaciones basadas en análisis estático y FW anteriores. El exploit puede funcionar o fallar silenciosamente. Ejecuta `gen_offsets.py` con los binarios reales para valores exactos.

**¿El loader sobrevive al rest mode?**
Sí, mientras `SceRedisServer` siga corriendo. Un reinicio completo requiere re-ejecutar el exploit.

**¿Por qué CVE-2023-41993 y no el bug de FW 4.03?**
CVE-2021-30889 (ChendoChap, FW 4.03) está parcheado en FW 11.xx. CVE-2023-41993 es el bug activo en el rango 10.xx–11.02.

**¿Funciona en FW 11.01 / 11.02?**
CVE-2023-41993 no fue parcheado hasta después de 11.02. Los offsets pueden diferir — ejecutar `gen_offsets.py` con los binarios de esa versión.

**Tengo los `.elf` del firmware, ¿qué hago?**
Subir los archivos al chat. Los scripts de análisis se ejecutarán directamente sobre ellos y generarán `offsets_1100.js` con valores verificados.

---

## Créditos

- **ChendoChap & Znullptr** — [PS5-Webkit-Execution](https://github.com/ChendoChap/PS5-Webkit-Execution) — estructura de primitivas y técnica de Worker pivot
- **john-tornblom** — [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr), [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) — ELF loader y SDK
- **SpecterDev** — PSFree, PS5-IPV6-Kernel-Exploit — referencia del jailbreak del kernel
- **sleirsgoevy** — [ps4jb2](https://github.com/sleirsgoevy/ps4jb2) — técnica del GOT leak para libkernel
- **flatz** — ps5_tools — herramientas de análisis del formato SELF de PS5
- **po6ix** — PoC inicial de CVE-2023-41993

---

> **Aviso legal:** Software exclusivamente para investigación de seguridad en hardware de tu propiedad.
> No está permitido su uso para piratería u otras actividades ilegales. Ver [LICENSE](LICENSE) (GPLv3).
