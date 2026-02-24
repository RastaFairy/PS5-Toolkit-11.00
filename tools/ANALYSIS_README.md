# PS5 Analysis Tools

Scripts de análisis automático para extraer offsets de los binarios del FW 11.00.
Ejecutar cuando tengas acceso a los archivos `.elf` del firmware.

## Flujo completo (3 pasos)

```
libkernel.sprx  ──┐
WebKit.sprx     ──┤── self2elf.py ──► .elf  ──► gen_offsets.py ──► offsets_1100.js
mini-syscore.elf──┘
```

---

## Paso 1 — Convertir SPRX → ELF

```bash
# Un archivo
python3 self2elf.py libkernel.sprx  libkernel.elf
python3 self2elf.py WebKit.sprx     WebKit.elf

# Directorio entero (convierte todos los .sprx que encuentre)
python3 self2elf.py --dir /ruta/priv/lib/ --out ./elfs/

# Verificar si un archivo es SELF o ya es ELF
python3 self2elf.py --check WebKit.sprx
```

---

## Paso 2 — Generar offsets_1100.js (script maestro)

```bash
# Mínimo (solo libkernel):
python3 gen_offsets.py --libkernel libkernel.elf

# Recomendado (los tres):
python3 gen_offsets.py \
    --libkernel libkernel.elf \
    --webkit    WebKit.elf \
    --kernel    mini-syscore.elf

# Con conversión automática desde SPRX:
python3 gen_offsets.py \
    --libkernel-sprx libkernel.sprx \
    --webkit-sprx    WebKit.sprx

# Especificar destino:
python3 gen_offsets.py \
    --libkernel libkernel.elf \
    --webkit WebKit.elf \
    --out ../exploit/js/offsets_1100.js
```

El script genera:
- `offsets_1100.js` — listo para copiar al proyecto
- `/tmp/ps5_analysis/*.json` — datos en bruto de cada análisis

---

## Scripts individuales (para análisis más detallado)

```bash
# Solo libkernel (gadgets, símbolos, pthread offsets)
python3 analyze_libkernel.py libkernel.elf --verbose

# Solo WebKit (GOT entries para leakLibKernelBase)
python3 analyze_webkit.py WebKit.elf --libkernel libkernel.elf --verbose

# Solo kernel (allproc, ucred, prison0)
python3 analyze_kernel.py mini-syscore.elf --verbose

# Guardar resultado en JSON para procesarlo luego
python3 analyze_libkernel.py libkernel.elf --json libkernel_offsets.json
```

---

## Cuando tengas los archivos, súbelos aquí

Si abres una nueva conversación con Claude y subes los `.elf`, Claude puede:
1. Ejecutar estos scripts directamente sobre los archivos
2. Analizar los resultados y detectar valores incorrectos
3. Generar el `offsets_1100.js` final verificado
4. Sugerir correcciones si algún offset parece fuera de rango

**Archivos imprescindibles:**
- `libkernel.elf` → gadgets ROP + símbolos para el leak
- `WebKit.elf` → GOT offset para leakLibKernelBase()

**Archivos opcionales pero útiles:**
- `mini-syscore.elf` → offsets de allproc/ucred para el jailbreak

---

## Valores que siempre requieren verificación en hardware

Estos valores NO pueden determinarse solo con análisis estático:

| Campo | Por qué necesita hardware |
|-------|--------------------------|
| `worker_ret_offset` | Depende del frame stack en runtime del handler onmessage |
| Offsets de struct proc | Pueden variar entre compilaciones del mismo FW |
| Offsets de struct ucred | Idem |
| `thread_list` | Puede estar en sección de datos no exportada |

Para verificar `worker_ret_offset` empíricamente:
ver `docs/offsets_guide.md` → sección "Verificación empírica del Worker"

---

## Dependencias

Solo herramientas del sistema, sin pip:
```
objdump   → análisis de gadgets ROP (binutils)
readelf   → secciones, relocaciones, segmentos
nm        → tabla de símbolos
strings   → búsqueda de strings
file      → verificación de tipo de archivo
```

Todas disponibles en cualquier Linux con `build-essential` o `binutils`.
En macOS: `brew install binutils`.
