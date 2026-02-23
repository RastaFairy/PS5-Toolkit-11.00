# Contribuir al proyecto PS5 Toolkit 11.xx

Gracias por tu interés en contribuir. Este documento explica cómo hacerlo de forma ordenada.

---

## Antes de abrir un issue

- Comprueba que no existe ya un issue abierto con el mismo problema.
- Indica siempre el **firmware exacto** de tu PS5 y el **sistema operativo** de tu PC.
- Si es un crash del exploit, adjunta la salida de `tools/listen_log.py`.

## Áreas donde se necesita ayuda

| Área | Descripción | Dificultad |
|------|-------------|-----------|
| `triggerWebKitBug()` | Implementar el trigger del bug para FW 11.00 | Alta |
| `leakLibKernelBase()` | Leak de libkBase desde WebKit | Alta |
| Offsets FW 11.00 | Verificar offsets en `offsets_1100.js` con Ghidra | Media |
| Offsets nuevos FW | Portar el toolkit a FW 11.xx posteriores | Alta |
| Tests Python | Tests unitarios para `send_payload.py` y `server.py` | Baja |
| Documentación | Mejorar docs, añadir ejemplos de payloads | Baja |

## Flujo de trabajo

```bash
# 1. Fork del repositorio en GitHub
# 2. Clonar tu fork
git clone https://github.com/RastaFairy/PS5-Toolkit-11.00
cd ps5-toolkit-11xx

# 3. Crear una rama para tu contribución
git checkout -b feature/mi-contribucion

# 4. Hacer cambios y commitear
git add .
git commit -m "feat: descripción clara del cambio"

# 5. Push y abrir Pull Request
git push origin feature/mi-contribucion
```

## Convenciones de commits

Usar el formato `tipo: descripción`:

| Tipo | Cuándo usarlo |
|------|--------------|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de bug |
| `docs` | Solo documentación |
| `offset` | Actualización de offsets de firmware |
| `refactor` | Refactoring sin cambio de comportamiento |

## Normas de código

**JavaScript (exploit/):**
- `"use strict"` en todos los archivos
- Comentarios en español o inglés, consistente por archivo
- Cada función con JSDoc mínimo (parámetros + retorno)

**C (elfldr/):**
- Estándar C11
- Sin warnings con `-Wall -Wextra`
- Cada función con comentario de propósito

**Python (host/, tools/):**
- Compatible con Python 3.8+
- Type hints donde sea útil
- Sin dependencias externas (solo stdlib)

## Seguridad

- **No subas dumps de firmware** ni binarios de Sony al repositorio.
- **No subas offsets extraídos directamente** de firmware sin permiso del propietario original.
- Los payloads de ejemplo deben ser inofensivos (hello world, info del sistema, etc.).

## Licencia

Al contribuir, aceptas que tu código se distribuya bajo la licencia GPLv3.
