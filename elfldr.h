/**
 * elfldr.h — Interfaz pública del ELF loader PS5
 */

#ifndef ELFLDR_H
#define ELFLDR_H

#include <stdint.h>
#include <stddef.h>

/* ── Tipos de payload ──────────────────────────────────────────────────── */

typedef enum {
    PAYLOAD_ELF  = 0,   /* ELF64 nativo (ET_EXEC o ET_DYN)        */
    PAYLOAD_SELF = 1,   /* SELF de Sony (contiene ELF cifrado/firmado) */
    PAYLOAD_RAW  = 2,   /* Binario raw; se ejecuta desde el inicio  */
} PayloadType;

/* ── Códigos de error ──────────────────────────────────────────────────── */

#define ELFLDR_OK              0
#define ELFLDR_ERR_MMAP       -1   /* mmap() falló                */
#define ELFLDR_ERR_LOAD       -2   /* No se pudo parsear/cargar el ELF */
#define ELFLDR_ERR_SELF_EXTRACT -3 /* No se pudo extraer ELF de SELF   */
#define ELFLDR_ERR_INVALID    -4   /* Formato inválido o no soportado   */

/* ── API pública ───────────────────────────────────────────────────────── */

/**
 * Detecta el tipo de payload según sus magic bytes.
 */
PayloadType elfldr_detect_type(const uint8_t *buf, size_t len);

/**
 * Carga y ejecuta un payload.
 * Debe llamarse desde un proceso hijo (fork()).
 *
 * @param buf   Buffer con el payload (mmap'd, RW)
 * @param len   Tamaño en bytes
 * @param type  Tipo detectado con elfldr_detect_type()
 * @returns     Código de salida del payload, o código de error negativo
 */
int elfldr_exec(uint8_t *buf, size_t len, PayloadType type);

#endif /* ELFLDR_H */
