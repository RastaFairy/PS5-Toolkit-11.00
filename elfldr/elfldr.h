/**
 * elfldr.h — ELF64 / SELF / RAW Loader Interface
 *
 * Parses and maps payload binaries into memory, then transfers control
 * to their entry point.
 *
 * Supported formats:
 *   ELF64  — Standard 64-bit ELF (magic: \x7fELF, EI_CLASS=2)
 *   SELF   — Sony signed ELF wrapper (magic: \x00PSF or \x4f\x15\x3d\x1d)
 *   RAW    — Flat binary, loaded at a fixed base address
 */

#ifndef ELFLDR_H
#define ELFLDR_H

#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>

/* ─── Format detection ───────────────────────────────────────────────────── */

typedef enum {
    ELFLDR_FMT_ELF64 = 0,
    ELFLDR_FMT_SELF  = 1,
    ELFLDR_FMT_RAW   = 2,
} elfldr_fmt_t;

/**
 * Detect the format of a payload by inspecting its magic bytes.
 *
 * @param data    Pointer to payload bytes.
 * @param len     Length of payload in bytes.
 * @returns       ELFLDR_FMT_ELF64, ELFLDR_FMT_SELF, or ELFLDR_FMT_RAW.
 */
elfldr_fmt_t elfldr_detect_format(const uint8_t *data, size_t len);

/* ─── Loading and execution ──────────────────────────────────────────────── */

/**
 * Load and execute a payload.
 *
 * Depending on the format:
 *   ELF64: parse PT_LOAD segments, mmap, apply RELA relocations, call entry
 *   SELF:  strip the Sony header, extract the inner ELF, then same as ELF64
 *   RAW:   mmap at RAW_BASE_ADDR, mark PROT_READ|EXEC, call base
 *
 * This function does NOT return on success (the payload takes over).
 *
 * @param data    Payload bytes (caller retains ownership).
 * @param len     Length of payload.
 * @param fmt     Format as returned by elfldr_detect_format().
 * @returns       Non-zero error code on failure.
 */
int elfldr_exec(const uint8_t *data, size_t len, elfldr_fmt_t fmt);

/* ─── Memory helpers ─────────────────────────────────────────────────────── */

/**
 * Allocate `size` bytes of anonymous read/write memory via mmap.
 * Returns NULL on failure.
 */
static inline void *mmap_alloc(size_t size) {
    void *p = mmap(NULL, size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

/**
 * Free memory allocated by mmap_alloc.
 */
static inline void mmap_free(void *p, size_t size) {
    if (p) munmap(p, size);
}

/* ─── Constants ─────────────────────────────────────────────────────────── */

/** Base address for RAW binary payloads. */
#define RAW_BASE_ADDR   0x926200000ULL

/** SELF header magic (two variants seen on PS5). */
#define SELF_MAGIC_V1   0x00505346   /* \x00PSF in LE uint32 */
#define SELF_MAGIC_V2   0x1d3d154f   /* alternative */

#endif /* ELFLDR_H */
