/**
 * pt.h — ptrace Bootstrap Interface
 */

#ifndef PT_H
#define PT_H

#include <stdint.h>

/* ─── Return codes ───────────────────────────────────────────────────────── */

#define PT_OK                  0
#define PT_ERR_PROC_NOT_FOUND -1
#define PT_ERR_ATTACH_FAILED  -2
#define PT_ERR_GETREGS_FAILED -3
#define PT_ERR_WRITE_FAILED   -4

/* ─── API ────────────────────────────────────────────────────────────────── */

/**
 * Attach to SceRedisServer via ptrace and inject the persistent ELF loader.
 *
 * @param elfldr_main_addr  Address of elfldr_main() to call in the target.
 * @returns PT_OK on success, negative error code on failure.
 */
int pt_inject(uintptr_t elfldr_main_addr);

#endif /* PT_H */
