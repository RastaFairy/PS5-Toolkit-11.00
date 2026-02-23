/**
 * pt.h — API del módulo de bootstrap vía ptrace
 */

#ifndef PT_H
#define PT_H

#include <sys/types.h>

/**
 * Inyecta el ELF loader en el proceso indicado por su nombre,
 * usando ptrace para escribir y ejecutar código en ese proceso.
 *
 * @param target_name  Nombre del proceso (ej. "SceRedisServer")
 * @returns 0 si OK, -1 si error
 */
int pt_bootstrap(const char *target_name);

#endif /* PT_H */
