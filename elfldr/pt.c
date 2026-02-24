/**
 * pt.c — Bootstrap vía ptrace: inyecta el ELF loader en SceRedisServer
 *
 * Técnica:
 *   1. Buscar el PID de SceRedisServer en /proc
 *   2. Adjuntarse al proceso con ptrace(PT_ATTACH)
 *   3. Copiar shellcode con ptrace(PT_WRITE_D) en una página RWX del target
 *   4. Redirigir RIP del target al shellcode
 *   5. El shellcode llama mmap() + memcpy() + instala el listener 9021
 *   6. Desadjuntarse (PT_DETACH): SceRedisServer continúa con el loader activo
 *
 * Este enfoque permite que el loader persista incluso cuando el proceso
 * de WebKit es destruido (cambio de juego, recarga del browser, etc.).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/reg.h>      /* Para struct reg en FreeBSD */

#include "pt.h"

/* ── Definiciones FreeBSD/Orbis ─────────────────────────────────────────── */

/* En FreeBSD, ptrace usa PT_* constantes */
#ifndef PT_ATTACH
#  define PT_ATTACH   10
#  define PT_DETACH   11
#  define PT_GETREGS  13
#  define PT_SETREGS  14
#  define PT_WRITE_D  5
#  define PT_READ_D   2
#  define PT_CONTINUE 7
#endif

/* ── Helpers de /proc ───────────────────────────────────────────────────── */

/**
 * Busca el PID de un proceso por nombre leyendo /proc/<pid>/comm.
 * @param name  Nombre del proceso (parcial o completo)
 * @returns PID o -1 si no se encontró
 */
static pid_t find_pid_by_name(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    pid_t result = -1;

    while ((ent = readdir(d)) != NULL) {
        /* Saltamos entradas que no son números */
        char *endptr;
        long pid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        /* Leer el nombre del proceso */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);

        int fd = open(comm_path, O_RDONLY);
        if (fd < 0) continue;

        char comm[256] = {0};
        ssize_t n = read(fd, comm, sizeof(comm) - 1);
        close(fd);

        if (n <= 0) continue;
        /* Quitar el newline final */
        if (comm[n-1] == '\n') comm[n-1] = '\0';

        if (strstr(comm, name) != NULL) {
            result = (pid_t)pid;
            break;
        }
    }

    closedir(d);
    return result;
}

/**
 * Lee la dirección de una región RWX del proceso target desde /proc/<pid>/maps.
 * Queremos un área donde podamos escribir shellcode.
 */
static uintptr_t find_rwx_region(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[256];
    uintptr_t result = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8];

        /* Formato: start-end perms offset dev inode [name] */
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;

        /* Buscar región rwxp */
        if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            if (end - start >= 0x1000) {   /* Al menos una página */
                result = start;
                break;
            }
        }
    }

    fclose(f);
    return result;
}

/* ── Shellcode de bootstrap ─────────────────────────────────────────────── */

/*
 * El shellcode que inyectamos en SceRedisServer hace lo mínimo necesario:
 *   1. Guardar todos los registros en el stack
 *   2. Llamar a la función que instala el listener del ELF loader
 *   3. Restaurar registros
 *   4. Retornar al RIP original (continúa SceRedisServer normalmente)
 *
 * El shellcode concreto depende de la ABI y los gadgets disponibles.
 * Aquí proporcionamos el esqueleto; el shellcode real se genera dinámicamente.
 */

/* Plantilla de shellcode x86-64 para FreeBSD/Orbis */
static const uint8_t SHELLCODE_TEMPLATE[] = {
    /* pushfq                   — guardar flags                         */
    0x9C,
    /* push rax                                                          */
    0x50,
    /* push rbx                                                          */
    0x53,
    /* push rcx                                                          */
    0x51,
    /* push rdx                                                          */
    0x52,
    /* push rsi                                                          */
    0x56,
    /* push rdi                                                          */
    0x57,
    /* push r8                                                           */
    0x41, 0x50,
    /* push r9                                                           */
    0x41, 0x51,
    /* push r10                                                          */
    0x41, 0x52,
    /* push r11                                                          */
    0x41, 0x53,

    /* mov rax, STUB_ADDR       — dirección de la función del loader     */
    /* [PATCH: 8 bytes en offset 14 = 0xE]                               */
    0x48, 0xB8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    /* call rax                                                          */
    0xFF, 0xD0,

    /* pop r11 / r10 / r9 / r8 / rdi / rsi / rdx / rcx / rbx / rax     */
    0x41, 0x5B,
    0x41, 0x5A,
    0x41, 0x59,
    0x41, 0x58,
    0x5F,
    0x5E,
    0x5A,
    0x59,
    0x5B,
    0x58,
    /* popfq                                                             */
    0x9D,

    /* mov rax, ORIG_RIP        — dirección de retorno original          */
    /* [PATCH: 8 bytes en offset 40 = 0x28]                              */
    0x48, 0xB8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    /* jmp rax                                                           */
    0xFF, 0xE0,
};

#define SHELLCODE_STUB_OFFSET   14   /* Offset donde parchear la dirección del stub */
#define SHELLCODE_ORIG_OFFSET   40   /* Offset donde parchear el RIP original */
#define SHELLCODE_SIZE          sizeof(SHELLCODE_TEMPLATE)

/* ── Implementación principal ───────────────────────────────────────────── */

/**
 * Inyecta el ELF loader en SceRedisServer vía ptrace.
 *
 * @param target_name  Nombre del proceso destino
 * @returns 0 si OK, -1 si error
 */
int pt_bootstrap(const char *target_name) {
    /* 1. Encontrar el PID del proceso destino */
    pid_t target_pid = find_pid_by_name(target_name);
    if (target_pid < 0) {
        return -1;  /* Proceso no encontrado */
    }

    /* 2. Adjuntarse al proceso */
    if (ptrace(PT_ATTACH, target_pid, NULL, 0) < 0) {
        return -1;
    }

    /* Esperar a que el proceso se detenga */
    int status;
    if (waitpid(target_pid, &status, 0) < 0) {
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    /* 3. Leer los registros actuales */
    struct reg regs;
    if (ptrace(PT_GETREGS, target_pid, &regs, 0) < 0) {
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    uintptr_t orig_rip = (uintptr_t)regs.r_rip;

    /* 4. Encontrar una región RWX donde inyectar el shellcode */
    uintptr_t rwx_addr = find_rwx_region(target_pid);
    if (rwx_addr == 0) {
        /* No hay región RWX; crear una con ptrace + mmap syscall */
        /* Esto requiere un stub ROP adicional — simplificado aquí */
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    /* 5. Preparar el shellcode */
    uint8_t shellcode[SHELLCODE_SIZE];
    memcpy(shellcode, SHELLCODE_TEMPLATE, SHELLCODE_SIZE);

    /* Parchar la dirección del stub del loader (instalador del listener) */
    /* En el contexto real, esta es la dirección de la función que
     * instala el socket server dentro de SceRedisServer */
    uintptr_t stub_addr = 0; /* TODO: se pasa como argumento en la implementación real */
    memcpy(shellcode + SHELLCODE_STUB_OFFSET, &stub_addr, sizeof(uintptr_t));

    /* Parchar el RIP original para retornar correctamente */
    memcpy(shellcode + SHELLCODE_ORIG_OFFSET, &orig_rip, sizeof(uintptr_t));

    /* 6. Escribir el shellcode en el proceso destino */
    size_t words = (SHELLCODE_SIZE + sizeof(long) - 1) / sizeof(long);
    for (size_t i = 0; i < words; i++) {
        long word;
        memcpy(&word, shellcode + i * sizeof(long),
               sizeof(long) > SHELLCODE_SIZE - i * sizeof(long)
               ? SHELLCODE_SIZE - i * sizeof(long)
               : sizeof(long));

        if (ptrace(PT_WRITE_D, target_pid,
                   (void *)(rwx_addr + i * sizeof(long)), word) < 0) {
            ptrace(PT_DETACH, target_pid, NULL, 0);
            return -1;
        }
    }

    /* 7. Redirigir RIP al shellcode */
    regs.r_rip = (register_t)rwx_addr;
    if (ptrace(PT_SETREGS, target_pid, &regs, 0) < 0) {
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    /* 8. Continuar la ejecución del proceso */
    if (ptrace(PT_CONTINUE, target_pid, (void *)1, 0) < 0) {
        ptrace(PT_DETACH, target_pid, NULL, 0);
        return -1;
    }

    /* 9. Esperar a que el shellcode se ejecute y el proceso continúe */
    /* En la práctica, esperamos una señal o un tiempo fijo */
    usleep(500000);  /* 500ms */

    /* 10. Desadjuntarse */
    ptrace(PT_DETACH, target_pid, (void *)1, 0);

    return 0;
}
