/**
 * elfldr.c — Parser y ejecutor de payloads ELF / SELF / RAW para PS5
 *
 * Soporta:
 *   • ELF64 estático (sin dynamic linker) — el caso más común para payloads
 *   • ELF64 PIC/PIE — con relocation básica
 *   • SELF (.self / .sprx) — extrae el ELF embebido y lo procesa igual
 *   • RAW — se copia a memoria RWX y se ejecuta desde el inicio del buffer
 *
 * Restricciones del entorno PS5:
 *   • XOM: las páginas ejecutables NO son legibles. Por eso el ELF se carga
 *     primero como RW, se parchean las relocations, y LUEGO se marcan RX.
 *   • ASLR: la base de carga se elige con mmap() y puede ser aleatoria.
 *     Los payloads PIE deben manejar self-relocation.
 *   • No hay dynamic linker disponible en este contexto. Los payloads
 *     deben ser estáticos o resolver sus propias importaciones.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

#include "elfldr.h"

/* ── Constantes y macros ───────────────────────────────────────────────── */

#define ELF_MAGIC      0x464C457FU  /* \x7fELF en little-endian */
#define SELF_MAGIC     0x464F5300U  /* \x00PSF en big-endian = PSF\x00 */

#define ALIGN_UP(v, a)   (((v) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(v, a) ((v) & ~((a) - 1))
#define PAGE_SIZE        0x4000     /* 16 KiB — tamaño de página en Orbis */

/* Tamaño máximo de un segmento individual (256 MiB) */
#define MAX_SEGMENT_SIZE (256UL * 1024 * 1024)

/* ── Estructura SELF (simplificada) ────────────────────────────────────── */
/* El formato SELF de Sony envuelve un ELF firmado. La cabecera describe
 * segmentos cifrados; el ELF real está embebido. Esta es la vista mínima
 * que necesitamos para extraer el ELF interno. */

typedef struct __attribute__((packed)) {
    uint32_t magic;         /* 0x4F465350 "OPFS" o 0x00534600 */
    uint8_t  version;
    uint8_t  mode;
    uint8_t  endian;
    uint8_t  attributes;
    uint16_t category;
    uint16_t program_type;
    uint64_t padding1;
    uint16_t header_size;
    uint16_t sign_info_size;
    uint32_t file_size;
    uint32_t padding2;
    uint16_t num_entries;
    uint16_t flags;
} SelfHeader;

/* ── Implementación ────────────────────────────────────────────────────── */

/**
 * Detecta el tipo de un payload por sus magic bytes.
 */
PayloadType elfldr_detect_type(const uint8_t *buf, size_t len) {
    if (len < 4) return PAYLOAD_RAW;

    uint32_t magic;
    memcpy(&magic, buf, 4);

    if (magic == ELF_MAGIC) return PAYLOAD_ELF;

    /* SELF: los primeros bytes son 0x00 P S F (big-endian: 0x00505346) */
    if (buf[0] == 0x00 && buf[1] == 'P' && buf[2] == 'S' && buf[3] == 'F')
        return PAYLOAD_SELF;

    return PAYLOAD_RAW;
}

/**
 * Extrae el ELF embebido en un SELF.
 * Retorna un puntero al inicio del ELF y su tamaño, o NULL en error.
 *
 * Nota: el puntero retornado apunta dentro de 'buf'; NO hay copia.
 * El caller debe verificar que el ELF resultante es válido.
 */
static const uint8_t *self_extract_elf(const uint8_t *buf, size_t len,
                                        size_t *elf_len_out) {
    if (len < sizeof(SelfHeader)) return NULL;

    const SelfHeader *hdr = (const SelfHeader *)buf;
    uint16_t hdr_size     = hdr->header_size;

    if (hdr_size >= len) return NULL;

    /* El ELF empieza justo después de la cabecera SELF */
    const uint8_t *elf = buf + hdr_size;
    size_t         rem = len - hdr_size;

    /* Verificar que tenga el magic ELF */
    uint32_t magic;
    if (rem < 4) return NULL;
    memcpy(&magic, elf, 4);
    if (magic != ELF_MAGIC) return NULL;

    *elf_len_out = rem;
    return elf;
}

/**
 * Carga un ELF64 en memoria y retorna un puntero a la función de entrada.
 *
 * @param buf      Buffer con el ELF completo
 * @param len      Longitud del buffer
 * @param base_out Se rellena con la dirección base de carga (para PIE)
 * @returns        Puntero a la función de entrada, o NULL en error
 */
static void *elf_load(const uint8_t *buf, size_t len, uintptr_t *base_out) {
    if (len < sizeof(Elf64_Ehdr)) return NULL;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buf;

    /* Validaciones básicas */
    if (ehdr->e_ident[EI_CLASS]   != ELFCLASS64)   return NULL;
    if (ehdr->e_ident[EI_DATA]    != ELFDATA2LSB)   return NULL;
    if (ehdr->e_machine           != EM_X86_64)     return NULL;
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) return NULL;

    /* ── Calcular el rango de carga ── */
    uintptr_t vaddr_min = UINTPTR_MAX;
    uintptr_t vaddr_max = 0;

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(buf + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;
        if (phdr[i].p_memsz == 0)      continue;

        uintptr_t seg_start = ALIGN_DOWN(phdr[i].p_vaddr, PAGE_SIZE);
        uintptr_t seg_end   = ALIGN_UP(phdr[i].p_vaddr + phdr[i].p_memsz, PAGE_SIZE);

        if (seg_start < vaddr_min) vaddr_min = seg_start;
        if (seg_end   > vaddr_max) vaddr_max = seg_end;
    }

    if (vaddr_min == UINTPTR_MAX || vaddr_max == 0) return NULL;

    size_t total_size = vaddr_max - vaddr_min;
    if (total_size == 0 || total_size > MAX_SEGMENT_SIZE) return NULL;

    /* ── Reservar espacio de carga ── */
    /* Para ELF estático (ET_EXEC) intentamos cargar en la dirección exacta.
     * Para PIE (ET_DYN) dejamos que el kernel elija la base. */
    void *hint = (ehdr->e_type == ET_EXEC) ? (void *)vaddr_min : NULL;

    void *load_base = mmap(hint, total_size,
                           PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE,
                           -1, 0);
    if (load_base == MAP_FAILED) return NULL;

    /* Para ET_EXEC verificar que el SO mapeó donde pedimos */
    if (ehdr->e_type == ET_EXEC && (uintptr_t)load_base != vaddr_min) {
        munmap(load_base, total_size);
        return NULL;
    }

    uintptr_t slide = (uintptr_t)load_base - vaddr_min;
    if (base_out) *base_out = (uintptr_t)load_base;

    /* Inicializar todo a cero (para BSS implícito) */
    memset(load_base, 0, total_size);

    /* ── Cargar segmentos PT_LOAD ── */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_memsz == 0)      continue;

        if (ph->p_filesz > len - ph->p_offset) {
            /* El ELF está truncado */
            munmap(load_base, total_size);
            return NULL;
        }

        uintptr_t dest = (uintptr_t)load_base + (ph->p_vaddr - vaddr_min);
        memcpy((void *)dest, buf + ph->p_offset, ph->p_filesz);
        /* El resto (p_memsz - p_filesz) ya es cero por el memset anterior */
    }

    /* ── Aplicar relocations (solo para PIE con RELA) ── */
    /* Buscamos la sección .rela.dyn si existe */
    if (ehdr->e_type == ET_DYN && ehdr->e_shoff != 0) {
        const Elf64_Shdr *shdr = (const Elf64_Shdr *)(buf + ehdr->e_shoff);
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_type != SHT_RELA) continue;

            const Elf64_Rela *rela = (const Elf64_Rela *)(buf + shdr[i].sh_offset);
            size_t nrela = shdr[i].sh_size / sizeof(Elf64_Rela);

            for (size_t j = 0; j < nrela; j++) {
                uint32_t rtype = ELF64_R_TYPE(rela[j].r_info);
                uintptr_t *target = (uintptr_t *)((uintptr_t)load_base
                                                  + rela[j].r_offset
                                                  - vaddr_min);

                switch (rtype) {
                case R_X86_64_RELATIVE:
                    /* B + A */
                    *target = (uintptr_t)load_base + rela[j].r_addend;
                    break;
                case R_X86_64_64:
                    /* S + A — requiere tabla de símbolos; ignorar por ahora */
                    break;
                default:
                    break;
                }
            }
        }
    }

    /* ── Aplicar permisos de página por segmento ── */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_memsz == 0)      continue;

        int prot = 0;
        if (ph->p_flags & PF_R) prot |= PROT_READ;
        if (ph->p_flags & PF_W) prot |= PROT_WRITE;
        if (ph->p_flags & PF_X) prot |= PROT_EXEC;

        uintptr_t seg_start = ALIGN_DOWN((uintptr_t)load_base
                                         + ph->p_vaddr - vaddr_min, PAGE_SIZE);
        size_t seg_size     = ALIGN_UP(ph->p_memsz + (ph->p_vaddr & (PAGE_SIZE-1)),
                                       PAGE_SIZE);

        mprotect((void *)seg_start, seg_size, prot);
    }

    /* Dirección de entrada */
    uintptr_t entry = ehdr->e_entry + slide;
    return (void *)entry;
}

/**
 * Ejecuta un payload (ELF, SELF o RAW).
 *
 * @param buf   Buffer con el payload
 * @param len   Tamaño del payload
 * @param type  Tipo detectado (ver PayloadType)
 * @returns     0 si OK, código de error si falla
 */
int elfldr_exec(uint8_t *buf, size_t len, PayloadType type) {
    void *entry = NULL;

    if (type == PAYLOAD_SELF) {
        /* Extraer ELF del SELF */
        size_t elf_len = 0;
        const uint8_t *elf = self_extract_elf(buf, len, &elf_len);
        if (!elf) return ELFLDR_ERR_SELF_EXTRACT;

        uintptr_t base;
        entry = elf_load(elf, elf_len, &base);

    } else if (type == PAYLOAD_ELF) {
        uintptr_t base;
        entry = elf_load(buf, len, &base);

    } else {
        /* RAW: copiar a memoria RWX y saltar al inicio */
        void *mem = mmap(NULL, len,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (mem == MAP_FAILED) return ELFLDR_ERR_MMAP;

        memcpy(mem, buf, len);
        entry = mem;
    }

    if (!entry) return ELFLDR_ERR_LOAD;

    /* Llamar al punto de entrada como una función C sin argumentos */
    typedef int (*EntryFn)(void);
    EntryFn fn = (EntryFn)entry;
    return fn();
}
