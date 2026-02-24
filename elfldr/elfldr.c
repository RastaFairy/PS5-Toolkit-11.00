/**
 * elfldr.c — ELF64 / SELF / RAW Payload Parser and Loader
 *
 * Architecture: FreeBSD AMD64 (Orbis OS)
 *
 * ELF64 loading sequence:
 *   1. Validate ELF header (magic, class, machine)
 *   2. Iterate PT_LOAD program headers
 *   3. mmap each segment at its p_vaddr with correct PROT flags
 *   4. Copy segment bytes from file
 *   5. Apply RELA relocations (if present)
 *   6. Jump to e_entry
 *
 * SELF loading:
 *   Extract the inner ELF from the SELF container, then follow ELF64 path.
 *
 * RAW loading:
 *   mmap at RAW_BASE_ADDR, mark PROT_READ|EXEC, call.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "elfldr.h"

/* ─── ELF64 type definitions ─────────────────────────────────────────────── */

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;
typedef uint16_t Elf64_Half;

#define EI_NIDENT  16

typedef struct {
    uint8_t    e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off  e_phoff;
    Elf64_Off  e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word  p_type;
    Elf64_Word  p_flags;
    Elf64_Off   p_offset;
    Elf64_Addr  p_vaddr;
    Elf64_Addr  p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct {
    Elf64_Addr   r_offset;
    Elf64_Xword  r_info;
    Elf64_Sxword r_addend;
} Elf64_Rela;

typedef struct {
    Elf64_Addr   st_value;
    /* ... other fields not needed for basic relocation */
} Elf64_Sym;

/* Program header types */
#define PT_LOAD    1
#define PT_DYNAMIC 2

/* Program header flags */
#define PF_X  1
#define PF_W  2
#define PF_R  4

/* Relocation type */
#define R_X86_64_RELATIVE  8

/* ─── Format detection ───────────────────────────────────────────────────── */

elfldr_fmt_t elfldr_detect_format(const uint8_t *data, size_t len) {
    if (len < 4) return ELFLDR_FMT_RAW;

    /* ELF magic: \x7fELF */
    if (data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return ELFLDR_FMT_ELF64;
    }

    /* SELF magic variant 1: \x00PSF */
    if (data[0] == 0x00 && data[1] == 'P' && data[2] == 'S' && data[3] == 'F') {
        return ELFLDR_FMT_SELF;
    }

    /* SELF magic variant 2 */
    if (data[0] == 0x4f && data[1] == 0x15 && data[2] == 0x3d && data[3] == 0x1d) {
        return ELFLDR_FMT_SELF;
    }

    return ELFLDR_FMT_RAW;
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

/** Convert ELF segment flags to mmap PROT_* flags. */
static int phdr_prot(Elf64_Word p_flags) {
    int prot = 0;
    if (p_flags & PF_R) prot |= PROT_READ;
    if (p_flags & PF_W) prot |= PROT_WRITE;
    if (p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

/** Round `n` down to the nearest multiple of `align`. */
static Elf64_Addr align_down(Elf64_Addr n, Elf64_Xword align) {
    return (align > 1) ? (n & ~(align - 1)) : n;
}

/** Round `n` up to the nearest multiple of `align`. */
static Elf64_Addr align_up(Elf64_Addr n, Elf64_Xword align) {
    return (align > 1) ? ((n + align - 1) & ~(align - 1)) : n;
}

/* ─── ELF64 loader ───────────────────────────────────────────────────────── */

/**
 * Validate the ELF header.
 * @returns 0 on success, non-zero on invalid header.
 */
static int elf64_validate(const Elf64_Ehdr *ehdr, size_t len) {
    if (len < sizeof(Elf64_Ehdr))            return -1;
    if (ehdr->e_ident[0] != 0x7f)           return -2;
    if (ehdr->e_ident[1] != 'E')            return -2;
    if (ehdr->e_ident[2] != 'L')            return -2;
    if (ehdr->e_ident[3] != 'F')            return -2;
    if (ehdr->e_ident[4] != 2)              return -3;  /* ELFCLASS64 */
    if (ehdr->e_ident[5] != 1)              return -4;  /* ELFDATA2LSB */
    if (ehdr->e_machine   != 62)            return -5;  /* EM_X86_64 */
    return 0;
}

/**
 * Load and execute an ELF64 binary.
 *
 * @param data   Raw ELF bytes.
 * @param len    Length of data.
 * @param base   Load offset (0 for non-PIE, computed for PIE).
 * @returns      Non-zero on error. Does not return on success.
 */
static int elf64_load(const uint8_t *data, size_t len) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;

    if (elf64_validate(ehdr, len) != 0) return -1;

    /* Determine if PIE (ET_DYN) and find load bias */
    Elf64_Addr load_bias = 0;
    int is_pie = (ehdr->e_type == 3); /* ET_DYN */

    /* First pass: if PIE, allocate space and compute bias */
    if (is_pie) {
        /* Find the lowest and highest vaddrs to determine total size */
        Elf64_Addr min_vaddr = (Elf64_Addr)-1;
        Elf64_Addr max_vaddr = 0;

        for (int i = 0; i < ehdr->e_phnum; i++) {
            const Elf64_Phdr *phdr =
                (const Elf64_Phdr *)(data + ehdr->e_phoff + i * ehdr->e_phentsize);
            if (phdr->p_type != PT_LOAD) continue;

            if (phdr->p_vaddr < min_vaddr) min_vaddr = phdr->p_vaddr;
            Elf64_Addr end = phdr->p_vaddr + phdr->p_memsz;
            if (end > max_vaddr) max_vaddr = end;
        }

        size_t total = (size_t)(max_vaddr - min_vaddr);
        void *base = mmap(NULL, total,
                          PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
        if (base == MAP_FAILED) return -2;
        load_bias = (Elf64_Addr)base - min_vaddr;
    }

    /* Second pass: map each PT_LOAD segment */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr =
            (const Elf64_Phdr *)(data + ehdr->e_phoff + i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD) continue;
        if (phdr->p_memsz == 0)      continue;

        Elf64_Addr seg_start = align_down(phdr->p_vaddr + load_bias, phdr->p_align);
        Elf64_Addr seg_end   = align_up(phdr->p_vaddr + load_bias + phdr->p_memsz, phdr->p_align);
        size_t     seg_size  = (size_t)(seg_end - seg_start);

        /* Map the segment as RW first so we can write it */
        void *seg = mmap((void *)seg_start, seg_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1, 0);
        if (seg == MAP_FAILED) return -3;

        /* Copy data from file into segment */
        if (phdr->p_filesz > 0 && phdr->p_offset + phdr->p_filesz <= len) {
            memcpy((uint8_t *)seg + (phdr->p_vaddr - align_down(phdr->p_vaddr, phdr->p_align)),
                   data + phdr->p_offset,
                   phdr->p_filesz);
        }

        /* Apply final protection flags */
        mprotect(seg, seg_size, phdr_prot(phdr->p_flags));
    }

    /* Apply RELA relocations if PIE */
    if (is_pie && load_bias != 0) {
        for (int i = 0; i < ehdr->e_phnum; i++) {
            const Elf64_Phdr *phdr =
                (const Elf64_Phdr *)(data + ehdr->e_phoff + i * ehdr->e_phentsize);
            if (phdr->p_type != PT_DYNAMIC) continue;

            /* Walk dynamic entries to find RELA table */
            /* (simplified: only handles R_X86_64_RELATIVE) */
            const int64_t *dyn = (const int64_t *)(data + phdr->p_offset);
            const Elf64_Rela *rela = NULL;
            size_t rela_count = 0;

            for (; dyn[0] != 0; dyn += 2) {
                if (dyn[0] == 7  /* DT_RELA */)      rela       = (const Elf64_Rela *)(load_bias + dyn[1]);
                if (dyn[0] == 8  /* DT_RELASZ */)     rela_count = dyn[1] / sizeof(Elf64_Rela);
            }

            if (rela && rela_count) {
                for (size_t r = 0; r < rela_count; r++) {
                    uint32_t rtype = (uint32_t)(rela[r].r_info & 0xffffffff);
                    if (rtype == R_X86_64_RELATIVE) {
                        uint64_t *target = (uint64_t *)(load_bias + rela[r].r_offset);
                        *target = load_bias + rela[r].r_addend;
                    }
                }
            }
            break;
        }
    }

    /* Jump to entry point */
    Elf64_Addr entry = ehdr->e_entry + load_bias;
    typedef void (*entry_fn_t)(void);
    ((entry_fn_t)entry)();

    /* Should not reach here */
    return 0;
}

/* ─── SELF extractor ─────────────────────────────────────────────────────── */

/*
 * SELF (Signed ELF) is Sony's wrapping format. The inner ELF starts at a
 * known offset within the container. The exact offset varies by SELF version;
 * the most common layout has the inner ELF starting at byte 0x100 or at an
 * offset stored in the SELF header.
 *
 * SELF header (simplified, first 32 bytes):
 *   +0x00  uint32  magic         (0x00505346 or 0x4f153d1d)
 *   +0x04  uint32  unk
 *   +0x08  uint16  category
 *   +0x0a  uint16  program_type
 *   +0x0c  uint16  padding
 *   +0x0e  uint16  header_size   ← inner ELF starts here
 *   +0x10  uint64  elf_file_size
 */

#define SELF_HEADER_SIZE_OFFSET  0x0e

static int self_load(const uint8_t *data, size_t len) {
    if (len < 0x20) return -1;

    /* Read the offset of the inner ELF from the SELF header */
    uint16_t inner_offset;
    memcpy(&inner_offset, data + SELF_HEADER_SIZE_OFFSET, sizeof(inner_offset));

    if (inner_offset >= len) return -2;

    const uint8_t *inner = data + inner_offset;
    size_t inner_len = len - inner_offset;

    /* Validate that the inner data looks like an ELF */
    if (elfldr_detect_format(inner, inner_len) != ELFLDR_FMT_ELF64) return -3;

    return elf64_load(inner, inner_len);
}

/* ─── RAW loader ─────────────────────────────────────────────────────────── */

static int raw_load(const uint8_t *data, size_t len) {
    void *base = mmap((void *)RAW_BASE_ADDR, len,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                      -1, 0);
    if (base == MAP_FAILED) return -1;

    memcpy(base, data, len);
    mprotect(base, len, PROT_READ | PROT_EXEC);

    typedef void (*raw_fn_t)(void);
    ((raw_fn_t)base)();

    return 0;
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

int elfldr_exec(const uint8_t *data, size_t len, elfldr_fmt_t fmt) {
    switch (fmt) {
        case ELFLDR_FMT_ELF64: return elf64_load(data, len);
        case ELFLDR_FMT_SELF:  return self_load(data, len);
        case ELFLDR_FMT_RAW:   return raw_load(data, len);
        default:               return -99;
    }
}
