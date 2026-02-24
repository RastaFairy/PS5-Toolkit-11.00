/**
 * pt.c — ptrace Bootstrap: Inject elfldr into SceRedisServer
 *
 * This module is executed as a payload by the initial ROP chain.
 * It finds the SceRedisServer process, attaches via ptrace, injects
 * a small shellcode stub that calls elfldr_main(), then detaches.
 *
 * SceRedisServer is chosen because:
 *   1. It runs persistently in the background
 *   2. It survives browser restarts and rest mode
 *   3. It has enough executable memory for injection
 *   4. It does not perform integrity checks on its own code
 *
 * Architecture: FreeBSD AMD64 (Orbis OS)
 * Requires: root + jail escape (done by kernel.js)
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include "pt.h"
#include "elfldr.h"

/* ─── Shellcode ───────────────────────────────────────────────────────────── */

/*
 * The injected shellcode does two things:
 *   1. Saves all registers (push rbp; mov rbp, rsp; pushall)
 *   2. Calls our elfldr_main() function
 *   3. Restores registers and jumps back to the original RIP
 *
 * Since we are hijacking an existing thread in SceRedisServer, we must
 * restore its execution state precisely after our loader is set up.
 *
 * The actual elfldr_main() creates a new thread for the listener so that
 * SceRedisServer's main thread can continue normally after we detach.
 */

/* Placeholder shellcode — real implementation is architecture-specific */
static const uint8_t INJECT_SHELLCODE[] = {
    /* push rbp          */ 0x55,
    /* mov rbp, rsp      */ 0x48, 0x89, 0xE5,
    /* push rax          */ 0x50,
    /* push rbx          */ 0x53,
    /* push rcx          */ 0x51,
    /* push rdx          */ 0x52,
    /* push rsi          */ 0x56,
    /* push rdi          */ 0x57,
    /* push r8           */ 0x41, 0x50,
    /* push r9           */ 0x41, 0x51,
    /* push r10          */ 0x41, 0x52,
    /* push r11          */ 0x41, 0x53,
    /* movabs rax, addr  */ 0x48, 0xB8,
      /* 8-byte address placeholder — patched at runtime */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* call rax          */ 0xFF, 0xD0,
    /* pop r11           */ 0x41, 0x5B,
    /* pop r10           */ 0x41, 0x5A,
    /* pop r9            */ 0x41, 0x59,
    /* pop r8            */ 0x41, 0x58,
    /* pop rdi           */ 0x5F,
    /* pop rsi           */ 0x5E,
    /* pop rdx           */ 0x5A,
    /* pop rcx           */ 0x59,
    /* pop rbx           */ 0x5B,
    /* pop rax           */ 0x58,
    /* pop rbp           */ 0x5D,
    /* ret               */ 0xC3,
};

/* Offset of the 8-byte address placeholder within INJECT_SHELLCODE */
#define SHELLCODE_ADDR_OFFSET  18

/* ─── Process utilities ──────────────────────────────────────────────────── */

/**
 * Find the PID of SceRedisServer by scanning /proc.
 * On Orbis OS, /proc/<pid>/cmdline contains the process name.
 *
 * @returns PID on success, -1 if not found.
 */
static pid_t find_redis_pid(void) {
    DIR *dp = opendir("/proc");
    if (!dp) return -1;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        /* Only look at numeric entries (PIDs) */
        pid_t pid = 0;
        for (int i = 0; de->d_name[i]; i++) {
            char c = de->d_name[i];
            if (c < '0' || c > '9') { pid = 0; break; }
            pid = pid * 10 + (c - '0');
        }
        if (!pid) continue;

        /* Read /proc/<pid>/cmdline */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);

        char cmdline[256] = {0};
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);

        if (strstr(cmdline, "SceRedisServer") != NULL) {
            closedir(dp);
            return pid;
        }
    }

    closedir(dp);
    return -1;
}

/* ─── ptrace helpers ─────────────────────────────────────────────────────── */

/**
 * Read `len` bytes from the target process at virtual address `addr`.
 * Uses PTRACE_PEEKDATA (reads one word at a time).
 *
 * @param pid    Target process PID.
 * @param addr   Virtual address in target.
 * @param buf    Output buffer.
 * @param len    Number of bytes to read.
 * @returns 0 on success, -1 on error.
 */
static int ptrace_read(pid_t pid, uintptr_t addr, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = ptrace(PT_READ_D, pid, (caddr_t)(addr + i), 0);
        size_t copy = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
        memcpy(buf + i, &word, copy);
    }
    return 0;
}

/**
 * Write `len` bytes to the target process at virtual address `addr`.
 * Uses PTRACE_POKEDATA (writes one word at a time).
 */
static int ptrace_write(pid_t pid, uintptr_t addr, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        size_t copy = (len - i < sizeof(long)) ? (len - i) : sizeof(long);

        /* For partial words, read-modify-write to preserve surrounding bytes */
        if (copy < sizeof(long)) {
            word = ptrace(PT_READ_D, pid, (caddr_t)(addr + i), 0);
        }

        memcpy(&word, buf + i, copy);
        ptrace(PT_WRITE_D, pid, (caddr_t)(addr + i), word);
    }
    return 0;
}

/* ─── Main injection routine ─────────────────────────────────────────────── */

/**
 * pt_inject() — Attach to SceRedisServer and inject the ELF loader.
 *
 * Steps:
 *   1. Find SceRedisServer PID
 *   2. ptrace attach + SIGSTOP
 *   3. Save registers (getregs)
 *   4. Patch shellcode with elfldr_main address
 *   5. Write shellcode to an executable region in target
 *   6. Redirect RIP to shellcode
 *   7. PTRACE_CONT — shellcode runs, sets up listener thread
 *   8. SIGSTOP again, restore original registers
 *   9. PTRACE_CONT — SceRedisServer continues normally
 *  10. ptrace detach
 *
 * @param elfldr_main_addr   Virtual address of elfldr_main() in OUR process.
 *                           Since we are running as a payload inside a fork()
 *                           of SceRedisServer (after the initial loader ELF
 *                           is executed), our address space already contains
 *                           elfldr_main — but in the injected context, this
 *                           address must be valid in the TARGET process too.
 *
 * @returns 0 on success.
 */
int pt_inject(uintptr_t elfldr_main_addr) {
    /* 1. Find SceRedisServer */
    pid_t target = find_redis_pid();
    if (target < 0) {
        return PT_ERR_PROC_NOT_FOUND;
    }

    /* 2. Attach */
    if (ptrace(PT_ATTACH, target, 0, 0) < 0) {
        return PT_ERR_ATTACH_FAILED;
    }

    /* Wait for SIGSTOP */
    int status;
    waitpid(target, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PT_DETACH, target, (caddr_t)1, 0);
        return PT_ERR_ATTACH_FAILED;
    }

    /* 3. Save registers */
    struct reg saved_regs;
    if (ptrace(PT_GETREGS, target, (caddr_t)&saved_regs, 0) < 0) {
        ptrace(PT_DETACH, target, (caddr_t)1, 0);
        return PT_ERR_GETREGS_FAILED;
    }

    /* 4. Patch shellcode: write elfldr_main_addr at the placeholder offset */
    uint8_t shellcode[sizeof(INJECT_SHELLCODE)];
    memcpy(shellcode, INJECT_SHELLCODE, sizeof(shellcode));
    memcpy(shellcode + SHELLCODE_ADDR_OFFSET, &elfldr_main_addr, 8);

    /* 5. Write shellcode into the target's stack (just below RSP — safe for
     *    a stopped process; we restore everything before continuing) */
    uintptr_t inject_addr = (uintptr_t)saved_regs.r_rsp - sizeof(shellcode) - 0x100;
    /* Align to 16 bytes */
    inject_addr &= ~0xFULL;

    /* Save original bytes at injection site */
    uint8_t orig_bytes[sizeof(shellcode)];
    ptrace_read(target, inject_addr, orig_bytes, sizeof(orig_bytes));

    ptrace_write(target, inject_addr, shellcode, sizeof(shellcode));

    /* 6. Redirect RIP */
    struct reg new_regs = saved_regs;
    new_regs.r_rip = inject_addr;
    ptrace(PT_SETREGS, target, (caddr_t)&new_regs, 0);

    /* 7. Continue — shellcode runs and sets up the listener thread */
    ptrace(PT_CONTINUE, target, (caddr_t)1, 0);

    /* Wait a moment for the thread to start (simple spin — no SAB/Atomics) */
    /* In practice, a short sleep is sufficient */
    volatile int spin = 1000000;
    while (spin-- > 0) { /* busy wait */ }

    /* 8. Stop again and restore registers + original bytes */
    kill(target, SIGSTOP);
    waitpid(target, &status, 0);

    ptrace_write(target, inject_addr, orig_bytes, sizeof(orig_bytes));
    ptrace(PT_SETREGS, target, (caddr_t)&saved_regs, 0);

    /* 9 & 10. Continue and detach */
    ptrace(PT_CONTINUE, target, (caddr_t)1, 0);
    ptrace(PT_DETACH,   target, (caddr_t)1, 0);

    return PT_OK;
}
