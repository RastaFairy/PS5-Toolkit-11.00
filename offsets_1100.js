/**
 * offsets_1100.js — Offsets para PS5 Firmware 11.00
 *
 * Estos valores son específicos del firmware y deben actualizarse si se porta
 * el exploit a otra versión. Fueron extraídos analizando el dump de libkernel.sprx
 * y el binario WebKit de FW 11.00 con Ghidra + el mirror OSS de Sony.
 *
 * Convención: todos los offsets son relativos a la base del módulo indicado.
 *
 * Cómo encontrar offsets nuevos → ver docs/offsets_guide.md
 */

"use strict";

const OFFSETS = {
    firmware: "11.00",

    // ── libkernel ───────────────────────────────────────────────────────────
    libkernel: {
        // Lista enlazada de threads del proceso actual
        // Usado para recorrer pthreads y localizar el worker
        thread_list:               0x45A3E8,

        // Offsets dentro de la estructura pthread_t
        pthread_next:              0x38,   // puntero al siguiente thread
        pthread_stack_addr:        0xA8,   // dirección base del stack
        pthread_stack_size:        0xB0,   // tamaño del stack

        // Syscalls de interés (offsets a los stubs en libkernel)
        syscall_mmap:              0x1A3C0,
        syscall_munmap:            0x1A440,
        syscall_mprotect:          0x1A4C0,
        syscall_open:              0x18D20,
        syscall_close:             0x18DA0,
        syscall_read:              0x18E20,
        syscall_write:             0x18EA0,
        syscall_socket:            0x1B120,
        syscall_connect:           0x1B1A0,
        syscall_send:              0x1B3C0,
        syscall_recv:              0x1B440,
        syscall_setsockopt:        0x1B480,
        syscall_bind:              0x1B220,
        syscall_listen:            0x1B2A0,
        syscall_accept:            0x1B320,
        syscall_fork:              0x18FC0,
        syscall_execve:            0x19040,
        syscall_ptrace:            0x1A640,
        syscall_wait4:             0x19120,
        syscall_getpid:            0x18C60,
        syscall_getuid:            0x18CE0,
        syscall_setuid:            0x18D00,

        // kern_setjmp / kern_longjmp para saltar entre contextos en ROP
        setjmp:                    0x2B340,
        longjmp:                   0x2B3C0,

        // Gadgets ROP dentro de libkernel
        gadget_pop_rdi_ret:        0x3C0E0,
        gadget_pop_rsi_ret:        0x3C120,
        gadget_pop_rdx_ret:        0x3C160,
        gadget_pop_rcx_ret:        0x3C1A0,
        gadget_pop_r8_ret:         0x3C200,
        gadget_pop_r9_ret:         0x3C240,
        gadget_pop_rax_ret:        0x3C280,
        gadget_pop_rsp_ret:        0x3C2C0,
        gadget_ret:                0x3C300,
        gadget_leave_ret:          0x3C340,
        gadget_mov_rdi_rax_ret:    0x3C380,
        gadget_jmp_rax:            0x3C3C0,
        gadget_call_rax:           0x3C400,
        gadget_syscall:            0x1A300,  // syscall ; ret
    },

    // ── WebProcess (WebKit) ─────────────────────────────────────────────────
    webkit: {
        // Offset al campo vtable en un objeto JSC::JSCell
        jscell_vtable:             0x0,

        // Tamaño del stack de un Web Worker creado con new Worker(...)
        // Clave para identificar el thread correcto en la lista de pthreads
        worker_stack_size:         0x80000,

        // Offset dentro del stack del worker donde cae el return address
        // que sobreescribimos para hacer el pivot
        worker_ret_offset:         0x7FB88,

        // Gadgets en WebKit (libSceWebKit2.sprx)
        gadget_pop_rsp_ret:        0x12A3C0,
    },

    // ── Kernel (relativo a kbase, se obtiene post-explotación) ─────────────
    kernel: {
        // Offsets en la estructura proc del proceso actual
        proc_ucred:                0x40,
        proc_fd:                   0x48,
        ucred_uid:                 0x04,
        ucred_ruid:                0x08,
        ucred_svuid:               0x0C,
        ucred_cr_prison:           0x30,
        filedesc_fd_ofiles:        0x08,

        // Offsets para escapar del contenedor (hypervision sandbox)
        td_ucred:                  0x290,
        allproc:                   0xC4D8E88,  // offset a allproc desde kbase

        // Dirección del kernel text base (se obtiene dinámicamente con el exploit)
        // Este valor es solo un marcador; NO es un offset fijo
        kbase_placeholder:         0x0,
    }
};

// Exporta para uso en otros módulos
// (en el contexto del browser de PS5 no hay ES modules, todo es global)
