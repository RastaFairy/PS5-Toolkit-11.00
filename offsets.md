---
name: Offsets para nuevo firmware
about: Aportar offsets verificados para un firmware diferente
title: '[OFFSETS] FW X.XX'
labels: offsets
assignees: ''
---

## Firmware
<!-- Versión exacta, ej: 11.02 -->

## Offsets verificados

### libkernel
| Campo | Offset | Método de verificación |
|-------|--------|----------------------|
| thread_list | 0x | |
| gadget_pop_rdi_ret | 0x | |
| gadget_pop_rsp_ret | 0x | |
| syscall_mmap | 0x | |

### WebKit
| Campo | Offset | Método de verificación |
|-------|--------|----------------------|
| worker_ret_offset | 0x | |
| worker_stack_size | 0x | |

### Kernel
| Campo | Offset | Método de verificación |
|-------|--------|----------------------|
| allproc | 0x | |
| proc_ucred | 0x | |

## Herramientas usadas
- [ ] Ghidra
- [ ] IDA Pro
- [ ] radare2
- [ ] Verificado en hardware real

## Notas adicionales
