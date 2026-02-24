#!/usr/bin/env python3
"""
gen_offsets.py — Script maestro que orquesta todos los análisis
                 y genera un offsets_1100.js completo y listo para usar.

Uso simple (lo más común):
    python3 gen_offsets.py \\
        --libkernel libkernel.elf \\
        --webkit    WebKit.elf \\
        --kernel    mini-syscore.elf

    → Genera: offsets_1100.js  (listo para copiar al proyecto)
              offsets_raw.json  (datos en bruto de todos los análisis)
              offsets_report.txt (informe con confianza de cada valor)

Solo libkernel (mínimo para empezar):
    python3 gen_offsets.py --libkernel libkernel.elf

Con conversión automática de SELF (si aún tienes los .sprx):
    python3 gen_offsets.py \\
        --libkernel-sprx libkernel.sprx \\
        --webkit-sprx    WebKit.sprx \\
        --kernel-sprx    mini-syscore.elf
"""

import sys
import os
import json
import argparse
import subprocess
import datetime
from pathlib import Path

# Añadir el directorio actual al path para importar los otros scripts
sys.path.insert(0, str(Path(__file__).parent))


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)


def convert_if_needed(sprx_path: str, out_dir: str) -> str | None:
    """Convierte un SELF/SPRX a ELF si es necesario."""
    if sprx_path is None:
        return None
    if sprx_path.endswith('.elf') and os.path.exists(sprx_path):
        return sprx_path

    out_path = os.path.join(out_dir, Path(sprx_path).stem + '.elf')
    print(f'[CONV] {sprx_path} → {out_path}')

    script = Path(__file__).parent / 'self2elf.py'
    ok, out = run(['python3', str(script), sprx_path, out_path])
    if ok and os.path.exists(out_path):
        return out_path
    else:
        print(f'[ERROR] Conversión fallida: {out}')
        return None


def run_analyzer(script_name: str, elf_path: str, extra_args: list = None,
                 json_out: str = None) -> dict:
    """Ejecuta un script de análisis y retorna el resultado parseado."""
    script = Path(__file__).parent / script_name
    cmd = ['python3', str(script), elf_path]
    if extra_args:
        cmd.extend(extra_args)
    if json_out:
        cmd.extend(['--json', json_out])

    print(f'\n{"="*60}')
    ok, output = run(cmd)
    print(output)

    if json_out and os.path.exists(json_out):
        with open(json_out) as f:
            return json.load(f)
    return {}


def confidence(val) -> str:
    """Retorna el nivel de confianza de un valor extraído."""
    if val is None:
        return 'FALTANTE'
    if isinstance(val, str) and 'VERIFICAR' in val.upper():
        return 'BAJA'
    return 'MEDIA'  # extraído automáticamente, sin verificación en hardware


# ── Template de offsets_1100.js ───────────────────────────────────────────

JS_TEMPLATE = '''/**
 * offsets_1100.js — Offsets para PS5 Firmware 11.00
 *
 * GENERADO AUTOMÁTICAMENTE por gen_offsets.py
 * Fecha: {date}
 *
 * Archivos analizados:
 *   libkernel : {libkernel_src}
 *   WebKit    : {webkit_src}
 *   kernel    : {kernel_src}
 *
 * IMPORTANTE: Los valores marcados con "// ⚠ VERIFICAR" son estimaciones
 * derivadas de análisis estático. Deben verificarse en hardware antes de
 * usar el exploit. Ver docs/offsets_guide.md para el proceso de verificación.
 *
 * Confianza por sección:
 *   Gadgets ROP      → {conf_gadgets}
 *   Símbolos libk    → {conf_symbols}
 *   pthread offsets  → {conf_pthread}
 *   WebKit GOT       → {conf_got}
 *   Kernel symbols   → {conf_kernel_syms}
 *   Kernel structs   → {conf_kernel_structs}
 */

"use strict";

// ════════════════════════════════════════════════════════════════
// SECCIÓN 1: libkernel.sprx
// ════════════════════════════════════════════════════════════════

// ── Gadgets ROP (offsets desde libkBase) ────────────────────────

{gadgets_js}

// ── Símbolos de libkernel (offsets desde libkBase) ──────────────
// Usados para el leak de libkBase desde la GOT de WebKit

{symbols_js}

// ── Estructura pthread_t ────────────────────────────────────────
// Usados en findWorkerStack() para iterar los threads y hallar el Worker

{pthread_js}

// ════════════════════════════════════════════════════════════════
// SECCIÓN 2: WebKit
// ════════════════════════════════════════════════════════════════

// ── GOT de WebKit → leak de libkBase ────────────────────────────
// leakLibKernelBase() lee webkit_base + got_offset → obtiene puntero a libkernel
// libkBase = ptr - libkernel_sym_offset

{webkit_js}

// ── Worker stack ────────────────────────────────────────────────
const worker_stack_size  = 0x80000;    // tamaño del stack del Web Worker (estable)
const worker_ret_offset  = {worker_ret_offset}; // ⚠ VERIFICAR empíricamente en hardware

// ════════════════════════════════════════════════════════════════
// SECCIÓN 3: Kernel
// ════════════════════════════════════════════════════════════════

// ── Símbolos del kernel (offsets desde kBase) ───────────────────

{kernel_symbols_js}

// ── Offsets de estructuras del kernel ───────────────────────────

{kernel_structs_js}

// ════════════════════════════════════════════════════════════════
// SECCIÓN 4: Constantes del sistema
// ════════════════════════════════════════════════════════════════

// Syscalls de PS5/Orbis (FreeBSD 11, Orbis modificado)
const SYS_mmap        = 197;
const SYS_munmap      = 73;
const SYS_mprotect    = 74;
const SYS_socket      = 97;
const SYS_connect     = 98;
const SYS_write       = 4;
const SYS_read        = 3;
const SYS_close       = 6;
const SYS_fork        = 2;
const SYS_getpid      = 20;
const SYS_pipe        = 42;
const SYS_sysctl      = 202;
const SYS_ptrace      = 26;
const SYS_kill        = 37;
const SYS_umtx_op     = 454;

// Flags de mmap/mprotect
const PROT_NONE  = 0x00;
const PROT_READ  = 0x01;
const PROT_WRITE = 0x02;
const PROT_EXEC  = 0x04;
const MAP_SHARED  = 0x0001;
const MAP_PRIVATE = 0x0002;
const MAP_FIXED   = 0x0010;
const MAP_ANON    = 0x1000;

// ════════════════════════════════════════════════════════════════
// SECCIÓN 5: Exports
// ════════════════════════════════════════════════════════════════

// Este objeto se usa en el resto de los módulos del exploit
const OFFSETS_1100 = {{
    // Gadgets
    pop_rdi_ret:   gadget_pop_rdi_ret,
    pop_rsi_ret:   gadget_pop_rsi_ret,
    pop_rdx_ret:   gadget_pop_rdx_ret,
    pop_rcx_ret:   gadget_pop_rcx_ret,
    pop_r8_ret:    gadget_pop_r8_ret,
    pop_r9_ret:    gadget_pop_r9_ret,
    pop_rsp_ret:   gadget_pop_rsp_ret,
    syscall_ret:   gadget_syscall_ret,
    pop_rax_ret:   gadget_pop_rax_ret,

    // pthread
    pthread_stack_addr: pthread_stack_addr,
    pthread_stack_size: pthread_stack_size,
    pthread_size:       pthread_size,
    thread_list:        thread_list,

    // WebKit → libkBase leak
    webkit_got_offset:         webkit_got_leak_offset,
    libkernel_sym_offset:      libkernel_leak_sym_offset,
    worker_ret_offset:         worker_ret_offset,
    worker_stack_size:         worker_stack_size,

    // Kernel
    allproc:       kernel_allproc,
    prison0:       kernel_prison0,
    securelevel:   kernel_securelevel,
    proc_pid:      proc_pid,
    proc_ucred:    proc_ucred,
    ucred_uid:     ucred_uid,
    ucred_ruid:    ucred_ruid,
    ucred_svuid:   ucred_svuid,
    ucred_prison:  ucred_prison,
}};
'''


def build_gadgets_js(gadgets: dict) -> tuple[str, str]:
    lines = []
    missing = []
    for name, val in gadgets.items():
        if val is not None:
            lines.append(f'const {name:<35s} = new Int64(0x0, 0x{val:x});')
        else:
            lines.append(f'const {name:<35s} = null; // ⚠ NO ENCONTRADO — buscar manualmente')
            missing.append(name)
    conf = 'ALTA' if not missing else f'MEDIA ({len(missing)} faltantes)'
    return '\n'.join(lines), conf


def build_symbols_js(symbols: dict) -> tuple[str, str]:
    lines = []
    missing = []
    for name, val in symbols.items():
        key = name.replace('sym_', 'libkernel_')
        if val is not None:
            lines.append(f'const {key:<40s} = new Int64(0x0, 0x{val:x});')
        else:
            lines.append(f'const {key:<40s} = null; // ⚠ VERIFICAR')
            missing.append(key)
    # Para el leak de libkBase: necesitamos thread_list o cualquier símbolo
    if 'thread_list' in symbols and symbols['thread_list']:
        lines.append(f'\nconst thread_list = new Int64(0x0, 0x{symbols["thread_list"]:x});')
    else:
        lines.append(f'\nconst thread_list = null; // ⚠ BUSCAR EN GHIDRA: lista global de pthreads')
    conf = 'ALTA' if not missing else f'MEDIA ({len(missing)} faltantes)'
    return '\n'.join(lines), conf


def build_pthread_js(pthread: dict) -> tuple[str, str]:
    lines = []
    for name, val in pthread.items():
        if val is not None and not isinstance(val, str):
            comment = ' // ⚠ VERIFICAR' if name not in ('worker_stack_size',) else ''
            lines.append(f'const {name:<30s} = 0x{val:x};{comment}')
        else:
            lines.append(f'const {name:<30s} = null; // ⚠ VERIFICAR')
    return '\n'.join(lines), 'MEDIA'


def build_webkit_js(got_candidates: dict, base_info: dict) -> tuple[str, str]:
    lines = []
    # Mejor candidato para el leak
    best_sym = None
    best_got = None
    best_lk  = None
    preferred = ['pthread_create', 'mmap', 'write', 'pthread_self', 'mprotect']
    for p in preferred:
        if p in got_candidates and got_candidates[p]['webkit_got_offset']:
            best_sym = p
            best_got = got_candidates[p]['webkit_got_offset']
            best_lk  = got_candidates[p]['libkernel_sym_offset']
            break

    if best_sym:
        lines.append(f'// Símbolo elegido para leak: {best_sym}')
        lines.append(f'const webkit_got_leak_offset    = new Int64(0x0, 0x{best_got:x});')
        if best_lk:
            lines.append(f'const libkernel_leak_sym_offset = new Int64(0x0, 0x{best_lk:x}); // offset de {best_sym} en libkernel')
            conf = 'ALTA'
        else:
            lines.append(f'const libkernel_leak_sym_offset = null; // ⚠ Ejecutar con --libkernel para calcular')
            conf = 'MEDIA'
    else:
        lines.append('const webkit_got_leak_offset    = null; // ⚠ Analizar WebKit.elf')
        lines.append('const libkernel_leak_sym_offset = null; // ⚠ Analizar libkernel.elf')
        conf = 'BAJA'

    # Todas las entradas GOT como comentario de referencia
    if got_candidates:
        lines.append('\n// Todas las entradas GOT encontradas (referencia):')
        for sym, data in got_candidates.items():
            got = data.get('webkit_got_offset')
            lk  = data.get('libkernel_sym_offset')
            lk_str = f'libk+0x{lk:x}' if lk else '??'
            if got:
                lines.append(f'// GOT[{sym:<25s}] = webkit+0x{got:x}  (libkernel: {lk_str})')

    return '\n'.join(lines), conf


def build_kernel_js(kernel_symbols: dict, kernel_structs: dict) -> tuple[str, str, str]:
    sym_lines = []
    missing = []
    for sym, val in kernel_symbols.items():
        key = f'kernel_{sym}'
        if val is not None:
            sym_lines.append(f'const {key:<30s} = new Int64(0x0, 0x{val:x});')
        else:
            sym_lines.append(f'const {key:<30s} = null; // ⚠ BUSCAR EN GHIDRA')
            missing.append(sym)

    struct_lines = []
    for field, val in kernel_structs.items():
        if val is not None and not isinstance(val, str):
            comment = ' // ⚠ VERIFICAR' if field not in ('proc_list_next', 'ucred_uid', 'ucred_ruid', 'ucred_svuid') else ''
            struct_lines.append(f'const {field:<25s} = 0x{val:x};{comment}')
        else:
            struct_lines.append(f'const {field:<25s} = null; // ⚠ VERIFICAR EN GHIDRA')

    conf_syms    = 'ALTA' if not missing else f'MEDIA ({len(missing)} faltantes)'
    conf_structs = 'MEDIA'
    return '\n'.join(sym_lines), '\n'.join(struct_lines), conf_syms, conf_structs


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Genera offsets_1100.js completo analizando los binarios del FW 11.00',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos:
  # Con los tres binarios (recomendado):
  python3 gen_offsets.py --libkernel libkernel.elf --webkit WebKit.elf --kernel mini-syscore.elf

  # Solo libkernel (mínimo):
  python3 gen_offsets.py --libkernel libkernel.elf

  # Con conversión automática desde SPRX:
  python3 gen_offsets.py --libkernel-sprx libkernel.sprx --webkit-sprx WebKit.sprx
        '''
    )
    ap.add_argument('--libkernel',      help='libkernel.elf (descomprimido)')
    ap.add_argument('--webkit',         help='WebKit.elf (descomprimido)')
    ap.add_argument('--kernel',         help='mini-syscore.elf / kernel.elf')
    ap.add_argument('--libkernel-sprx', help='libkernel.sprx (se convierte automáticamente)')
    ap.add_argument('--webkit-sprx',    help='WebKit.sprx (se convierte automáticamente)')
    ap.add_argument('--kernel-sprx',    help='mini-syscore.elf (suele no estar cifrado)')
    ap.add_argument('--out',     default='offsets_1100.js',  help='Archivo JS de salida')
    ap.add_argument('--tmp',     default='/tmp/ps5_analysis', help='Directorio temporal')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    os.makedirs(args.tmp, exist_ok=True)

    print('╔══════════════════════════════════════════════════════╗')
    print('║  gen_offsets.py — PS5 Toolkit 11.xx                  ║')
    print('║  Generador de offsets_1100.js                         ║')
    print('╚══════════════════════════════════════════════════════╝')

    # Convertir SPRX si hace falta
    libkernel = args.libkernel or convert_if_needed(args.libkernel_sprx, args.tmp)
    webkit    = args.webkit    or convert_if_needed(args.webkit_sprx,    args.tmp)
    kernel    = args.kernel    or convert_if_needed(args.kernel_sprx,    args.tmp)

    if not libkernel:
        print('[ERROR] Se necesita al menos --libkernel libkernel.elf')
        sys.exit(1)

    # ── Ejecutar análisis ──────────────────────────────────────────────────

    libk_json  = os.path.join(args.tmp, 'libkernel_offsets.json')
    webkit_json = os.path.join(args.tmp, 'webkit_offsets.json')
    kernel_json = os.path.join(args.tmp, 'kernel_offsets.json')

    libk_data = run_analyzer('analyze_libkernel.py', libkernel,
                             ['--verbose'] if args.verbose else [],
                             libk_json)

    webkit_data = {}
    if webkit:
        webkit_extra = ['--libkernel', libkernel] if libkernel else []
        if args.verbose:
            webkit_extra.append('--verbose')
        webkit_data = run_analyzer('analyze_webkit.py', webkit, webkit_extra, webkit_json)

    kernel_data = {}
    if kernel:
        kernel_data = run_analyzer('analyze_kernel.py', kernel,
                                  ['--verbose'] if args.verbose else [],
                                  kernel_json)

    # ── Construir JS ───────────────────────────────────────────────────────

    gadgets_js, conf_gadgets = build_gadgets_js(libk_data.get('gadgets', {}))
    symbols_js, conf_symbols = build_symbols_js(libk_data.get('symbols', {}))
    pthread_js, conf_pthread = build_pthread_js(libk_data.get('pthread', {}))
    webkit_js,  conf_got     = build_webkit_js(
        webkit_data.get('got_candidates', {}),
        webkit_data.get('base_info', {})
    )

    kernel_sym_js, kernel_struct_js, conf_ksyms, conf_kstructs = build_kernel_js(
        kernel_data.get('symbols', {}),
        kernel_data.get('structs', {})
    )

    worker_ret = '0x7FB88' if not webkit_data else \
                 webkit_data.get('worker_info', {}).get('worker_ret_offset', '0x7FB88')
    if isinstance(worker_ret, str):
        worker_ret = worker_ret.split()[0]  # limpiar si tiene sufijo explicativo

    js_output = JS_TEMPLATE.format(
        date            = datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
        libkernel_src   = libkernel or 'no analizado',
        webkit_src      = webkit    or 'no analizado',
        kernel_src      = kernel    or 'no analizado',
        conf_gadgets    = conf_gadgets,
        conf_symbols    = conf_symbols,
        conf_pthread    = conf_pthread,
        conf_got        = conf_got,
        conf_kernel_syms    = conf_ksyms    if kernel else 'N/A',
        conf_kernel_structs = conf_kstructs if kernel else 'N/A',
        gadgets_js      = gadgets_js,
        symbols_js      = symbols_js,
        pthread_js      = pthread_js,
        webkit_js       = webkit_js,
        worker_ret_offset = worker_ret,
        kernel_symbols_js = kernel_sym_js  if kernel else '// ⚠ Ejecutar con --kernel para obtener offsets del kernel',
        kernel_structs_js = kernel_struct_js if kernel else '// ⚠ Ejecutar con --kernel',
    )

    with open(args.out, 'w') as f:
        f.write(js_output)

    print(f'\n\n{"="*60}')
    print(f'✓ offsets_1100.js generado: {args.out}')
    print(f'{"="*60}')
    print(f'\nConfianza por sección:')
    print(f'  Gadgets ROP    : {conf_gadgets}')
    print(f'  Símbolos libk  : {conf_symbols}')
    print(f'  pthread        : {conf_pthread}')
    print(f'  WebKit GOT     : {conf_got}')
    if kernel:
        print(f'  Kernel symbols : {conf_ksyms}')
        print(f'  Kernel structs : {conf_kstructs}')

    print(f'\nPróximo paso:')
    print(f'  cp {args.out} ../ps5-toolkit-11xx/exploit/js/offsets_1100.js')
    print(f'\nPara verificar worker_ret_offset en hardware:')
    print(f'  Ver docs/offsets_guide.md → sección "Verificación empírica"')


if __name__ == '__main__':
    main()
