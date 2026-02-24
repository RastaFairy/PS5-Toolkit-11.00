#!/usr/bin/env python3
"""
analyze_kernel.py — Extrae offsets del kernel de PS5 (mini-syscore.elf / kernel.elf)

Busca:
  - allproc:      lista enlazada de todos los procesos
  - kern.securelevel: para desactivar protecciones
  - proc->p_ucred: offset del campo ucred dentro de proc
  - ucred->cr_uid:    offset de uid en ucred
  - ucred->cr_prison: offset del puntero jail en ucred
  - prison0:      símbolo del jail raíz del kernel

Uso:
    python3 analyze_kernel.py kernel.elf
    python3 analyze_kernel.py mini-syscore.elf --json kernel_offsets.json
"""

import subprocess
import sys
import re
import os
import json
import argparse
from pathlib import Path


def run(cmd: list[str], timeout: int = 300) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


# ── Símbolos del kernel que necesitamos ───────────────────────────────────

KERNEL_SYMBOLS = [
    'allproc',
    'prison0',
    'kern_securelevel',
    'securelevel',
    'rootvnode',
    'nproc',
    'cpuinfo',
    'cpu_features',
    'cpu_features2',
]

# Offsets de estructuras (FreeBSD 11 base, PS5 puede diferir)
# struct proc:
#   p_list      → +0x00 (LIST_ENTRY, next/prev)
#   p_pid       → +0x80 (pid_t)
#   p_ucred     → ?     (struct ucred *)
#   p_comm      → ?     (char[MAXCOMLEN+1])
# struct ucred:
#   cr_uid      → +0x04
#   cr_ruid     → +0x08
#   cr_svuid    → +0x0c
#   cr_prison   → ?


def find_kernel_symbols(kernel_elf: str, verbose: bool = False) -> dict:
    """Extrae símbolos del kernel usando nm/readelf."""
    print(f'\n[1/3] Extrayendo símbolos del kernel...')

    nm_out = run(['nm', kernel_elf])
    if not nm_out:
        nm_out = run(['nm', '--defined-only', kernel_elf])

    sym_pat = re.compile(r'^([0-9a-f]+)\s+[A-Za-z]\s+(.+)$', re.MULTILINE)
    all_syms = {}
    for m in sym_pat.finditer(nm_out):
        all_syms[m.group(2).strip()] = int(m.group(1), 16)

    print(f'    Símbolos totales: {len(all_syms):,}')

    results = {}
    for sym in KERNEL_SYMBOLS:
        found = None
        # Búsqueda exacta
        for name, addr in all_syms.items():
            if name == sym or name == f'_{sym}' or f'__{sym}' == name:
                found = addr
                break
        # Búsqueda parcial
        if found is None:
            for name, addr in all_syms.items():
                if sym.lower() in name.lower():
                    found = addr
                    break

        results[sym] = found
        status = f'✓ 0x{found:x}' if found else '✗ no encontrado'
        print(f'    {sym:<30s} {status}')

    return results


def find_struct_offsets(kernel_elf: str, verbose: bool = False) -> dict:
    """
    Intenta determinar los offsets de campos clave en proc y ucred
    analizando funciones del kernel que acceden a esos campos.
    """
    print(f'\n[2/3] Buscando offsets de estructuras proc y ucred...')

    asm = run(['objdump', '-d', kernel_elf])
    lines = asm.split('\n')

    results = {
        'proc_pid':     None,
        'proc_ucred':   None,
        'proc_comm':    None,
        'proc_list_next': 0x00,  # siempre es el primer campo en FreeBSD
        'ucred_uid':    None,
        'ucred_ruid':   None,
        'ucred_prison': None,
    }

    # Buscar funciones relevantes
    target_funcs = {
        'pfind':         ['proc_pid', 'proc_list_next'],
        'crfree':        ['ucred_uid'],
        'prison_free':   ['ucred_prison'],
        'proc_getcomm':  ['proc_comm'],
    }

    current_func = ''
    func_instrs = []
    all_funcs = {}

    for line in lines:
        func_m = re.match(r'^([0-9a-f]+)\s+<(.+)>:$', line)
        if func_m:
            if current_func and func_instrs:
                all_funcs[current_func] = func_instrs
            current_func = func_m.group(2)
            func_instrs = []
        else:
            instr_m = re.match(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s+(.+)$', line)
            if instr_m:
                func_instrs.append((int(instr_m.group(1), 16), instr_m.group(2).strip()))

    # Analizar pfind — típicamente hace comparación de PID
    # busca: cmp   [reg + OFFSET], pid_value → ese OFFSET es proc->p_pid
    proc_pid_candidates = []
    for fname, instrs in all_funcs.items():
        if 'pfind' in fname.lower() or 'proc_find' in fname.lower():
            for addr, instr in instrs:
                # Accesos a campo positivo dentro de una estructura
                m = re.search(r'(0x[0-9a-f]+)\(%r\w+\)', instr)
                if m:
                    off = int(m.group(1), 16)
                    if 0x78 <= off <= 0x90:  # PID suele estar aquí en FreeBSD
                        proc_pid_candidates.append(off)

    if proc_pid_candidates:
        from collections import Counter
        most_common = Counter(proc_pid_candidates).most_common(1)[0][0]
        results['proc_pid'] = most_common
        print(f'    proc->p_pid    : ✓ 0x{most_common:x} (candidato)')
    else:
        results['proc_pid'] = 0x80  # valor típico FreeBSD 11
        print(f'    proc->p_pid    : usando valor FreeBSD11 (0x80) — VERIFICAR')

    # proc->p_ucred: buscar en fork1 o similar
    ucred_candidates = []
    for fname, instrs in all_funcs.items():
        if any(x in fname.lower() for x in ['fork', 'exec', 'cred']):
            for addr, instr in instrs:
                m = re.search(r'(0x[0-9a-f]+)\(%r\w+\)', instr)
                if m:
                    off = int(m.group(1), 16)
                    if 0x100 <= off <= 0x200:
                        ucred_candidates.append(off)

    if ucred_candidates:
        from collections import Counter
        most_common = Counter(ucred_candidates).most_common(1)[0][0]
        results['proc_ucred'] = most_common
        print(f'    proc->p_ucred  : ✓ 0x{most_common:x} (candidato)')
    else:
        results['proc_ucred'] = 0x170  # valor típico PS4/PS5
        print(f'    proc->p_ucred  : usando valor PS4/PS5 conocido (0x170) — VERIFICAR')

    # ucred offsets (más estables en FreeBSD)
    results['ucred_uid']    = 0x04
    results['ucred_ruid']   = 0x08
    results['ucred_svuid']  = 0x0c
    results['ucred_prison'] = 0x30  # puede variar — VERIFICAR

    print(f'    ucred->cr_uid  : 0x04 (estándar FreeBSD)')
    print(f'    ucred->cr_ruid : 0x08 (estándar FreeBSD)')
    print(f'    ucred->cr_prison: 0x30 (típico PS5) — VERIFICAR')

    return results


def find_cpu_features(kernel_elf: str, verbose: bool = False) -> dict:
    """Busca los offsets de cpu_features para deshabilitar SCEP."""
    print(f'\n[3/3] Buscando cpu_features...')

    # Buscar strings relacionados con CPU features
    strings_out = run(['strings', '-a', '-n', '8', kernel_elf])
    cpu_hints = [l for l in strings_out.split('\n')
                 if any(x in l.lower() for x in ['scep', 'cpu_feat', 'cpuid', 'smep', 'smap'])]

    if cpu_hints:
        print(f'    Strings CPU: {cpu_hints[:5]}')
    else:
        print(f'    No se encontraron strings de CPU features')

    return {
        'cpu_features_note': 'VERIFICAR con Ghidra — buscar función que configure SMEP/SMAP/SCEP'
    }


def generate_js_fragment(symbols: dict, structs: dict) -> str:
    lines = ['// ── Kernel offsets (FW 11.00) ─────────────────────────────']
    lines.append('// Generado automáticamente por analyze_kernel.py')
    lines.append('')
    lines.append('// Símbolos del kernel (offsets desde kbase)')
    for sym, val in symbols.items():
        val_str = f'0x{val:x}' if val else 'null /* NO ENCONTRADO — buscar con Ghidra */'
        lines.append(f'const kernel_{sym} = new Int64(0x0, {val_str});')
    lines.append('')
    lines.append('// Offsets de estructuras')
    for field, val in structs.items():
        val_str = f'0x{val:x}' if val else 'null'
        comment = ' // VERIFICAR' if 'VERIFICAR' not in str(val) else ''
        lines.append(f'const {field} = {val_str};{comment}')
    return '\n'.join(lines)


def analyze(kernel_elf: str, verbose: bool = False, json_out: str = None):
    print(f'╔══════════════════════════════════════════════════════╗')
    print(f'║  analyze_kernel.py — PS5 Toolkit 11.xx               ║')
    print(f'╚══════════════════════════════════════════════════════╝')
    print(f'Kernel: {kernel_elf}')

    if not os.path.exists(kernel_elf):
        print(f'[ERROR] No se encuentra: {kernel_elf}')
        sys.exit(1)

    symbols = find_kernel_symbols(kernel_elf, verbose)
    structs = find_struct_offsets(kernel_elf, verbose)
    cpu     = find_cpu_features(kernel_elf, verbose)

    result = {'symbols': symbols, 'structs': structs, 'cpu': cpu}

    print('\n\n' + '='*60)
    print('FRAGMENTO PARA offsets_1100.js (sección kernel):')
    print('='*60)
    print(generate_js_fragment(symbols, structs))

    if json_out:
        with open(json_out, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f'\n[OK] Guardado en {json_out}')

    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Analiza el kernel ELF de PS5')
    ap.add_argument('kernel', help='Ruta a mini-syscore.elf o kernel.elf')
    ap.add_argument('--json',    help='Guardar en JSON')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    analyze(args.kernel, args.verbose, args.json)
