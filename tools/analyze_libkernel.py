#!/usr/bin/env python3
"""
analyze_libkernel.py — Extrae automáticamente todos los offsets de libkernel.elf
                       necesarios para offsets_1100.js

Uso:
    python3 analyze_libkernel.py libkernel.elf
    python3 analyze_libkernel.py libkernel.elf --json offsets_libkernel.json
    python3 analyze_libkernel.py libkernel.elf --verbose

Extrae:
    - Gadgets ROP: pop rdi/rsi/rdx/rcx/r8/r9, pop rsp, syscall, etc.
    - Offsets de símbolos: pthread_create, mmap, munmap, mprotect, socket, etc.
    - Offsets de pthread_t: stack_addr, stack_size (para findWorkerStack)
    - thread_list: puntero global a la lista de pthreads del proceso
"""

import subprocess
import sys
import re
import struct
import json
import argparse
from pathlib import Path


# ── Gadgets que necesitamos ─────────────────────────────────────────────────

# Cada entrada: (nombre_en_offsets_js, patron_regex_en_objdump)
GADGETS_NEEDED = [
    # Para llamadas ROP con argumentos (ABI SysV AMD64)
    ('gadget_pop_rdi_ret',   r'pop\s+%rdi\s*$\s*.*ret\s*$'),
    ('gadget_pop_rsi_ret',   r'pop\s+%rsi\s*$\s*.*ret\s*$'),
    ('gadget_pop_rdx_ret',   r'pop\s+%rdx\s*$\s*.*ret\s*$'),
    ('gadget_pop_rcx_ret',   r'pop\s+%rcx\s*$\s*.*ret\s*$'),
    ('gadget_pop_r8_ret',    r'pop\s+%r8\s*$\s*.*ret\s*$'),
    ('gadget_pop_r9_ret',    r'pop\s+%r9\s*$\s*.*ret\s*$'),
    # Para el stack pivot (el más crítico)
    ('gadget_pop_rsp_ret',   r'pop\s+%rsp\s*$\s*.*ret\s*$'),
    # Para syscalls desde ROP
    ('gadget_syscall_ret',   r'syscall\s*$\s*.*ret\s*$'),
    # Utilidades
    ('gadget_pop_rax_ret',   r'pop\s+%rax\s*$\s*.*ret\s*$'),
    ('gadget_ret',           r'^\s*ret\s*$'),
    ('gadget_pop_rdi_pop_rsi_ret', r'pop\s+%rdi.*pop\s+%rsi.*ret'),
    ('gadget_xchg_rax_rsp',  r'xchg\s+%rax,%rsp'),
]

# Símbolos que necesitamos (para el leak de libkBase desde WebKit GOT)
SYMBOLS_NEEDED = [
    'pthread_create',
    'pthread_join',
    'pthread_self',
    'mmap',
    'munmap',
    'mprotect',
    'socket',
    'connect',
    'write',
    'read',
    'close',
    'fork',
    'open',
    'sysctl',
    'ptrace',
    'kill',
    'getpid',
    'pipe',
    'pipe2',
    'umtx_op',
    '_umtx_op',
]

# Símbolos para encontrar thread_list (lista global de pthreads)
THREAD_LIST_HINTS = [
    '_thread_list',
    '_pthread_list',
    '__pthread_list',
    'curthread',
    '_curthread',
]


# ── Ejecutor de comandos ───────────────────────────────────────────────────

def run(cmd: list[str]) -> str:
    """Ejecuta un comando y retorna stdout como string."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return ''
    except FileNotFoundError:
        print(f'[ERROR] Comando no encontrado: {cmd[0]}')
        return ''


# ── Análisis de gadgets ROP ────────────────────────────────────────────────

def find_gadgets(elf_path: str, verbose: bool = False) -> dict:
    """
    Busca gadgets ROP en el binario usando objdump.
    Estrategia: disassemble todo, buscar secuencias útiles.
    """
    print(f'\n[1/4] Buscando gadgets ROP en {Path(elf_path).name}...')

    # Obtener el disassembly completo del segmento .text
    asm = run(['objdump', '-d', '-M', 'att', elf_path])
    if not asm:
        print('[ERROR] objdump falló o no está disponible')
        return {}

    # Dividir en líneas con sus direcciones
    lines = asm.split('\n')
    addr_pattern = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s+(.+)$')

    # Construir lista de (addr, instrucción)
    instrs = []
    for line in lines:
        m = addr_pattern.match(line)
        if m:
            addr = int(m.group(1), 16)
            instr = m.group(2).strip().lower()
            instrs.append((addr, instr))

    print(f'    Instrucciones encontradas: {len(instrs):,}')

    gadgets = {}

    # Búsqueda de gadgets específicos (ventana de 1-4 instrucciones)
    for name, pattern in GADGETS_NEEDED:
        found = []
        for i, (addr, instr) in enumerate(instrs):
            # Ventana: instrucción actual + 3 siguientes
            window_instrs = [ins for _, ins in instrs[i:i+4]]
            window_text = ' | '.join(window_instrs)

            # pop rdi ; ret (2 instrucciones)
            if name == 'gadget_pop_rdi_ret':
                if 'pop' in instr and '%rdi' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_rsi_ret':
                if 'pop' in instr and '%rsi' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_rdx_ret':
                if 'pop' in instr and '%rdx' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_rcx_ret':
                if 'pop' in instr and '%rcx' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_r8_ret':
                if 'pop' in instr and '%r8' in instr and '%r8d' not in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_r9_ret':
                if 'pop' in instr and '%r9' in instr and '%r9d' not in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_rsp_ret':
                if 'pop' in instr and '%rsp' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_syscall_ret':
                if instr.startswith('syscall'):
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_pop_rax_ret':
                if 'pop' in instr and '%rax' in instr:
                    if i+1 < len(instrs) and instrs[i+1][1].startswith('ret'):
                        found.append(addr)

            elif name == 'gadget_ret':
                if instr.strip() == 'ret':
                    found.append(addr)

            elif name == 'gadget_xchg_rax_rsp':
                if 'xchg' in instr and 'rax' in instr and 'rsp' in instr:
                    found.append(addr)

        if found:
            # Preferir el primer gadget encontrado (más estable en librerías)
            gadgets[name] = found[0]
            status = f'✓ 0x{found[0]:x}'
            if len(found) > 1 and verbose:
                status += f'  ({len(found)} candidatos)'
        else:
            gadgets[name] = None
            status = '✗ NO ENCONTRADO'

        print(f'    {name:<35s} {status}')

    return gadgets


# ── Análisis de símbolos ───────────────────────────────────────────────────

def find_symbols(elf_path: str, verbose: bool = False) -> dict:
    """Extrae offsets de símbolos usando nm y readelf."""
    print(f'\n[2/4] Extrayendo símbolos de {Path(elf_path).name}...')

    # nm da la tabla de símbolos
    nm_out = run(['nm', '-D', '--defined-only', elf_path])
    if not nm_out:
        nm_out = run(['nm', '--defined-only', elf_path])

    symbols = {}
    sym_pattern = re.compile(r'^([0-9a-f]+)\s+[A-Za-z]\s+(.+)$', re.MULTILINE)

    for m in sym_pattern.finditer(nm_out):
        addr = int(m.group(1), 16)
        name = m.group(2).strip()
        symbols[name] = addr

    results = {}
    for sym in SYMBOLS_NEEDED:
        # Buscar el símbolo exacto o con prefijos típicos de PS5 (sceKernel, _)
        candidates = [
            sym,
            f'_{sym}',
            f'sceKernel{sym[0].upper() + sym[1:]}',
            f'__sys_{sym}',
        ]
        found = None
        for c in candidates:
            if c in symbols:
                found = symbols[c]
                break
        # Búsqueda parcial si no se encontró exacto
        if found is None:
            for s_name, s_addr in symbols.items():
                if sym.lower() in s_name.lower():
                    found = s_addr
                    break

        results[f'sym_{sym}'] = found
        status = f'✓ 0x{found:x}' if found else '✗ no encontrado'
        print(f'    {sym:<35s} {status}')

    # thread_list: símbolo global especial
    print(f'\n    Buscando thread_list...')
    for hint in THREAD_LIST_HINTS:
        if hint in symbols:
            results['thread_list'] = symbols[hint]
            print(f'    thread_list ({hint}): ✓ 0x{symbols[hint]:x}')
            break
    else:
        # Búsqueda por strings
        results['thread_list'] = None
        print(f'    thread_list: no encontrado por símbolo (se intentará vía strings)')

    return results


# ── Análisis de estructura pthread_t ──────────────────────────────────────

def find_pthread_offsets(elf_path: str, verbose: bool = False) -> dict:
    """
    Intenta encontrar los offsets de campos clave en la estructura pthread_t.
    Estrategia: analizar pthread_create y pthread_attr_getstack para
    identificar los accesos al campo stack_addr y stack_size.
    """
    print(f'\n[3/4] Analizando estructura pthread_t...')

    asm = run(['objdump', '-d', '-M', 'att', elf_path])
    lines = asm.split('\n')

    # Buscamos la función pthread_getattr_np o pthread_attr_getstack
    # que típicamente accede a los campos de stack directamente
    in_target = False
    target_addrs = []
    current_func = ''

    mem_accesses = []  # (offset_en_struct, tipo_acceso)

    for i, line in enumerate(lines):
        # Detectar inicio de función
        func_match = re.match(r'^([0-9a-f]+)\s+<(.+)>:$', line)
        if func_match:
            current_func = func_match.group(2)
            in_target = any(x in current_func.lower() for x in
                           ['pthread_attr_getstack', 'pthread_attr_getstacksize',
                            'pthread_attr_getstackaddr', 'thr_self'])
            continue

        if not in_target:
            continue

        # Buscar accesos a memoria que parezcan [struct + offset]
        # Patrón: movq/movl 0xXX(%reg), %reg
        mem_match = re.search(r'(0x[0-9a-f]+)\((%r\w+)\)', line)
        if mem_match:
            offset_str = mem_match.group(1)
            reg = mem_match.group(2)
            try:
                offset = int(offset_str, 16)
                mem_accesses.append(offset)
            except ValueError:
                pass

    results = {}

    # Heurística: en libpthread/libc de FreeBSD, los campos típicos son:
    # pthread_t->stack_addr ~ offset 0x60-0x90
    # pthread_t->stack_size ~ offset 0x68-0x98
    # (varían por versión del SDK de PS5)

    # Si encontramos accesos en ese rango, reportarlos como candidatos
    stack_candidates = [o for o in set(mem_accesses) if 0x40 <= o <= 0xC0]

    if len(stack_candidates) >= 2:
        stack_candidates.sort()
        results['pthread_stack_addr'] = stack_candidates[0]
        results['pthread_stack_size'] = stack_candidates[1] if len(stack_candidates) > 1 else None
        print(f'    pthread_stack_addr (candidato): 0x{stack_candidates[0]:x}')
        if results['pthread_stack_size']:
            print(f'    pthread_stack_size (candidato): 0x{stack_candidates[1]:x}')
    else:
        # Valores conocidos de FreeBSD 11 / PS4 como fallback
        results['pthread_stack_addr'] = 0x80
        results['pthread_stack_size'] = 0x88
        print(f'    pthread_stack_addr: usando valor FreeBSD11 conocido (0x80) — VERIFICAR')
        print(f'    pthread_stack_size: usando valor FreeBSD11 conocido (0x88) — VERIFICAR')

    # pthread_size: tamaño total de la estructura
    # Buscar en pthread_create: el argumento de malloc/calloc
    results['pthread_size'] = None
    alloc_pattern = re.compile(r'mov[ql]?\s+\$(0x[0-9a-f]+),')
    in_create = False
    for line in lines:
        if re.match(r'^[0-9a-f]+\s+<.*pthread_create.*>:', line):
            in_create = True
        elif re.match(r'^[0-9a-f]+\s+<', line):
            in_create = False
        if in_create:
            m = alloc_pattern.search(line)
            if m:
                val = int(m.group(1), 16)
                if 0x100 <= val <= 0x400:  # tamaño razonable para pthread_t
                    results['pthread_size'] = val
                    break

    if results['pthread_size']:
        print(f'    pthread_size: 0x{results["pthread_size"]:x}')
    else:
        results['pthread_size'] = 0x280  # valor típico PS5
        print(f'    pthread_size: usando valor típico (0x280) — VERIFICAR')

    return results


# ── Análisis de GOT (para el leak de libkBase desde WebKit) ───────────────

def find_got_entries(elf_path: str, verbose: bool = False) -> dict:
    """
    Extrae las entradas de la GOT que son candidatas para el leak de libkBase.
    Retorna los offsets de las entradas GOT de funciones conocidas.
    """
    print(f'\n[4/4] Analizando GOT para leak de libkBase...')

    # readelf -r muestra las relocaciones (que incluyen entradas GOT)
    reloc_out = run(['readelf', '-r', elf_path])
    dyn_out   = run(['readelf', '-d', elf_path])

    got_entries = {}
    # Formato: offset  info  type  sym_value  sym_name + addend
    reloc_pattern = re.compile(
        r'^\s*([0-9a-f]+)\s+[0-9a-f]+\s+\S+\s+[0-9a-f]+\s+(.+?)(?:\s+\+\s*[0-9a-f]+)?\s*$',
        re.MULTILINE
    )

    for m in reloc_pattern.finditer(reloc_out):
        got_off = int(m.group(1), 16)
        sym_name = m.group(2).strip()
        if any(s in sym_name for s in ['pthread', 'mmap', 'mprotect', 'write', 'read', 'socket']):
            got_entries[f'got_{sym_name}'] = got_off
            if verbose:
                print(f'    GOT[{sym_name}] = 0x{got_off:x}')

    # Mejor candidato para el leak (mmap o pthread_create suelen ser estables)
    preferred = ['pthread_create', 'mmap', 'write', 'mprotect']
    leak_candidate = None
    for p in preferred:
        key = f'got_{p}'
        if key in got_entries:
            leak_candidate = (p, got_entries[key])
            break

    if leak_candidate:
        print(f'    Mejor candidato para libkBase leak: GOT[{leak_candidate[0]}] @ 0x{leak_candidate[1]:x}')
    else:
        print(f'    No se encontraron entradas GOT útiles — puede que sea el propio libkernel')
        print(f'    (En libkernel.elf no hay GOT externa; las GOT relevantes están en WebKit.elf)')

    return got_entries


# ── Generador de resultado ─────────────────────────────────────────────────

def analyze(elf_path: str, verbose: bool = False, json_out: str = None):
    """Función principal: analiza libkernel.elf y retorna todos los offsets."""

    print(f'╔══════════════════════════════════════════════════════╗')
    print(f'║  analyze_libkernel.py — PS5 Toolkit 11.xx            ║')
    print(f'╚══════════════════════════════════════════════════════╝')
    print(f'Archivo: {elf_path}')

    # Verificación básica
    import os
    if not os.path.exists(elf_path):
        print(f'[ERROR] Archivo no encontrado: {elf_path}')
        sys.exit(1)

    with open(elf_path, 'rb') as f:
        magic = f.read(4)

    if magic == b'\x4fSCE':
        print('[WARN] El archivo es un SELF — ejecuta self2elf.py primero')
        print('       python3 self2elf.py libkernel.sprx libkernel.elf')
        sys.exit(1)

    if magic != b'\x7fELF':
        print(f'[ERROR] No es un ELF válido (magic: {magic.hex()})')
        sys.exit(1)

    gadgets = find_gadgets(elf_path, verbose)
    symbols = find_symbols(elf_path, verbose)
    pthread = find_pthread_offsets(elf_path, verbose)
    got     = find_got_entries(elf_path, verbose)

    result = {
        'source_file': elf_path,
        'gadgets':     gadgets,
        'symbols':     symbols,
        'pthread':     pthread,
        'got':         got,
    }

    # Generar fragmento de JavaScript para offsets_1100.js
    print('\n\n' + '='*60)
    print('FRAGMENTO PARA offsets_1100.js (sección libkernel):')
    print('='*60)

    js = generate_js_fragment(gadgets, symbols, pthread)
    print(js)

    if json_out:
        with open(json_out, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f'\n[OK] Resultado guardado en {json_out}')

    return result


def generate_js_fragment(gadgets: dict, symbols: dict, pthread: dict) -> str:
    """Genera el fragmento JS para pegar en offsets_1100.js."""
    lines = ['// ── libkernel.sprx offsets (FW 11.00) ──────────────────────']
    lines.append('// Generado automáticamente por analyze_libkernel.py')
    lines.append('')
    lines.append('// Gadgets ROP')

    for name, val in gadgets.items():
        val_str = f'0x{val:x}' if val is not None else 'null /* NO ENCONTRADO */'
        lines.append(f'const {name} = new Int64(0x0, {val_str});')

    lines.append('')
    lines.append('// Símbolos de libkernel (offsets desde la base)')

    for name, val in symbols.items():
        val_str = f'0x{val:x}' if val is not None else 'null /* NO ENCONTRADO */'
        lines.append(f'const {name} = new Int64(0x0, {val_str});')

    lines.append('')
    lines.append('// Estructura pthread_t')
    for name, val in pthread.items():
        val_str = f'0x{val:x}' if val is not None else 'null'
        lines.append(f'const {name} = {val_str};')

    return '\n'.join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description='Analiza libkernel.elf y extrae offsets para offsets_1100.js'
    )
    ap.add_argument('elf', help='Ruta a libkernel.elf (descomprimido con self2elf.py)')
    ap.add_argument('--json',    help='Guardar resultado en JSON')
    ap.add_argument('--verbose', action='store_true', help='Mostrar más detalles')
    args = ap.parse_args()

    analyze(args.elf, verbose=args.verbose, json_out=args.json)
