#!/usr/bin/env python3
"""
analyze_webkit.py — Extrae de WebKit.elf los offsets necesarios para:
                    1. leakLibKernelBase() — entrada GOT que apunta a libkernel
                    2. worker_ret_offset   — offset del return address del Worker
                    3. webkit_base_symbol  — símbolo para calcular la base de WebKit

Uso:
    python3 analyze_webkit.py WebKit.elf
    python3 analyze_webkit.py WebKit.elf --libkernel libkernel.elf
    python3 analyze_webkit.py WebKit.elf --json offsets_webkit.json

El script relaciona las entradas GOT de WebKit con los símbolos de libkernel,
de forma que leakLibKernelBase() solo necesita:
  1. Leer un puntero de una dirección GOT conocida (webkit_base + GOT_OFFSET)
  2. Restar el offset del símbolo en libkernel
  → Resultado: libkBase
"""

import subprocess
import sys
import re
import os
import json
import struct
import argparse
from pathlib import Path


# ── Imports de libkernel que buscamos en la GOT de WebKit ─────────────────
# Estos son los que WebKit típicamente importa de libkernel.
# Los mejores candidatos para el leak son funciones que:
# a) WebKit definitivamente llama (siempre presente en GOT)
# b) Tienen un offset estable en libkernel entre versiones menores del FW

LEAK_CANDIDATES = [
    'pthread_create',
    'pthread_self',
    'pthread_mutex_lock',
    'pthread_mutex_unlock',
    'mmap',
    'munmap',
    'mprotect',
    'write',
    'read',
    'open',
    'close',
    'socket',
    'sysctl',
    'getpid',
]


def run(cmd: list[str], timeout: int = 180) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        print(f'[TIMEOUT] {" ".join(cmd[:3])}...')
        return ''
    except FileNotFoundError:
        return ''


# ── Análisis de la GOT de WebKit ──────────────────────────────────────────

def find_got_leak_candidates(webkit_elf: str, libkernel_elf: str = None,
                             verbose: bool = False) -> dict:
    """
    Encuentra en la GOT de WebKit las entradas que apuntan a libkernel.
    Si se provee libkernel.elf, también calcula el offset del símbolo
    para que leakLibKernelBase() pueda calcular libkBase directamente.
    """
    print(f'\n[1/3] Analizando GOT de {Path(webkit_elf).name}...')

    # Obtener relocaciones dinámicas (entradas GOT)
    reloc_out = run(['readelf', '-r', webkit_elf])

    # Formato típico de readelf -r:
    # 000000abcdef  001234000007 R_X86_64_JUMP_SLO 0000000000000000 pthread_create + 0
    reloc_pattern = re.compile(
        r'^\s*([0-9a-f]+)\s+[0-9a-f]+\s+\S+\s+[0-9a-f]+\s+(.+?)(?:\s+\+\s*0)?\s*$',
        re.MULTILINE
    )

    got_map = {}  # sym_name -> got_offset_in_webkit
    for m in reloc_pattern.finditer(reloc_out):
        offset = int(m.group(1), 16)
        sym    = m.group(2).strip()
        # Limpiar nombre (quitar versiones de símbolo @GLIBC etc.)
        sym_clean = re.split(r'@', sym)[0].strip()
        got_map[sym_clean] = offset

    print(f'    Entradas GOT encontradas: {len(got_map)}')

    # Filtrar las que son candidatas para leak de libkernel
    candidates = {}
    for sym in LEAK_CANDIDATES:
        # Búsqueda exacta y parcial
        for gname, goff in got_map.items():
            if sym.lower() == gname.lower() or sym.lower() in gname.lower():
                candidates[sym] = goff
                break

    print(f'    Candidatos para leak de libkBase: {len(candidates)}')

    # Obtener offsets en libkernel para cada candidato (si tenemos el .elf)
    libk_offsets = {}
    if libkernel_elf and os.path.exists(libkernel_elf):
        print(f'    Cruzando con {Path(libkernel_elf).name}...')
        nm_out = run(['nm', '-D', '--defined-only', libkernel_elf])
        nm_pat = re.compile(r'^([0-9a-f]+)\s+[A-Za-z]\s+(.+)$', re.MULTILINE)
        for m in nm_pat.finditer(nm_out):
            addr = int(m.group(1), 16)
            name = m.group(2).strip()
            libk_offsets[name] = addr

    # Construir resultado final
    result = {}
    print(f'\n    {"Símbolo":<30} {"GOT offset en WebKit":<25} {"Offset en libkernel"}')
    print(f'    {"-"*30} {"-"*25} {"-"*22}')

    for sym in LEAK_CANDIDATES:
        if sym not in candidates:
            continue
        got_off = candidates[sym]

        # Offset en libkernel
        lk_off = None
        for lk_name, lk_addr in libk_offsets.items():
            if sym.lower() in lk_name.lower():
                lk_off = lk_addr
                break

        result[sym] = {
            'webkit_got_offset':   got_off,
            'libkernel_sym_offset': lk_off,
        }

        lk_str = f'0x{lk_off:x}' if lk_off else '?? (necesita libkernel.elf)'
        print(f'    {sym:<30} 0x{got_off:<23x} {lk_str}')

    # Seleccionar el mejor candidato
    best = None
    for sym in LEAK_CANDIDATES:
        if sym in result and result[sym]['libkernel_sym_offset'] is not None:
            best = sym
            break
    if best is None and result:
        best = list(result.keys())[0]

    if best:
        print(f'\n    ★ Mejor candidato: {best}')
        print(f'      webkit_got_offset   = 0x{result[best]["webkit_got_offset"]:x}')
        if result[best]['libkernel_sym_offset']:
            print(f'      libkernel_sym_offset = 0x{result[best]["libkernel_sym_offset"]:x}')
        print(f'\n    En leakLibKernelBase():')
        print(f'      const gotAddr = webkitBase.add(new Int64(0x0, 0x{result[best]["webkit_got_offset"]:x}));')
        print(f'      const symPtr  = primitives.read8(gotAddr);')
        if result[best]['libkernel_sym_offset']:
            print(f'      const libkBase = symPtr.sub(new Int64(0x0, 0x{result[best]["libkernel_sym_offset"]:x}));')

    return result


# ── Análisis de WebKit base symbol ────────────────────────────────────────

def find_webkit_base_symbol(webkit_elf: str, verbose: bool = False) -> dict:
    """
    Para construir primitivas de R/W necesitamos saber la base de WebKit
    en memoria. Buscamos un símbolo conocido que esté cerca del inicio
    del segmento .text para poder calcular webkit_base desde el leak
    de cualquier puntero a código de WebKit.
    """
    print(f'\n[2/3] Buscando símbolo de base de WebKit...')

    # El segmento .text comienza en la primera sección ejecutable
    readelf_out = run(['readelf', '-S', webkit_elf])
    text_offset = None

    for line in readelf_out.split('\n'):
        if '.text' in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == '.text' or p.endswith('.text'):
                    try:
                        # La dirección virtual está 2 posiciones después de .text
                        text_offset = int(parts[i+2], 16) if i+2 < len(parts) else None
                        break
                    except (ValueError, IndexError):
                        pass
            if text_offset:
                break

    if text_offset:
        print(f'    .text VMA: 0x{text_offset:x}')
    else:
        print(f'    .text: no encontrado')

    # Obtener la sección LOAD con execute bit para saber el load bias
    ph_out = run(['readelf', '-l', webkit_elf])
    load_bias = 0
    for line in ph_out.split('\n'):
        if 'LOAD' in line and 'R E' in line or ('LOAD' in line and 'RE' in line):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    load_bias = int(parts[2], 16)  # VirtAddr del primer PT_LOAD ejecutable
                    break
                except ValueError:
                    pass

    print(f'    Load bias (primer PT_LOAD exec): 0x{load_bias:x}')

    return {
        'text_vma':   text_offset,
        'load_bias':  load_bias,
    }


# ── Análisis del JavaScriptCore para el Worker ────────────────────────────

def find_worker_hints(webkit_elf: str, verbose: bool = False) -> dict:
    """
    Busca pistas sobre el Web Worker en WebKit:
    - Tamaño del stack del Worker (debe ser 0x80000 para filtrarlo)
    - Función MessageEvent handler (donde vive el return address)
    - Strings relacionados con JSC WorkerThread
    """
    print(f'\n[3/3] Analizando hints del Web Worker...')

    # Strings relacionados con Workers en el binario
    strings_out = run(['strings', '-a', '-n', '10', webkit_elf])
    worker_strings = []
    for line in strings_out.split('\n'):
        if any(x in line.lower() for x in ['worker', 'jsworkerglobals', 'workerthread',
                                             'messageevent', 'postmessage', 'workerclient']):
            worker_strings.append(line.strip())

    if worker_strings:
        print(f'    Strings relacionados con Worker:')
        for s in worker_strings[:15]:
            print(f'      "{s}"')
    else:
        print(f'    No se encontraron strings de Worker (pueden estar ofuscados)')

    # Buscar el stack size del Worker en el disassembly
    # WebKit crea el stack del Worker con un tamaño fijo, normalmente 0x80000
    asm_out = run(['objdump', '-d', webkit_elf])
    stack_size_candidates = []
    for line in asm_out.split('\n'):
        if '0x80000' in line or '524288' in line:
            m = re.search(r'0x80000', line)
            if m:
                # Extraer la dirección de la instrucción
                addr_m = re.match(r'^\s*([0-9a-f]+):', line)
                if addr_m:
                    stack_size_candidates.append({
                        'addr': int(addr_m.group(1), 16),
                        'line': line.strip()
                    })

    if stack_size_candidates:
        print(f'\n    Referencias a 0x80000 (worker stack size): {len(stack_size_candidates)}')
        if verbose:
            for c in stack_size_candidates[:5]:
                print(f'      0x{c["addr"]:x}: {c["line"]}')
    else:
        print(f'\n    No se encontraron referencias directas a 0x80000')

    # worker_ret_offset: no se puede determinar estáticamente de forma fiable
    # pero podemos estimar la profundidad del stack frame del message handler
    print(f'\n    worker_ret_offset: requiere verificación empírica en hardware.')
    print(f'    Valor actual en offsets_1100.js (0x7FB88) basado en versiones previas.')
    print(f'    Para verificarlo: usar findWorkerRetOffset() una vez el bug esté activo.')

    return {
        'worker_stack_size':    0x80000,
        'worker_strings_found': worker_strings[:5],
        'worker_ret_offset':    '0x7FB88 (VERIFICAR EN HARDWARE)',
    }


# ── Generador JS ──────────────────────────────────────────────────────────

def generate_js_fragment(got_result: dict, base_result: dict) -> str:
    lines = ['// ── WebKit offsets (FW 11.00) ──────────────────────────────']
    lines.append('// Generado automáticamente por analyze_webkit.py')
    lines.append('')

    # Mejor candidato para el leak
    candidates_with_lk = {k: v for k, v in got_result.items()
                          if v['libkernel_sym_offset'] is not None}
    if candidates_with_lk:
        best_sym = list(candidates_with_lk.keys())[0]
        best = candidates_with_lk[best_sym]
        lines.append(f'// Leak de libkBase vía GOT[{best_sym}]')
        lines.append(f'const webkit_got_libkernel_sym   = new Int64(0x0, 0x{best["webkit_got_offset"]:x});')
        lines.append(f'const libkernel_{best_sym}_offset = new Int64(0x0, 0x{best["libkernel_sym_offset"]:x});')
    else:
        lines.append('// GOT offsets — completar con analyze_libkernel.py')
        for sym, data in got_result.items():
            lines.append(f'// GOT[{sym}] = 0x{data["webkit_got_offset"]:x}')

    lines.append('')
    if base_result.get('load_bias'):
        lines.append(f'const webkit_load_bias = new Int64(0x0, 0x{base_result["load_bias"]:x});')

    return '\n'.join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

def analyze(webkit_elf: str, libkernel_elf: str = None,
            verbose: bool = False, json_out: str = None):

    print(f'╔══════════════════════════════════════════════════════╗')
    print(f'║  analyze_webkit.py — PS5 Toolkit 11.xx               ║')
    print(f'╚══════════════════════════════════════════════════════╝')
    print(f'WebKit:    {webkit_elf}')
    if libkernel_elf:
        print(f'libkernel: {libkernel_elf}')

    if not os.path.exists(webkit_elf):
        print(f'[ERROR] No se encuentra: {webkit_elf}')
        sys.exit(1)

    with open(webkit_elf, 'rb') as f:
        magic = f.read(4)
    if magic == b'\x4fSCE':
        print('[WARN] Es un SELF — ejecuta self2elf.py primero')
        sys.exit(1)

    got_result  = find_got_leak_candidates(webkit_elf, libkernel_elf, verbose)
    base_result = find_webkit_base_symbol(webkit_elf, verbose)
    worker_info = find_worker_hints(webkit_elf, verbose)

    result = {
        'source_webkit':   webkit_elf,
        'source_libkernel': libkernel_elf,
        'got_candidates':  got_result,
        'base_info':       base_result,
        'worker_info':     worker_info,
    }

    print('\n\n' + '='*60)
    print('FRAGMENTO PARA offsets_1100.js (sección WebKit):')
    print('='*60)
    print(generate_js_fragment(got_result, base_result))

    if json_out:
        with open(json_out, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f'\n[OK] Guardado en {json_out}')

    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description='Analiza WebKit.elf para offsets de leakLibKernelBase y Worker'
    )
    ap.add_argument('webkit', help='Ruta a WebKit.elf')
    ap.add_argument('--libkernel', help='Ruta a libkernel.elf (para cruzar símbolos)')
    ap.add_argument('--json',    help='Guardar resultado en JSON')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    analyze(args.webkit, args.libkernel, args.verbose, args.json)
