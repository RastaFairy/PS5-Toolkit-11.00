#!/usr/bin/env python3
"""
self2elf.py — Descomprime binarios SELF/SPRX de PS5 a ELF puro
              (variante sin cifrado, para dumps extraídos con acceso kernel)

Uso:
    python3 self2elf.py input.sprx output.elf
    python3 self2elf.py --dir /path/to/priv/lib/ --out /path/to/elfs/
    python3 self2elf.py --check input.sprx       # Solo verifica si es SELF válido

El formato SELF de PS5 es una envoltura sobre ELF64 con:
  - Cabecera SELF (0x20 bytes) + segmentos de metadatos
  - El ELF real embebido después del header_size indicado en la cabecera

Para dumps no cifrados (extraídos directamente de la PS5 jailbroken),
el ELF está accesible directamente sin necesitar claves de descifrado.
"""

import sys
import os
import struct
import argparse
from pathlib import Path


# ── Constantes del formato SELF ────────────────────────────────────────────

SELF_MAGIC       = b'\x4fSCE'  # "OSCE" — magic de todos los SELF/SPRX de Sony
ELF_MAGIC        = b'\x7fELF'  # magic de ELF estándar
SELF_HEADER_SIZE = 0x20        # tamaño mínimo de la cabecera SELF

# Offsets dentro de la cabecera SELF (little-endian)
# struct SCE_header {
#   uint32_t magic;           // +0x00: 0x4F534345 "OSCE"
#   uint32_t unk1;            // +0x04
#   uint16_t file_category;   // +0x08: 1=SELF, 2=PFS
#   uint16_t num_segments;    // +0x0A: número de segmentos de metadatos
#   uint64_t header_size;     // +0x10: offset donde empieza el ELF interno
# }
OFF_MAGIC         = 0x00
OFF_FILE_CATEGORY = 0x08
OFF_NUM_SEGMENTS  = 0x0A
OFF_HEADER_SIZE   = 0x10


# ── Parser ─────────────────────────────────────────────────────────────────

class SelfParser:
    def __init__(self, data: bytes):
        self.data = data
        self.magic         = data[OFF_MAGIC:OFF_MAGIC+4]
        self.file_category = struct.unpack_from('<H', data, OFF_FILE_CATEGORY)[0]
        self.num_segments  = struct.unpack_from('<H', data, OFF_NUM_SEGMENTS)[0]
        self.header_size   = struct.unpack_from('<Q', data, OFF_HEADER_SIZE)[0]

    def is_self(self) -> bool:
        return self.magic == SELF_MAGIC

    def is_encrypted(self) -> bool:
        """Comprueba si el ELF interno está cifrado.
        En dumps de PS5 jailbroken, el ELF está en claro.
        El indicador es si los bytes en header_size son un ELF válido."""
        if self.header_size >= len(self.data):
            return True
        return self.data[self.header_size:self.header_size+4] != ELF_MAGIC

    def extract_elf(self) -> bytes | None:
        """Extrae el ELF embebido dentro del SELF."""
        if not self.is_self():
            return None
        if self.is_encrypted():
            return None
        return self.data[self.header_size:]

    def info(self) -> dict:
        return {
            'magic':         self.magic.hex(),
            'file_category': self.file_category,
            'num_segments':  self.num_segments,
            'header_size':   hex(self.header_size),
            'is_self':       self.is_self(),
            'is_encrypted':  self.is_encrypted() if self.is_self() else 'N/A',
            'total_size':    len(self.data),
        }


# ── Funciones principales ──────────────────────────────────────────────────

def convert_file(input_path: str, output_path: str, verbose: bool = True) -> bool:
    """Convierte un archivo SELF/SPRX a ELF. Retorna True si tuvo éxito."""
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f'[ERROR] No se pudo leer {input_path}: {e}')
        return False

    # ¿Es ya un ELF directo?
    if data[:4] == ELF_MAGIC:
        if verbose:
            print(f'[INFO]  {input_path} ya es un ELF, copiando directamente...')
        with open(output_path, 'wb') as f:
            f.write(data)
        return True

    parser = SelfParser(data)

    if not parser.is_self():
        print(f'[ERROR] {input_path}: magic desconocido ({data[:4].hex()}), no es SELF ni ELF')
        return False

    if parser.is_encrypted():
        print(f'[ERROR] {input_path}: el ELF interno parece cifrado.')
        print(f'        header_size=0x{parser.header_size:x}, bytes en ese offset: {data[parser.header_size:parser.header_size+8].hex()}')
        print(f'        Los SELF cifrados necesitan claves de descifrado no incluidas aquí.')
        print(f'        Asegúrate de usar dumps extraídos de una PS5 jailbroken (los binarios')
        print(f'        en /system/priv/lib/ suelen estar descifrados en memoria).')
        return False

    elf_data = parser.extract_elf()
    if elf_data is None:
        print(f'[ERROR] {input_path}: no se pudo extraer el ELF')
        return False

    # Verificación adicional: el ELF debe ser ELF64 x86-64
    if len(elf_data) < 20:
        print(f'[ERROR] {input_path}: ELF extraído demasiado pequeño ({len(elf_data)} bytes)')
        return False

    ei_class   = elf_data[4]   # 1=32bit, 2=64bit
    e_machine  = struct.unpack_from('<H', elf_data, 18)[0]

    if ei_class != 2:
        print(f'[WARN]  {input_path}: ELF{32 if ei_class==1 else "?"} (se esperaba ELF64)')
    if e_machine != 0x3e:
        print(f'[WARN]  {input_path}: arquitectura {hex(e_machine)} (se esperaba x86-64 = 0x3e)')

    with open(output_path, 'wb') as f:
        f.write(elf_data)

    if verbose:
        print(f'[OK]    {input_path}')
        print(f'        → {output_path}  ({len(elf_data):,} bytes)')
        print(f'        Segmentos SELF: {parser.num_segments}  |  header_size: {hex(parser.header_size)}')

    return True


def convert_directory(input_dir: str, output_dir: str, verbose: bool = True):
    """Convierte todos los SPRX/SELF de un directorio."""
    os.makedirs(output_dir, exist_ok=True)
    extensions = {'.sprx', '.self', '.prx', '.elf'}
    files = [f for f in Path(input_dir).rglob('*') if f.suffix.lower() in extensions or f.suffix == '']

    ok_count    = 0
    fail_count  = 0
    skip_count  = 0

    print(f'\n[SCAN] {len(files)} archivos encontrados en {input_dir}\n')

    for f in sorted(files):
        out = Path(output_dir) / (f.stem + '.elf')
        with open(f, 'rb') as fh:
            magic = fh.read(4)
        if magic not in (SELF_MAGIC, ELF_MAGIC):
            skip_count += 1
            continue
        if convert_file(str(f), str(out), verbose):
            ok_count += 1
        else:
            fail_count += 1

    print(f'\n[RESUMEN]  OK: {ok_count}  |  Fallidos: {fail_count}  |  Saltados: {skip_count}')
    print(f'           Archivos listos en: {output_dir}')


def check_file(path: str):
    """Solo muestra información sobre el archivo sin convertir."""
    with open(path, 'rb') as f:
        data = f.read(256)  # solo la cabecera

    if data[:4] == ELF_MAGIC:
        ei_class  = data[4]
        e_machine = struct.unpack_from('<H', data, 18)[0] if len(data) >= 20 else 0
        e_type    = struct.unpack_from('<H', data, 16)[0] if len(data) >= 18 else 0
        types = {1:'ET_REL', 2:'ET_EXEC', 3:'ET_DYN', 4:'ET_CORE'}
        print(f'Tipo:        ELF puro (no SELF)')
        print(f'Clase:       ELF{"64" if ei_class==2 else "32"}')
        print(f'Arquitectura: {hex(e_machine)} {"(x86-64)" if e_machine==0x3e else ""}')
        print(f'e_type:      {types.get(e_type, hex(e_type))}')
        return

    with open(path, 'rb') as f:
        full_data = f.read()
    parser = SelfParser(full_data)
    info = parser.info()

    print(f'Tipo:        {"SELF/SPRX" if parser.is_self() else "Desconocido"}')
    for k, v in info.items():
        print(f'{k:20s}: {v}')


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Descomprime SELF/SPRX de PS5 a ELF puro'
    )
    ap.add_argument('input',        nargs='?', help='Archivo SELF/SPRX de entrada')
    ap.add_argument('output',       nargs='?', help='Archivo ELF de salida')
    ap.add_argument('--dir',        help='Directorio de entrada (modo batch)')
    ap.add_argument('--out',        help='Directorio de salida (modo batch)')
    ap.add_argument('--check',      help='Solo muestra información del archivo')
    ap.add_argument('--quiet', '-q', action='store_true', help='Silencioso')
    args = ap.parse_args()

    if args.check:
        check_file(args.check)
    elif args.dir:
        out_dir = args.out or (args.dir + '_elfs')
        convert_directory(args.dir, out_dir, verbose=not args.quiet)
    elif args.input and args.output:
        success = convert_file(args.input, args.output, verbose=not args.quiet)
        sys.exit(0 if success else 1)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()
