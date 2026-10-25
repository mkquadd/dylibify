#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dylibify — inject a dylib into an existing Mach-O binary.

Based on yololib by Sam Hocevar (WTFPL v2):
    https://github.com/KJCracks/yololib

Rewritten in Python with several fixes:
  * Thin 32-bit Mach-O no longer wrongly routed to the 64-bit path.
  * Alignment is fixed at 8 bytes (the original used sizeof(long),
    which is host-dependent and produced different command sizes on
    32- vs 64-bit hosts, corrupting padding).
  * Existing padding after the load commands is detected by scanning
    sections, not assumed.  If padding is too small, the file is
    grown and every file-offset-bearing load command is rewritten
    (LC_SEGMENT[_64], LC_SYMTAB, LC_DYLD_INFO[_ONLY], LC_CODE_SIGNATURE,
    LC_FUNCTION_STARTS, LC_ENCRYPTION_INFO[_64], LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS, LC_MAIN).
  * Fat 32- and 64-bit universal binaries are handled; per-slice offset
    and size fields are updated when a slice grows in place.

Usage:
    python dylibify.py <binary> <dylib> [options]

Options:
    -p, --prefix PREFIX   Prefix for the dylib path (default: @executable_path/)
    -o, --output FILE     Output file (default: in-place, with .bak backup)
    --legacy              Mimic original yololib: overwrite whatever is after
                          the load commands instead of growing the file.

License:
    WTFPL v2 (same as the original yololib).
"""

import argparse
import struct
import sys
from pathlib import Path


# ─── constants ───
MH_MAGIC      = 0xFEEDFACE
MH_CIGAM      = 0xCEFAEDFE
MH_MAGIC_64   = 0xFEEDFACF
MH_CIGAM_64   = 0xCFFAEDFE

FAT_MAGIC     = 0xCAFEBABE
FAT_CIGAM     = 0xBEBAFECA
FAT_MAGIC_64  = 0xCAFEBABF
FAT_CIGAM_64  = 0xBFBAFECA

LC_SEGMENT              = 0x01
LC_SYMTAB               = 0x02
LC_LOAD_DYLIB           = 0x0C
LC_CODE_SIGNATURE       = 0x1D
LC_ENCRYPTION_INFO      = 0x21
LC_DYLD_INFO            = 0x22
LC_DYLD_INFO_ONLY       = 0x80000022
LC_SEGMENT_64           = 0x19
LC_FUNCTION_STARTS      = 0x26
LC_MAIN                 = 0x80000028
LC_DATA_IN_CODE         = 0x29
LC_DYLIB_CODE_SIGN_DRS  = 0x2B
LC_ENCRYPTION_INFO_64   = 0x2C

DYLIB_CURRENT_VERSION       = 0x10000
DYLIB_COMPATIBILITY_VERSION = 0x10000


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def build_dylib_command(path_bytes: bytes, align_to: int = 8) -> bytes:
    """Encode a full LC_LOAD_DYLIB command containing `path_bytes`."""
    name_off = 24
    cmd_size = align(name_off + len(path_bytes) + 1, align_to)
    pad = cmd_size - name_off - len(path_bytes)
    hdr = struct.pack(
        '<IIIIII',
        LC_LOAD_DYLIB,
        cmd_size,
        name_off,
        2,
        DYLIB_CURRENT_VERSION,
        DYLIB_COMPATIBILITY_VERSION,
    )
    return hdr + path_bytes + b'\x00' * pad


def detect_macho_endian(data: bytes, base: int):
    le = struct.unpack_from('<I', data, base)[0]
    be = struct.unpack_from('>I', data, base)[0]
    if le in (MH_MAGIC, MH_MAGIC_64):
        return '<', le == MH_MAGIC_64
    if be in (MH_MAGIC, MH_MAGIC_64):
        return '>', be == MH_MAGIC_64
    raise ValueError(f"not a Mach-O slice at offset {base:#x} "
                     f"(magic LE={le:#x} BE={be:#x})")


def find_min_content_offset(data: bytes, base: int, header_size: int,
                             sizeofcmds: int, endian: str) -> int:
    insert_rel = header_size + sizeofcmds
    min_rel = None
    cursor = base + header_size
    end_cmds = base + insert_rel
    while cursor + 8 <= end_cmds:
        cmd, cmdsize = struct.unpack_from(endian + 'II', data, cursor)
        if cmdsize < 8 or cursor + cmdsize > end_cmds:
            break
        if cmd == LC_SEGMENT:
            nsects = struct.unpack_from(endian + 'I', data, cursor + 48)[0]
            sect_base = cursor + 56
            for j in range(nsects):
                so = sect_base + j * 68
                if so + 68 > end_cmds:
                    break
                offset = struct.unpack_from(endian + 'I', data, so + 40)[0]
                size   = struct.unpack_from(endian + 'I', data, so + 36)[0]
                if offset > 0 and size > 0:
                    if min_rel is None or offset < min_rel:
                        min_rel = offset
        elif cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from(endian + 'I', data, cursor + 64)[0]
            sect_base = cursor + 72
            for j in range(nsects):
                so = sect_base + j * 80
                if so + 80 > end_cmds:
                    break
                offset = struct.unpack_from(endian + 'I', data, so + 48)[0]
                size   = struct.unpack_from(endian + 'Q', data, so + 40)[0]
                if offset > 0 and size > 0:
                    if min_rel is None or offset < min_rel:
                        min_rel = offset
        cursor += cmdsize
    if min_rel is None:
        min_rel = insert_rel
    return base + min_rel


def rewrite_offsets(data: bytearray, base: int, header_size: int,
                     sizeofcmds: int, delta: int, endian: str) -> None:
    insert_rel = header_size + sizeofcmds
    cursor = base + header_size
    end_cmds = base + insert_rel
    while cursor + 8 <= end_cmds:
        cmd, cmdsize = struct.unpack_from(endian + 'II', data, cursor)
        if cmdsize < 8 or cursor + cmdsize > end_cmds:
            break

        if cmd == LC_SEGMENT:
            fileoff = struct.unpack_from(endian + 'I', data, cursor + 32)[0]
            if fileoff > 0 and fileoff >= insert_rel:
                struct.pack_into(endian + 'I', data, cursor + 32, fileoff + delta)
            nsects = struct.unpack_from(endian + 'I', data, cursor + 48)[0]
            sect_base = cursor + 56
            for j in range(nsects):
                so = sect_base + j * 68
                if so + 68 > end_cmds:
                    break
                off = struct.unpack_from(endian + 'I', data, so + 40)[0]
                if off > 0 and off >= insert_rel:
                    struct.pack_into(endian + 'I', data, so + 40, off + delta)
                reloff = struct.unpack_from(endian + 'I', data, so + 48)[0]
                if reloff > 0 and reloff >= insert_rel:
                    struct.pack_into(endian + 'I', data, so + 48, reloff + delta)

        elif cmd == LC_SEGMENT_64:
            fileoff = struct.unpack_from(endian + 'Q', data, cursor + 40)[0]
            if fileoff > 0 and fileoff >= insert_rel:
                struct.pack_into(endian + 'Q', data, cursor + 40, fileoff + delta)
            nsects = struct.unpack_from(endian + 'I', data, cursor + 64)[0]
            sect_base = cursor + 72
            for j in range(nsects):
                so = sect_base + j * 80
                if so + 80 > end_cmds:
                    break
                off = struct.unpack_from(endian + 'I', data, so + 48)[0]
                if off > 0 and off >= insert_rel:
                    struct.pack_into(endian + 'I', data, so + 48, off + delta)
                reloff = struct.unpack_from(endian + 'I', data, so + 56)[0]
                if reloff > 0 and reloff >= insert_rel:
                    struct.pack_into(endian + 'I', data, so + 56, reloff + delta)

        elif cmd == LC_SYMTAB:
            symoff = struct.unpack_from(endian + 'I', data, cursor + 8)[0]
            stroff = struct.unpack_from(endian + 'I', data, cursor + 16)[0]
            if symoff > 0 and symoff >= insert_rel:
                struct.pack_into(endian + 'I', data, cursor + 8, symoff + delta)
            if stroff > 0 and stroff >= insert_rel:
                struct.pack_into(endian + 'I', data, cursor + 16, stroff + delta)

        elif cmd in (LC_CODE_SIGNATURE, LC_FUNCTION_STARTS,
                     LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64,
                     LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS):
            dataoff = struct.unpack_from(endian + 'I', data, cursor + 8)[0]
            if dataoff > 0 and dataoff >= insert_rel:
                struct.pack_into(endian + 'I', data, cursor + 8, dataoff + delta)

        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            for k in range(5):
                f = cursor + 8 + k * 8
                off = struct.unpack_from(endian + 'I', data, f)[0]
                if off > 0 and off >= insert_rel:
                    struct.pack_into(endian + 'I', data, f, off + delta)

        elif cmd == LC_MAIN:
            entryoff = struct.unpack_from(endian + 'Q', data, cursor + 8)[0]
            if entryoff > 0 and entryoff >= insert_rel:
                struct.pack_into(endian + 'Q', data, cursor + 8, entryoff + delta)

        cursor += cmdsize


def inject_thin(data: bytearray, base: int, dylib_cmd: bytes,
                 legacy: bool = False) -> None:
    endian, is_64 = detect_macho_endian(data, base)
    header_size = 32 if is_64 else 28

    ncmds_off      = base + 16
    sizeofcmds_off = base + 20
    ncmds      = struct.unpack_from(endian + 'I', data, ncmds_off)[0]
    sizeofcmds = struct.unpack_from(endian + 'I', data, sizeofcmds_off)[0]

    cmds_end      = base + header_size + sizeofcmds
    min_content   = find_min_content_offset(data, base, header_size,
                                             sizeofcmds, endian)
    padding       = min_content - cmds_end
    needed        = len(dylib_cmd)

    if padding >= needed:
        data[cmds_end:cmds_end + needed] = dylib_cmd
        shifted = False
    elif legacy:
        data[cmds_end:cmds_end + needed] = dylib_cmd
        shifted = False
        print(f'  [!] legacy mode: overwrote {needed} bytes after load '
              f'commands (padding was {padding})', file=sys.stderr)
    else:
        data[cmds_end:cmds_end] = dylib_cmd
        rewrite_offsets(data, base, header_size, sizeofcmds, needed, endian)
        shifted = True

    struct.pack_into(endian + 'I', data, ncmds_off,      ncmds + 1)
    struct.pack_into(endian + 'I', data, sizeofcmds_off, sizeofcmds + needed)

    kind = '64' if is_64 else '32'
    print(f'  [i] slice @ {base:#x}: {kind}-bit, '
          f'padding={padding}, needed={needed}, '
          f'{"shifted" if shifted else "in-place"}')


def parse_fat(data: bytes):
    be = struct.unpack_from('>I', data, 0)[0]
    le = struct.unpack_from('<I', data, 0)[0]
    if be == FAT_MAGIC:
        endian, is64, arch_size = '>', False, 20
    elif be == FAT_MAGIC_64:
        endian, is64, arch_size = '>', True, 32
    elif le == FAT_MAGIC:
        endian, is64, arch_size = '<', False, 20
    elif le == FAT_MAGIC_64:
        endian, is64, arch_size = '<', True, 32
    else:
        raise ValueError(f"not a fat binary (magic BE={be:#x}, LE={le:#x})")

    nfat = struct.unpack_from(endian + 'I', data, 4)[0]
    archs = []
    for i in range(nfat):
        entry_off = 8 + i * arch_size
        if is64:
            cputype, cpusubtype, offset, size, align_, _ = struct.unpack_from(
                endian + 'IIQQII', data, entry_off)
        else:
            cputype, cpusubtype, offset, size, align_ = struct.unpack_from(
                endian + 'IIIII', data, entry_off)
        archs.append({'idx': i, 'entry_off': entry_off,
                      'offset': offset, 'size': size,
                      'cputype': cputype, 'cpusubtype': cpusubtype})
    return endian, is64, archs


def process_fat(data: bytearray, dylib_cmd: bytes,
                 legacy: bool = False) -> None:
    endian, is64, archs = parse_fat(data)
    size_field_off = 16 if is64 else 12
    offset_field_off = 8

    archs.sort(key=lambda a: a['offset'])
    for a in reversed(archs):
        old_size = a['size']
        inject_thin(data, a['offset'], dylib_cmd, legacy=legacy)
        delta = len(dylib_cmd)
        new_size = old_size + delta
        a['size'] = new_size

        if is64:
            struct.pack_into(endian + 'Q', data, a['entry_off'] + size_field_off,
                             new_size)
        else:
            struct.pack_into(endian + 'I', data, a['entry_off'] + size_field_off,
                             new_size)

        for other in archs:
            if other['offset'] > a['offset']:
                other['offset'] += delta
                if is64:
                    struct.pack_into(endian + 'Q', data,
                                     other['entry_off'] + offset_field_off,
                                     other['offset'])
                else:
                    struct.pack_into(endian + 'I', data,
                                     other['entry_off'] + offset_field_off,
                                     other['offset'])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='dylibify',
        description='Inject a dylib into a Mach-O binary '
                    '(based on yololib).')
    ap.add_argument('binary', help='input Mach-O binary')
    ap.add_argument('dylib',  help='dylib filename/path to inject')
    ap.add_argument('-p', '--prefix', default='@executable_path/',
                    help='path prefix (default: @executable_path/)')
    ap.add_argument('-o', '--output', help='output file (default: in-place)')
    ap.add_argument('--legacy', action='store_true',
                    help='original yololib behaviour: never grow the file, '
                         'overwrite bytes after load commands')
    args = ap.parse_args(argv)

    src = Path(args.binary)
    if not src.is_file():
        print(f'[!] no such file: {src}', file=sys.stderr)
        return 1

    path_bytes = (args.prefix + args.dylib).encode('utf-8')
    dylib_cmd  = build_dylib_command(path_bytes)
    print(f'[i] injecting: {path_bytes.decode()}  ({len(dylib_cmd)} bytes)')

    data = bytearray(src.read_bytes())
    if len(data) < 4:
        print('[!] file too short', file=sys.stderr)
        return 1

    magic_be = struct.unpack_from('>I', data, 0)[0]
    magic_le = struct.unpack_from('<I', data, 0)[0]

    try:
        if magic_be in (FAT_MAGIC, FAT_MAGIC_64) or \
           magic_le in (FAT_MAGIC, FAT_MAGIC_64):
            print('[i] fat binary')
            process_fat(data, dylib_cmd, legacy=args.legacy)
        elif magic_le in (MH_MAGIC, MH_MAGIC_64) or \
             magic_be in (MH_MAGIC, MH_MAGIC_64):
            print('[i] thin Mach-O')
            inject_thin(data, 0, dylib_cmd, legacy=args.legacy)
        else:
            print(f'[!] unknown magic LE={magic_le:#x} BE={magic_be:#x}',
                  file=sys.stderr)
            return 1
    except ValueError as e:
        print(f'[!] {e}', file=sys.stderr)
        return 1

    out = Path(args.output) if args.output else src
    if out == src:
        bak = src.with_suffix(src.suffix + '.bak')
        if not bak.exists():
            bak.write_bytes(src.read_bytes())
            print(f'[i] backup: {bak}')
    out.write_bytes(bytes(data))
    print(f'[✓] wrote {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())