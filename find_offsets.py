#!/usr/bin/env python3
"""
IL2CPP reset_guest offset finder & verifier for libil2cpp.so
Supports ARM64 (arm64-v8a) and ARM32 (armeabi-v7a)

Usage:
    python find_offsets.py libil2cpp.so
    python find_offsets.py libil2cpp.so --patch          # patch in-place
    python find_offsets.py libil2cpp.so --patch --out patched.so
"""

import struct
import sys
import os
import argparse
import shutil
from pathlib import Path

# ─── Known offsets ────────────────────────────────────────────────────────────
KNOWN_OFFSETS = {
    "arm64": [0x635DB70, 0x635DC24],
    "arm32": [0x5340504, 0x53405EC],
}

# ─── Patch bytes: always return true (1) ──────────────────────────────────────
#  ARM64: MOV W0, #1  (20 00 80 52)  +  RET         (C0 03 5F D6)
#  ARM32: MOV R0, #1  (01 00 A0 E3)  +  BX LR       (1E FF 2F E1)
PATCH_BYTES = {
    "arm64": bytes([0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]),
    "arm32": bytes([0x01, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1]),
}

# ─── Typical function prologue signatures ─────────────────────────────────────
#  Used to scan ± N bytes around known offsets when the symbol is stripped.
#
#  ARM64 prologues (little-endian, lower 8 bits of instruction ignored for stp):
ARM64_PROLOGUE_PATTERNS = [
    b"\xfd\x7b",   # STP x29, x30, [sp, ...]
    b"\xf6\x57",   # STP x22, x21
    b"\xf4\x4f",   # STP x20, x19
]
#  ARM32 PUSH instruction: 0xE9 2D xx xx  (PUSH {regs, LR})
ARM32_PUSH_MASK  = 0xFFFF0000
ARM32_PUSH_VALUE = 0xE92D0000


# ─────────────────────────────────────────────────────────────────────────────
# ELF helpers
# ─────────────────────────────────────────────────────────────────────────────

def detect_arch(data: bytes) -> tuple[str, str]:
    """Return (arch, endian_char): arch is 'arm64' or 'arm32', endian '<' or '>'."""
    if data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    endian = "<" if data[5] == 1 else ">"
    e_machine = struct.unpack_from(endian + "H", data, 18)[0]
    if e_machine == 0xB7:
        return "arm64", endian
    if e_machine == 0x28:
        return "arm32", endian
    raise ValueError(f"Unsupported e_machine=0x{e_machine:04X}  (expected ARM or AArch64)")


def get_load_segments(data: bytes, arch: str, endian: str) -> list[tuple[int, int, int]]:
    """Return [(vaddr, file_offset, file_size), ...] for every PT_LOAD segment."""
    bits = 64 if arch == "arm64" else 32
    e = endian

    if bits == 64:
        e_phoff, e_phentsize, e_phnum = struct.unpack_from(e + "QHH", data, 32)
        phdr_fmt = e + "IIQQQQQQ"   # p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    else:
        e_phoff, e_phentsize, e_phnum = struct.unpack_from(e + "IHH", data, 28)
        phdr_fmt = e + "IIIIIIII"   # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align

    PT_LOAD = 1
    segments = []
    for i in range(e_phnum):
        phdr = struct.unpack_from(phdr_fmt, data, e_phoff + i * e_phentsize)
        p_type = phdr[0]
        if p_type != PT_LOAD:
            continue
        if bits == 64:
            _, _, p_offset, p_vaddr, _, p_filesz, _, _ = phdr
        else:
            _, p_offset, p_vaddr, _, p_filesz, _, _, _ = phdr
        segments.append((p_vaddr, p_offset, p_filesz))
    return segments


def vaddr_to_foff(vaddr: int, segments: list) -> int | None:
    """Convert a virtual address to a file offset."""
    for seg_vaddr, seg_foff, seg_fsz in segments:
        if seg_vaddr <= vaddr < seg_vaddr + seg_fsz:
            return seg_foff + (vaddr - seg_vaddr)
    return None


def get_symbol_table(data: bytes, arch: str, endian: str) -> dict[str, int]:
    """
    Parse .dynsym / .symtab and return {name: vaddr} for all FUNC symbols.
    Returns empty dict if the binary is fully stripped.
    """
    bits = 64 if arch == "arm64" else 32
    e = endian

    # Read section headers
    if bits == 64:
        e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "QHHH", data, 40)
        shdr_fmt = e + "IIQQQQIIQQ"
    else:
        e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "IHHH", data, 32)
        shdr_fmt = e + "IIIIIIIIII"

    if e_shoff == 0 or e_shnum == 0:
        return {}

    def read_shdr(idx):
        return struct.unpack_from(shdr_fmt, data, e_shoff + idx * e_shentsize)

    # Section name string table
    shstrtab_shdr = read_shdr(e_shstrndx)
    shstrtab_off  = shstrtab_shdr[4] if bits == 64 else shstrtab_shdr[4]
    shstrtab_size = shstrtab_shdr[5] if bits == 64 else shstrtab_shdr[5]
    shstrtab      = data[shstrtab_off: shstrtab_off + shstrtab_size]

    SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3

    symbols: dict[str, int] = {}

    for i in range(e_shnum):
        shdr = read_shdr(i)
        sh_type = shdr[1]
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue

        # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
        if bits == 64:
            sh_offset = shdr[4]; sh_size = shdr[5]; sh_link = shdr[6]; sh_entsize = shdr[9]
            sym_fmt   = e + "IBBHQQ"   # st_name, st_info, st_other, st_shndx, st_value, st_size
        else:
            sh_offset = shdr[4]; sh_size = shdr[5]; sh_link = shdr[6]; sh_entsize = shdr[9]
            sym_fmt   = e + "IIIBBH"   # st_name, st_value, st_size, st_info, st_other, st_shndx

        strtab_shdr = read_shdr(sh_link)
        strtab_off  = strtab_shdr[4]
        strtab_size = strtab_shdr[5]
        strtab      = data[strtab_off: strtab_off + strtab_size]

        n_syms = sh_size // sh_entsize
        for j in range(n_syms):
            sym = struct.unpack_from(sym_fmt, data, sh_offset + j * sh_entsize)
            if bits == 64:
                st_name, st_info, _, _, st_value, _ = sym
                sym_type = st_info & 0xF
            else:
                st_name, st_value, _, st_info, _, _ = sym
                sym_type = st_info & 0xF

            STT_FUNC = 2
            if sym_type != STT_FUNC or st_value == 0:
                continue

            name_end = strtab.index(b"\x00", st_name)
            name = strtab[st_name:name_end].decode("utf-8", errors="replace")
            symbols[name] = st_value

    return symbols


# ─────────────────────────────────────────────────────────────────────────────
# Search helpers
# ─────────────────────────────────────────────────────────────────────────────

def find_by_symbol(symbols: dict[str, int], keyword: str = "reset_guest") -> list[int]:
    """Return vaddrs of all symbols whose name contains `keyword`."""
    kw = keyword.lower()
    return [va for name, va in symbols.items() if kw in name.lower()]


def scan_near_offset(data: bytes, arch: str, foff: int, window: int = 0x200) -> list[int]:
    """
    Scan ± window bytes around foff for known function prologues.
    Returns file offsets of candidate prologue starts.
    """
    start = max(0, foff - window)
    end   = min(len(data), foff + window)
    hits  = []

    if arch == "arm64":
        # ARM64 instructions are 4-byte aligned
        for off in range(start & ~3, end, 4):
            for pat in ARM64_PROLOGUE_PATTERNS:
                if data[off: off + len(pat)] == pat:
                    hits.append(off)
                    break
    else:
        # ARM32 PUSH {regs, LR}
        for off in range(start & ~3, end, 4):
            word = struct.unpack_from("<I", data, off)[0]
            if (word & ARM32_PUSH_MASK) == ARM32_PUSH_VALUE:
                hits.append(off)

    return hits


def bytes_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Find & verify IL2CPP reset_guest offsets in libil2cpp.so"
    )
    parser.add_argument("lib", help="Path to libil2cpp.so")
    parser.add_argument("--patch", action="store_true", help="Apply true-patch to the file")
    parser.add_argument("--out",   default=None,        help="Output path for patched file (default: overwrite)")
    args = parser.parse_args()

    lib_path = Path(args.lib)
    if not lib_path.is_file():
        print(f"[!] File not found: {lib_path}")
        sys.exit(1)

    data = bytearray(lib_path.read_bytes())
    print(f"[*] Loaded {lib_path.name}  ({len(data):,} bytes)")

    # ── Detect architecture ───────────────────────────────────────────────────
    try:
        arch, endian = detect_arch(data)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[*] Architecture : {'ARM64 (arm64-v8a)' if arch == 'arm64' else 'ARM32 (armeabi-v7a)'}")
    print()

    # ── Load segments (vaddr ↔ file offset mapping) ───────────────────────────
    segments = get_load_segments(data, arch, endian)
    if not segments:
        print("[!] No PT_LOAD segments found")
        sys.exit(1)

    # ── Symbol table (may be empty if stripped) ───────────────────────────────
    symbols = get_symbol_table(data, arch, endian)
    if symbols:
        print(f"[*] Symbol table : {len(symbols):,} FUNC symbols found")
        sym_hits = find_by_symbol(symbols)
        if sym_hits:
            print(f"[+] reset_guest matches in symbol table:")
            for va in sym_hits:
                foff = vaddr_to_foff(va, segments)
                print(f"      vaddr=0x{va:08X}  file_offset=0x{foff:08X}")
        else:
            print("[~] 'reset_guest' not found in symbol table (mangled/stripped)")
    else:
        print("[~] Binary is stripped (no symbol table)")
    print()

    # ── Verify / patch known offsets ──────────────────────────────────────────
    known   = KNOWN_OFFSETS[arch]
    patch   = PATCH_BYTES[arch]
    already = bytes_hex(patch)

    print(f"[*] Verifying {len(known)} known offset(s)  [patch = {already}]")
    print("-" * 60)

    patched_count = 0
    for vaddr in known:
        foff = vaddr_to_foff(vaddr, segments)
        if foff is None:
            print(f"  vaddr 0x{vaddr:08X}  =>  NOT mapped in any PT_LOAD segment")
            # Try nearby prologue scan anyway
            approx_foff = vaddr   # rough guess if base is 0
            near = scan_near_offset(bytes(data), arch, approx_foff)
            if near:
                print(f"    (prologue candidates near raw offset: {[hex(x) for x in near]})")
            continue

        current = bytes(data[foff: foff + len(patch)])
        is_patched = current == patch

        print(f"  vaddr  : 0x{vaddr:08X}")
        print(f"  foffset: 0x{foff:08X}")
        print(f"  current: {bytes_hex(current)}{'  ← already patched' if is_patched else ''}")

        if not is_patched:
            # Scan for function prologues near this offset to confirm it looks like a function
            near = scan_near_offset(bytes(data), arch, foff, window=0x40)
            if foff in near or (foff & ~3) in near:
                print(f"  prologue detected at offset  ✓")
            else:
                print(f"  prologue: not detected near offset (may be mid-function or wrong offset)")

            if args.patch:
                data[foff: foff + len(patch)] = patch
                print(f"  patched  : {bytes_hex(patch)}  ✓")
                patched_count += 1
            else:
                print(f"  would patch to: {bytes_hex(patch)}")
        print()

    # ── Write output ──────────────────────────────────────────────────────────
    if args.patch and patched_count > 0:
        out_path = Path(args.out) if args.out else lib_path
        if out_path == lib_path:
            backup = lib_path.with_suffix(".so.bak")
            shutil.copy2(lib_path, backup)
            print(f"[*] Backup saved to {backup}")
        out_path.write_bytes(data)
        print(f"[+] Patched file written to {out_path}  ({patched_count} patch(es) applied)")
    elif args.patch and patched_count == 0:
        print("[*] Nothing to patch (all offsets already patched)")


if __name__ == "__main__":
    main()
