#!/usr/bin/env python3
"""Print "<format> <arch>" for a binary, read from its object header.

Prints one of: `elf x86_64` / `elf aarch64` / `macho x86_64` / `macho aarch64` / `pe x86_64` /
`pe aarch64`, or `unknown ...` — matching the `format` and `arch` fields of a target row in
.github/release-targets.json.

WHY A PARSER AND NOT `file(1)` OR `uname`.

The release gate runs this on ubuntu, ubuntu-arm, macos-intel, macos-arm and windows runners. `file`
is absent on Windows and its output wording differs between GNU file and macOS's; `uname -m`
reports the RUNNER's architecture, not the artifact's, which makes it exactly useless for the
failure this check exists to catch — an asset named aarch64 that contains x86_64 bytes. The object
header is the artifact's own claim about itself and is identical everywhere, so parsing 20 bytes of
it is both more portable and more direct than shelling out to a tool that reads the same bytes.
"""

import struct
import sys

ELF_MACHINE = {0x3E: "x86_64", 0xB7: "aarch64"}
MACHO_CPU = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
PE_MACHINE = {0x8664: "x86_64", 0xAA64: "aarch64"}


def probe(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4096)

    if head[:4] == b"\x7fELF":
        # e_machine is a u16 at offset 18, endianness from EI_DATA at offset 5.
        endian = "<" if head[5] == 1 else ">"
        (machine,) = struct.unpack_from(endian + "H", head, 18)
        return "elf " + ELF_MACHINE.get(machine, f"unknown(0x{machine:x})")

    # Mach-O thin, both endiannesses. cputype is the u32 right after the magic.
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        (cpu,) = struct.unpack_from("<I", head, 4)
        return "macho " + MACHO_CPU.get(cpu, f"unknown(0x{cpu:x})")
    if head[:4] in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        (cpu,) = struct.unpack_from(">I", head, 4)
        return "macho " + MACHO_CPU.get(cpu, f"unknown(0x{cpu:x})")

    # Mach-O universal ("fat"). A release artifact declaring ONE architecture must not be a fat
    # binary carrying several: it doubles the download and means the declared arch row is not
    # actually what was shipped. Named explicitly so the failure is legible.
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "macho-universal multiple"

    if head[:2] == b"MZ":
        # PE: e_lfanew (u32 @ 0x3C) -> "PE\0\0" -> COFF Machine (u16).
        (pe_off,) = struct.unpack_from("<I", head, 0x3C)
        if head[pe_off : pe_off + 4] == b"PE\0\0":
            (machine,) = struct.unpack_from("<H", head, pe_off + 4)
            return "pe " + PE_MACHINE.get(machine, f"unknown(0x{machine:x})")
        return "pe unknown"

    return "unknown unknown"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: binfmt.py <binary>", file=sys.stderr)
        raise SystemExit(2)
    print(probe(sys.argv[1]))
