#!/usr/bin/env python3
"""Generate the deterministic canary executables used by the hash-IOC atomic test.

Rustinel hashes an executable when it becomes a *process image*, so the only way
to test the hash-IOC path end to end is to launch a file whose bytes — and
therefore whose SHA-256 — are fixed in advance. These are the smallest programs
that do nothing and exit 0: a static ELF per Linux architecture and an
import-less PE for Windows. They are emitted byte for byte by the atomic scripts
from an embedded base64 blob, so nothing binary lives in the repository.

macOS has no entry here on purpose: arm64 refuses to execute an unsigned image,
and an ad-hoc signature is not byte-stable across toolchains, so a Mach-O canary
cannot have a hash known at authoring time. The macOS atomic uses the path-regex
indicator in the same IOC set instead.

Run it to regenerate the blobs after any change:

    uv run python tests/atomic/canary/make_canary.py

It prints, per target, the base64 to paste into the atomic script and the SHA-256
to record in preview/ioc/common/ioc_canary_exec.yml. Output is stable: running it
twice produces identical bytes.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import textwrap

ELF_HEADER_SIZE = 64
ELF_PHDR_SIZE = 56
ELF_ENTRY_OFFSET = ELF_HEADER_SIZE + ELF_PHDR_SIZE  # 0x78
ELF_BASE = 0x400000

EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7

# exit(0), with no libc: status register to 0, syscall number, trap.
CODE_X86_64 = (
    b"\x31\xff"  # xor edi, edi -> status 0
    b"\xb8\x3c\x00\x00\x00"  # mov eax, 60 -> __NR_exit
    b"\x0f\x05"  # syscall
)
CODE_AARCH64 = struct.pack(
    "<III",
    0xD2800000,  # mov x0, #0   -> status 0
    0xD2800BA8,  # mov x8, #93  -> __NR_exit
    0xD4000001,  # svc #0
)


def build_elf(machine: int, code: bytes, align: int) -> bytes:
    """A single PT_LOAD segment covering the whole file, entry just past the headers."""
    total = ELF_ENTRY_OFFSET + len(code)
    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0]) + bytes(8)  # 64-bit, LSB, SysV
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type   ET_EXEC
        machine,  # e_machine
        1,  # e_version
        ELF_BASE + ELF_ENTRY_OFFSET,  # e_entry
        ELF_HEADER_SIZE,  # e_phoff
        0,  # e_shoff  (no section headers)
        0,  # e_flags
        ELF_HEADER_SIZE,  # e_ehsize
        ELF_PHDR_SIZE,  # e_phentsize
        1,  # e_phnum
        64,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type   PT_LOAD
        5,  # p_flags  PF_R | PF_X
        0,  # p_offset
        ELF_BASE,  # p_vaddr
        ELF_BASE,  # p_paddr
        total,  # p_filesz
        total,  # p_memsz
        align,  # p_align
    )
    blob = header + phdr + code
    assert len(blob) == total, (len(blob), total)
    return blob


# --- Windows -------------------------------------------------------------- #
# A PE64 with one executable section and no imports. The loader maps it at the
# preferred base (no DYNAMIC_BASE, so the absent relocation directory is fine),
# calls the entry point, and the return unwinds into RtlExitUserThread, which
# ends the process.
PE_FILE_ALIGN = 0x200
PE_SECTION_ALIGN = 0x1000
PE_TEXT_RVA = 0x1000
PE_CODE = bytes((0x31, 0xC0, 0xC3))  # xor eax, eax ; ret  -> exit code 0


def build_pe() -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)  # e_lfanew

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine  IMAGE_FILE_MACHINE_AMD64
        1,  # NumberOfSections
        0,  # TimeDateStamp  (zero: the output must be reproducible)
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader
        0x0022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    optional = (
        struct.pack(
            "<HBBIIIIIQ",
            0x20B,  # Magic  PE32+
            14,
            0,  # Linker version
            PE_FILE_ALIGN,  # SizeOfCode
            0,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
            PE_TEXT_RVA,  # AddressOfEntryPoint
            PE_TEXT_RVA,  # BaseOfCode
            0x140000000,  # ImageBase
        )
        + struct.pack(
            "<IIHHHHHHIIIIHHQQQQII",
            PE_SECTION_ALIGN,  # SectionAlignment
            PE_FILE_ALIGN,  # FileAlignment
            6,
            0,  # OS version
            0,
            0,  # Image version
            6,
            0,  # Subsystem version
            0,  # Win32VersionValue
            PE_TEXT_RVA + PE_SECTION_ALIGN,  # SizeOfImage
            PE_FILE_ALIGN,  # SizeOfHeaders
            0,  # CheckSum  (not required for an EXE)
            3,  # Subsystem  IMAGE_SUBSYSTEM_WINDOWS_CUI
            0x0100,  # DllCharacteristics  NX_COMPAT only
            0x100000,
            0x1000,  # Stack reserve / commit
            0x100000,
            0x1000,  # Heap reserve / commit
            0,  # LoaderFlags
            16,  # NumberOfRvaAndSizes
        )
        + bytes(16 * 8)
    )  # 16 empty data directories

    assert len(optional) == 0xF0, len(optional)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        PE_FILE_ALIGN,  # VirtualSize
        PE_TEXT_RVA,  # VirtualAddress
        PE_FILE_ALIGN,  # SizeOfRawData
        PE_FILE_ALIGN,  # PointerToRawData
        0,
        0,
        0,
        0,  # relocations / line numbers
        0x60000020,  # CODE | EXECUTE | READ
    )
    assert len(section) == 40, len(section)

    headers = bytes(dos) + b"PE\0\0" + coff + optional + section
    assert len(headers) <= PE_FILE_ALIGN, len(headers)
    body = PE_CODE.ljust(PE_FILE_ALIGN, b"\0")
    return headers.ljust(PE_FILE_ALIGN, b"\0") + body


TARGETS = {
    "linux-x86_64": lambda: build_elf(EM_X86_64, CODE_X86_64, 0x1000),
    # arm64 kernels may use 64K pages; p_vaddr and p_offset stay congruent.
    "linux-aarch64": lambda: build_elf(EM_AARCH64, CODE_AARCH64, 0x10000),
    "windows-x86_64": build_pe,
}


def main() -> int:
    for name, build in TARGETS.items():
        blob = build()
        digest = hashlib.sha256(blob).hexdigest()
        encoded = base64.b64encode(blob).decode("ascii")
        print(f"## {name}  ({len(blob)} bytes)")
        print(f"sha256: {digest}")
        print("base64:")
        for line in textwrap.wrap(encoded, 76):
            print(f"  {line}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
