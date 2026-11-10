#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a synthetic IL2CPP-style module for the test suite.

Everything is hand-assembled: one PE with a ``.text`` section holding four
functions, and a matching PDB whose symbols point at them.

The code emulates the two shapes this toolchain cares about:

* ``WorldRpcInfo__cctor`` -- three ``mov edx, imm32`` / ``mov rcx, rbx`` /
  ``call`` groups, i.e. a registration table with three keys
* two ``*_RemoteCall*`` wrappers, one of which embeds a registered key and one
  which does not
* a UI function that calls both wrappers, so the xref scan has something real

Run standalone to write the fixtures into ``tests/data``::

    python tests/make_fixture.py
"""
import os
import struct

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
BLOCK = 512
IMAGE_BASE = 0x180000000
TEXT_VA = 0x1000
TEXT_RAW_PTR = 0x400
TEXT_RAW_SIZE = 0x200

GUID = bytes.fromhex("00112233445566778899aabbccddeeff")
AGE = 7

# RVA layout inside .text
# Every entry sits after 0xCC padding so "is there a terminator before it?"
# has a real answer -- a function at the very start of a section has no
# preceding byte and will (correctly) fail the entry check.
CTOR_RVA = TEXT_VA + 0x010
CALL1_RVA = TEXT_VA + 0x040
CALL2_RVA = TEXT_VA + 0x060
UI_RVA = TEXT_VA + 0x080

#: Keys the registration constructor installs.
REGISTERED_IDS = (0x11111111, 0x22222222, 0x33333333)
#: Key embedded in the first wrapper (registered).
BOUND_ID = 0x11111111
#: Key embedded in the second wrapper (not registered -> must stay unmatched).
UNBOUND_ID = 0x99999999


def _mov_edx(value):
    return b"\xBA" + struct.pack("<I", value)


MOV_RCX_RBX = b"\x48\x8B\xCB"
CALL_SELF = b"\xE8\x00\x00\x00\x00"      # rel32 = 0, target = next instruction
RET = b"\xC3"
PROLOGUE = b"\x48\x89\x5C\x24\x08"       # mov [rsp+8], rbx


def _registration_ctor():
    code = bytearray(PROLOGUE)
    for method_id in REGISTERED_IDS:
        code += _mov_edx(method_id)
        code += MOV_RCX_RBX
        code += CALL_SELF
    code += RET
    return bytes(code)


def _wrapper(method_id):
    return PROLOGUE + _mov_edx(method_id) + MOV_RCX_RBX + CALL_SELF + RET


def _ui_caller():
    # call wrapper1 then wrapper2, with rel32 computed from the next instruction
    code = bytearray(PROLOGUE)
    site1 = UI_RVA + len(code)
    code += b"\xE8" + struct.pack("<i", CALL1_RVA - (site1 + 5))
    site2 = UI_RVA + len(code)
    code += b"\xE8" + struct.pack("<i", CALL2_RVA - (site2 + 5))
    code += RET
    return bytes(code)


def build_text():
    """Assemble .text with 0xCC padding so every entry is preceded by a terminator."""
    size = TEXT_RAW_SIZE
    text = bytearray(b"\xCC" * size)

    def place(rva, payload):
        offset = rva - TEXT_VA
        text[offset:offset + len(payload)] = payload

    place(CTOR_RVA, _registration_ctor())
    place(CALL1_RVA, _wrapper(BOUND_ID))
    place(CALL2_RVA, _wrapper(UNBOUND_ID))
    place(UI_RVA, _ui_caller())
    return bytes(text)


# ---------------------------------------------------------------- PE fixture

def build_pe():
    image = bytearray(TEXT_RAW_PTR + TEXT_RAW_SIZE)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x8664, 1)        # machine, sections
    struct.pack_into("<I", image, 0x88, 0x5F112233)        # timestamp
    struct.pack_into("<H", image, 0x94, 240)               # SizeOfOptionalHeader

    opt = 0x98
    struct.pack_into("<H", image, opt, 0x20B)              # PE32+
    struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
    struct.pack_into("<I", image, opt + 56, 0x2000)        # SizeOfImage

    sec = opt + 240
    image[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<4I", image, sec + 8,
                     0x1000, TEXT_VA, TEXT_RAW_SIZE, TEXT_RAW_PTR)
    struct.pack_into("<I", image, sec + 36, 0x60000020)    # CODE|EXECUTE|READ

    image[TEXT_RAW_PTR:TEXT_RAW_PTR + TEXT_RAW_SIZE] = build_text()
    return bytes(image)


# --------------------------------------------------------------- PDB fixture

SYMBOLS = [
    (CTOR_RVA, 0x2D, "?WorldRpcInfo__cctor@@YAXXZ"),
    (CALL1_RVA, 0x13, "?WorldEntity_RemoteCallDoThing@UWorldEntity@@QEAAXXZ"),
    (CALL2_RVA, 0x13, "?OtherEntity_RemoteCallUnknown@UOtherEntity@@QEAAXXZ"),
    (UI_RVA, 0x10, "?UiWorld_OnButtonClicked@UUiWorld@@QEAAXXZ"),
]


def _info_stream():
    return struct.pack("<III", 20000404, 0x12345678, AGE) + GUID


def _dbi_stream(sym_stream=4):
    out = bytearray(64)
    struct.pack_into("<III", out, 0, 0xFFFFFFFF, 19990903, AGE)
    struct.pack_into("<6H", out, 12, 3, 0, 3, 0, sym_stream, 0)
    struct.pack_into("<HH", out, 56, 0, 0x8664)
    return bytes(out)


def _symbol_stream():
    out = bytearray()
    for rva, _size, name in SYMBOLS:
        encoded = name.encode("ascii")
        offset = rva - TEXT_VA
        length = 2 + 4 + 4 + 2 + len(encoded) + 1
        # flags: CVPSF_CODE | CVPSF_FUNCTION so the portable reader classifies it
        out += struct.pack("<HHIIH", length, 0x110E, 0x0003, offset, 1)
        out += encoded + b"\0"
    return bytes(out)


def build_pdb():
    streams = [b"", _info_stream(), b"", _dbi_stream(), _symbol_stream()]

    def chunk(payload):
        n = -(-len(payload) // BLOCK)
        return [payload[i * BLOCK:(i + 1) * BLOCK].ljust(BLOCK, b"\0")
                for i in range(n)]

    blocks = [chunk(s) for s in streams]
    index = 2                          # 0 = superblock, 1 = directory
    lists = []
    for group in blocks:
        lists.append(list(range(index, index + len(group))))
        index += len(group)
    map_block = index

    directory = struct.pack("<I", len(streams))
    directory += struct.pack("<%dI" % len(streams), *[len(s) for s in streams])
    for group in lists:
        directory += struct.pack("<%dI" % len(group), *group)
    directory = directory.ljust(BLOCK, b"\0")

    superblock = bytearray(64)
    superblock[0:32] = MSF_MAGIC
    struct.pack_into("<6I", superblock, 32, BLOCK, 0, map_block + 1,
                     len(directory), 0, map_block)

    image = bytearray(superblock.ljust(BLOCK, b"\0"))
    image += directory
    for group in blocks:
        for b in group:
            image += b
    image += struct.pack("<I", 1).ljust(BLOCK, b"\0")
    return bytes(image)


def write_fixtures(directory):
    os.makedirs(directory, exist_ok=True)
    dll = os.path.join(directory, "GameAssembly.dll")
    pdb = os.path.join(directory, "GameAssembly.pdb")
    with open(dll, "wb") as f:
        f.write(build_pe())
    with open(pdb, "wb") as f:
        f.write(build_pdb())
    return dll, pdb


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    dll, pdb = write_fixtures(os.path.join(here, "data"))
    print("wrote %s (%d bytes)" % (dll, os.path.getsize(dll)))
    print("wrote %s (%d bytes)" % (pdb, os.path.getsize(pdb)))
