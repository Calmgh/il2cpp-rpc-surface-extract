#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Symbol export through ``dbghelp`` (Windows only, no extra dependencies).

``dbghelp`` is preferred over parsing the PDB ourselves because it classifies
symbols: ``SymTagFunction`` (5) versus ``SymTagData`` (7). IL2CPP symbol names
alone do not tell you which is which, and the function table is what the whole
workflow queries.

Two things that will bite you (see references/pitfalls.md):

* ``argtypes`` must be declared. On x64 an undeclared ``SymLoadModuleEx``
  receives the 64-bit base as a C ``int`` and Python raises
  ``OverflowError: int too long to convert``.
* With ``mask="*"`` the first ~800k symbols can all report ``tag=7`` (the
  ``_RuntimeMethod_var`` entries come first). Zero functions so far is normal,
  not a failure.
"""
import ctypes
import os
import sys

from .table import Symbol

# SYMBOL_INFO, x64. Field offsets match the documented layout:
# Tag=72, NameLen=76, Name=84, Address=56, Size=28.
class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ctypes.c_ulong),
        ("TypeIndex", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", ctypes.c_ulong),
        ("Size", ctypes.c_ulong),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", ctypes.c_ulong),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", ctypes.c_ulong),
        ("Scope", ctypes.c_ulong),
        ("Tag", ctypes.c_ulong),
        ("NameLen", ctypes.c_ulong),
        ("MaxNameLen", ctypes.c_ulong),
        ("Name", ctypes.c_char * 1),
    ]


SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004

SYMTAG_FUNCTION = 5
SYMTAG_DATA = 7

_NAME_OFFSET = 84


def available():
    return sys.platform.startswith("win")


def export_symbols(dll_path, search_path=None, mask="*",
                   wanted_tags=(SYMTAG_FUNCTION, SYMTAG_DATA), progress=None):
    """Return ``(symbols, base)`` for *dll_path*.

    *search_path* is where ``dbghelp`` looks for the PDB; it defaults to the
    DLL's own directory. *progress* is called with the running symbol count
    every ~200k symbols. *base* is the load base ``dbghelp`` assigned, which
    should equal the module's preferred image base (commonly ``0x180000000``
    for IL2CPP builds) -- a mismatch means the PDB did not match.
    """
    if not available():
        raise RuntimeError("dbghelp export requires Windows")

    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS)

    process = kernel32.GetCurrentProcess()
    search = os.path.abspath(search_path or os.path.dirname(dll_path))
    dll = os.path.abspath(dll_path)

    if not dbghelp.SymInitialize(process, search.encode("mbcs", "replace"), False):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        # Declare argtypes before calling: see the module docstring.
        dbghelp.SymLoadModuleEx.restype = ctypes.c_ulonglong
        dbghelp.SymLoadModuleEx.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_ulonglong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
        ]
        base = dbghelp.SymLoadModuleEx(
            process, None, dll.encode("mbcs", "replace"), None, 0, 0, None, 0)
        if not base:
            raise ctypes.WinError(ctypes.get_last_error())

        symbols = []
        wanted = set(wanted_tags)
        counter = [0]

        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_bool, ctypes.POINTER(SYMBOL_INFO), ctypes.c_ulong, ctypes.c_void_p)

        def _on_symbol(info_ptr, size, _context):
            counter[0] += 1
            if progress is not None and counter[0] % 200000 == 0:
                progress(counter[0], len(symbols))
            info = info_ptr.contents
            if info.Tag not in wanted:
                return True
            rva = info.Address - base
            # Negative / overflowed addresses occur in real dumps; drop them.
            if rva <= 0 or rva > (1 << 47):
                return True
            raw = ctypes.string_at(ctypes.addressof(info) + _NAME_OFFSET, info.NameLen)
            symbols.append(Symbol(rva, info.Size, info.Tag,
                                  raw.decode("latin-1", "replace")))
            return True

        dbghelp.SymEnumSymbols.restype = ctypes.c_bool
        dbghelp.SymEnumSymbols.argtypes = [
            ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
            callback_type, ctypes.c_void_p,
        ]
        dbghelp.SymEnumSymbols(process, base, mask.encode(), callback_type(_on_symbol), None)
        return symbols, base
    finally:
        dbghelp.SymCleanup(process)


def strip_hashes(name):
    """Remove IL2CPP's ``_m<32 hex>`` suffix so the class name is readable.

    ``Foo_RemoteCallBar_m1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D`` -> ``Foo_RemoteCallBar``.
    ``_RuntimeMethod_var`` data symbols get their suffix removed too.
    """
    import re
    name = re.sub(r"_m[0-9A-Fa-f]{16,}(_RuntimeMethod_var)?$", "", name)
    return name
