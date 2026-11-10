#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check an RVA against the build: entry bytes, prologue, and hook safety.

Usage::

    python tools/check_entry.py GameAssembly.dll 0x1A2B3C0 [options]

Options::

    --symbols FILE    also report whether a symbol starts at this RVA
    --json            machine-readable output

Answers three questions, in increasing cost:

1. **Is the address inside a section at all?** An RVA from an old note may not
   survive a build change.
2. **Does a function actually start here?** Decent evidence: the preceding byte
   terminates the previous function and the first bytes are a standard x64
   prologue.
3. **Can a 5-byte jump be written here?** i.e. does the patch land on an
   instruction boundary.

Use this before trusting any RVA copied out of older notes. A stale address that
still points into code will silently produce nonsense.
"""
import argparse
import json
import sys

import _common  # noqa: F401

from il2cpprpc import disasm, pe as pe_mod
from il2cpprpc.table import SymbolTable


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("rva")
    ap.add_argument("--symbols", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not disasm.available():
        print("capstone is required: pip install capstone")
        return 2

    rva = int(args.rva, 16)
    module = pe_mod.PE(args.dll)

    segment = disasm.segment_info(module, rva)
    entry = disasm.check_entry(module, rva)
    patch = disasm.jmp_patchable(module, rva)

    symbol = None
    if args.symbols:
        table = SymbolTable.load_tsv(args.symbols)
        exact = table.exact(rva)
        symbol = exact.name if exact else None

    report = {
        "rva": rva,
        "segment": segment,
        "entry": entry,
        "patch": patch,
        "symbol": symbol,
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print("module  : %s" % args.dll)
    print("RVA     : 0x%X" % rva)
    if segment:
        print("section : %s + 0x%X (of 0x%X)" % (
            segment["section"], segment["offset_in_section"], segment["section_size"]))
    else:
        print("section : *** not inside any section ***")
    if symbol:
        print("symbol  : %s" % symbol)
    print()

    print("entry check")
    print("  first bytes      : %s" % entry.get("first_bytes", "-"))
    print("  preceding byte   : %s" % (entry.get("prev_byte") or "-"))
    print("  standard prologue: %s" % ("yes" if entry.get("prologue") else "no"))
    print("  terminator before: %s" % ("yes" if entry.get("terminator_before") else "no"))
    print("  => function entry: %s" % ("YES" if entry.get("ok") else "NO"))
    if not entry.get("ok"):
        print("     If this RVA came from notes, re-derive it on the current build.")
    print()

    print("patch check (5-byte jmp)")
    if patch.get("ok"):
        print("  ok: instruction boundary at 0x%X" % patch["boundary"])
        print("  displaced: %s" % "; ".join(patch["displaced"]))
    else:
        print("  not clean: %s" % patch.get("reason"))
        if patch.get("split_at"):
            print("  would split instruction at 0x%X" % patch["split_at"])
    return 0 if entry.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
