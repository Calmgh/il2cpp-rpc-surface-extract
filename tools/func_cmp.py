#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Compare two functions: same template, or unrelated code?

Usage::

    python tools/func_cmp.py GameAssembly.dll 0x1A2B3C0 0x1A2B520 [options]

Options::

    --symbols FILE    take function sizes from a symbol table
    --json            machine-readable output

Interpretation:

* same size, same mnemonics, differences only in immediates  -> **isomorphic**
  The two are one template with substituted constants. Argument register
  semantics can be reused; a whole round of runtime calibration is unnecessary.
* different instruction count or divergent mnemonics        -> **not siblings**
  Do not assume the parameter layout carries over.
"""
import argparse
import json
import sys

import _common  # noqa: F401

from il2cpprpc import compare as cmp_mod, disasm, pe as pe_mod
from il2cpprpc.table import SymbolTable


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("a", help="first RVA (hex)")
    ap.add_argument("b", help="second RVA (hex)")
    ap.add_argument("--symbols", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not disasm.available():
        print("capstone is required: pip install capstone")
        return 2

    a_rva, b_rva = int(args.a, 16), int(args.b, 16)
    module = pe_mod.PE(args.dll)

    if args.symbols:
        table = SymbolTable.load_tsv(args.symbols)
        diff = cmp_mod.compare_with_table(module, table, a_rva, b_rva)
    else:
        diff = cmp_mod.compare(module, a_rva, b_rva)

    if args.json:
        print(json.dumps(diff.summary(), indent=2, default=str))
        return 0

    print("A: 0x%X  size 0x%X" % (a_rva, diff.a_size))
    print("B: 0x%X  size 0x%X" % (b_rva, diff.b_size))
    print()
    print("same size      : %s" % ("yes" if diff.same_size else "no"))
    print("byte diffs     : %d byte(s) in %d range(s)" % (
        sum(e - s for s, e in diff.byte_ranges), len(diff.byte_ranges)))
    print("instruction diffs: %d" % len(diff.insn_diffs))
    print("immediate diffs: %d" % len(diff.immediate_diffs))
    print()
    print("VERDICT: %s" % (
        "isomorphic (same template)" if diff.isomorphic else "not the same template"))

    if diff.insn_diffs:
        print()
        print("%-10s %-8s %-34s %s" % ("offset", "kind", "A", "B"))
        print("-" * 100)
        for d in diff.insn_diffs[:25]:
            if d["kind"] == "length":
                print("instruction count differs: A=%d B=%d" % (
                    d["a_count"], d["b_count"]))
                continue
            print("+0x%-7X %-8s %-34s %s" % (
                d.get("offset", 0), d["kind"], d.get("a", ""), d.get("b", "")))
        if len(diff.insn_diffs) > 25:
            print("... %d more" % (len(diff.insn_diffs) - 25))
    return 0


if __name__ == "__main__":
    sys.exit(main())
