#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Recover the RPC registration table (methodId key set) from its constructors.

Usage::

    python tools/rpc_registry.py GameAssembly.dll --symbols sym_funcs.tsv [options]

Options::

    --pattern TEXT    constructor name filter (default: RpcInfo__cctor)
    --out FILE        write registry rows (default: registry.tsv)
    --key-reg REG     register holding the key (default: EDX)
    --gap N           instructions allowed between key load and call (default: 0)

Output rows: ``0x<method_id>\\t<constructor>\\t0x<site_rva>``

The constructor is plain generated code: per entry it loads the methodId into
``edx``, the dictionary into ``rcx``, and calls ``Dictionary.Add``. Every such
immediate is a key in that entity's RPC table.
"""
import argparse
import os
import sys

import _common  # noqa: F401

from il2cpprpc import disasm, pe as pe_mod, registry
from il2cpprpc.table import SymbolTable


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("--symbols", required=True, help="*_funcs.tsv from export_symbols")
    ap.add_argument("--pattern", default="RpcInfo__cctor")
    ap.add_argument("--out", default="registry.tsv")
    ap.add_argument("--key-reg", default="EDX")
    ap.add_argument("--gap", type=int, default=0)
    args = ap.parse_args(argv)

    if not disasm.available():
        print("capstone is required: pip install capstone")
        return 2

    table = SymbolTable.load_tsv(args.symbols)
    print("symbols loaded : %d" % len(table))

    ctors = registry.find_registration_ctors(table, args.pattern)
    if not ctors:
        print("\nno constructor matched %r" % args.pattern)
        print("Try a looser pattern, e.g. --pattern cctor")
        return 2

    print("constructors   : %d" % len(ctors))
    print()
    print("%-56s %10s %8s %8s" % ("constructor", "size", "found", "hint"))
    print("-" * 86)

    module = pe_mod.PE(args.dll)
    entries = []
    for ctor in ctors:
        size = table.effective_size(ctor)
        got = registry.extract_method_ids(
            module, ctor, key_reg=args.key_reg, gap=args.gap, size=size)
        hint = registry.table_size_hint(
            ctor.__class__(ctor.rva, size or 0, ctor.tag, ctor.name))
        print("%-56s %10s %8d %8s" % (
            ctor.name, "0x%X" % size if size else "-",
            len(got), hint if hint else "-"))
        entries.extend(got)

    ids = registry.unique_ids(entries)
    print()
    print("entries        : %d" % len(entries))
    print("unique methodIds: %d" % len(ids))
    if entries:
        print("id range       : 0x%08X .. 0x%08X" % (min(ids), max(ids)))

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# method_id\tconstructor\tsite_rva\n")
        for e in sorted(entries, key=lambda x: x.method_id):
            f.write("0x%08X\t%s\t0x%X\n" % (e.method_id, e.ctor, e.site_rva))
    print("written        : %s" % args.out)

    if entries and len(ids) < len(entries) // 4:
        print()
        print("NOTE: many duplicate keys across constructors. A type reachable")
        print("      through several channels legitimately appears in several")
        print("      tables, but a ratio this low can also mean --gap is too loose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
