#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Find call sites for one or more target RVAs.

Usage::

    python tools/find_callers.py GameAssembly.dll --target 0x1A2B3C0 [options]

Options::

    --symbols FILE    optional symbol table, used to name the enclosing function
    --verify          only keep sites that fall inside a known function
    --json            machine-readable output

Why this matters before testing anything: an RPC wrapper's caller determines
whether the entry is reachable in the situation the attack assumes. A wrapper
fired only from a button that appears at close range cannot be driven remotely,
regardless of how the RPC itself is written. Checking this costs a minute and
can save a whole round of testing that was never going to work.
"""
import argparse
import json
import sys

import _common  # noqa: F401

from il2cpprpc import pe as pe_mod, xref
from il2cpprpc.table import SymbolTable


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("--target", action="append", required=True,
                    help="target RVA, repeatable")
    ap.add_argument("--symbols", default=None)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    targets = [int(t, 16) for t in args.target]
    table = SymbolTable.load_tsv(args.symbols) if args.symbols else None

    module = pe_mod.PE(args.dll)
    hits = xref.find_callers(module, targets,
                             verify_table=table if args.verify else None)
    described = xref.describe_callers(module, table, hits)

    if args.json:
        print(json.dumps(described, indent=2))
        return 0

    print("module  : %s" % args.dll)
    print("targets : %s" % ", ".join("0x%X" % t for t in targets))
    print("sites   : %d" % len(described))
    print()

    for target in targets:
        mine = [d for d in described if d["target"] == target]
        print("0x%X  %d call site(s)" % (target, len(mine)))
        if not mine:
            print("   no direct call or jump found.")
            print("   The wrapper may be reached through a vtable slot, a")
            print("   function pointer, or a thunk this scan cannot follow.")
        for d in mine[:20]:
            owner = d["owner"] or "?"
            print("   %-4s 0x%-12X in %s" % (d["kind"], d["site"], owner))
        if len(mine) > 20:
            print("   ... %d more" % (len(mine) - 20))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
