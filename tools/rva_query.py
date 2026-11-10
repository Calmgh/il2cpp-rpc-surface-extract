#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Query a symbol table: RVA -> name, owner lookup, and name search.

Usage::

    python tools/rva_query.py --symbols sym_funcs.tsv [queries...]

Queries::

    --rva 0x1A2B3C0       symbol starting exactly at this RVA
    --owner 0x1A2B9F1     symbol whose range contains this RVA
    --search RemoteCall   name substring (case-insensitive)
    --regex "^World.*Ack" regular expression over names
    --count               with --search/--regex, print only the number of hits

Any number of queries can be passed in one call; results are printed in order.

``--owner`` is the one that matters when you have a call site: an xref lands
inside a function, not on its entry.
"""
import argparse
import re
import sys

import _common  # noqa: F401

from il2cpprpc.table import SymbolTable


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--symbols", required=True)
    ap.add_argument("--rva", action="append", default=[])
    ap.add_argument("--owner", action="append", default=[])
    ap.add_argument("--search", action="append", default=[])
    ap.add_argument("--regex", action="append", default=[])
    ap.add_argument("--count", action="store_true")
    ap.add_argument("--limit", type=int, default=60)
    args = ap.parse_args(argv)

    table = SymbolTable.load_tsv(args.symbols)
    print("symbols: %d" % len(table))

    for raw in args.rva:
        rva = int(raw, 16)
        sym = table.exact(rva)
        print()
        print("[exact] 0x%X" % rva)
        if sym:
            print("   %-8s 0x%X  tag=%d  %s" % (
                "size", sym.size, sym.tag, sym.name))
        else:
            near = table.owner(rva)
            print("   no symbol starts here")
            if near:
                print("   nearest preceding: %s (0x%X, +0x%X)" % (
                    near.name, near.rva, rva - near.rva))

    for raw in args.owner:
        rva = int(raw, 16)
        sym = table.owner(rva)
        print()
        print("[owner] 0x%X" % rva)
        if sym:
            print("   %s" % sym.name)
            print("   entry 0x%X  size 0x%X  offset +0x%X" % (
                sym.rva, sym.size, rva - sym.rva))
        else:
            print("   nothing contains this address")

    for pattern in args.search:
        hits = table.search(pattern, ignore_case=True)
        _report(hits, "search %r" % pattern, args)

    for pattern in args.regex:
        rx = re.compile(pattern)
        hits = table.search(rx)
        _report(hits, "regex %r" % pattern, args)

    return 0


def _report(hits, label, args):
    print()
    print("[%s] %d hit(s)" % (label, len(hits)))
    if args.count:
        return
    for sym in hits[:args.limit]:
        print("   0x%-12X %6s  %s" % (
            sym.rva, "0x%X" % sym.size if sym.size else "-", sym.name))
    if len(hits) > args.limit:
        print("   ... %d more (raise --limit)" % (len(hits) - args.limit))


if __name__ == "__main__":
    sys.exit(main())
