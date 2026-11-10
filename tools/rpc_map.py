#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bind methodIds to the client wrapper functions that send them.

Usage::

    python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv \\
        --registry registry.tsv [options]

Options::

    --pattern TEXT    wrapper name filter (default: _RemoteCall)
    --case-sensitive  do not fold case (default is case-insensitive on purpose)
    --out FILE        write the mapping (default: rpc_map.tsv)
    --by-component    print the component summary only

Output rows: ``0x<method_id>\\t<wrapper>\\t<component>``

Mechanism: each generated wrapper embeds its methodId as an immediate before
calling the shared send helper. Intersecting those immediates with the
registration key set gives the binding. Wrappers with no hit are almost always
generic/gshared instantiations that load the key indirectly.
"""
import argparse
import os
import sys

import _common  # noqa: F401

from il2cpprpc import disasm, mapping, pe as pe_mod
from il2cpprpc.table import SymbolTable


def load_registry(path):
    ids = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if parts and parts[0].startswith("0x"):
                ids.append(int(parts[0], 16))
    return sorted(set(ids))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("--symbols", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--pattern", default="_RemoteCall")
    ap.add_argument("--case-sensitive", action="store_true")
    ap.add_argument("--out", default="rpc_map.tsv")
    ap.add_argument("--by-component", action="store_true")
    args = ap.parse_args(argv)

    if not disasm.available():
        print("capstone is required: pip install capstone")
        return 2

    table = SymbolTable.load_tsv(args.symbols)
    known = load_registry(args.registry)
    if not known:
        print("registry %s contains no methodIds" % args.registry)
        return 2

    wrappers = mapping.find_wrappers(
        table, args.pattern, ignore_case=not args.case_sensitive)
    print("symbols        : %d" % len(table))
    print("registry keys  : %d" % len(known))
    print("wrappers       : %d  (pattern %r%s)" % (
        len(wrappers), args.pattern,
        ", case-sensitive" if args.case_sensitive else ", case-insensitive"))
    if not wrappers:
        return 2

    module = pe_mod.PE(args.dll)
    bindings, unmatched = mapping.build_mapping(module, wrappers, known, table=table)
    rate = mapping.coverage(bindings, wrappers)

    print("bound          : %d wrappers (%.1f%%)" % (
        len(wrappers) - len(unmatched), rate * 100))
    print("unmatched      : %d" % len(unmatched))
    print("bindings       : %d" % len(bindings))
    print()

    grouped = mapping.group_by_id(bindings)
    if not args.by_component:
        print("%-12s %s" % ("methodId", "wrapper"))
        print("-" * 90)
        for method_id, names in list(grouped.items())[:40]:
            print("0x%08X   %s" % (method_id, ", ".join(names)))
        if len(grouped) > 40:
            print("... %d more (see %s)" % (len(grouped) - 40, args.out))
        print()

    components = mapping.group_by_component(bindings)
    print("components     : %d" % len(components))
    print("%-40s %6s" % ("component", "rpcs"))
    print("-" * 48)
    for name, items in list(components.items())[:30]:
        print("%-40s %6d" % (name, len(items)))
    if len(components) > 30:
        print("... %d more" % (len(components) - 30))

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# method_id\twrapper\tcomponent\n")
        for b in sorted(bindings, key=lambda x: (x.method_id, x.wrapper.name)):
            f.write("0x%08X\t%s\t%s\n" % (
                b.method_id, b.wrapper.name, mapping.component_of(b.wrapper.name)))
    print()
    print("written        : %s" % args.out)

    if unmatched:
        print()
        print("%d wrappers had no key in the registry. Those are usually generic" % len(unmatched))
        print("or gshared instantiations. Spot-check a few before assuming the")
        print("registry is incomplete:")
        for sym in unmatched[:5]:
            print("   %s  0x%X" % (sym.name, sym.rva))
    return 0


if __name__ == "__main__":
    sys.exit(main())
