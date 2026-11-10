#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Export the full symbol table of an IL2CPP module.

Usage::

    python tools/export_symbols.py GameAssembly.dll [options]

Options::

    --pdb-dir DIR     where to look for the PDB (default: the DLL's directory)
    --out PREFIX      output prefix (default: GameAssembly_symbols)
    --mask GLOB       dbghelp filter, e.g. "*RemoteCall*" (default: "*")
    --from-pdb        use the portable pure-Python reader instead of dbghelp
    --quiet           no progress output

Outputs::

    <prefix>.tsv              every symbol
    <prefix>_funcs.tsv        tag 5 only -- the main query table
    <prefix>_methvars.tsv     tag 7 whose name ends in _RuntimeMethod_var

Row format: ``0x<RVA>\\t0x<size>\\t<tag>\\t<name>``
"""
import argparse
import os
import sys

import _common  # noqa: F401  (path bootstrap)

from il2cpprpc import dbghelp, pdb, pe as pe_mod
from il2cpprpc.table import SymbolTable, TAG_DATA, TAG_FUNCTION


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll")
    ap.add_argument("--pdb-dir", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--mask", default="*")
    ap.add_argument("--from-pdb", action="store_true",
                    help="parse the PDB in pure Python (no symbol classification)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    prefix = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.dll)), "GameAssembly_symbols")
    out_dir = os.path.dirname(os.path.abspath(prefix))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    module = pe_mod.PE(args.dll)
    print("module   : %s" % args.dll)
    print("imagebase: 0x%X" % module.image_base)
    print("fingerprint: TimeDateStamp=%d SizeOfImage=0x%X" % (
        module.timestamp, module.size_of_image))

    if args.from_pdb:
        symbols = _from_pdb(args.dll, args.pdb_dir)
    else:
        symbols = _from_dbghelp(args.dll, args.pdb_dir, args.mask, args.quiet)

    if not symbols:
        print("\nNo symbols exported.")
        print("Check that GameAssembly.pdb sits next to the DLL and matches this build.")
        return 2

    table = SymbolTable(symbols)
    table.save_tsv(prefix + ".tsv")

    funcs = [s for s in symbols if s.tag == TAG_FUNCTION]
    table.save_tsv(prefix + "_funcs.tsv", funcs)

    methvars = [s for s in symbols if s.tag == TAG_DATA
                and s.name.endswith("_RuntimeMethod_var")]
    table.save_tsv(prefix + "_methvars.tsv", methvars)

    print()
    print("symbols      : %d" % len(symbols))
    print("functions    : %d" % len(funcs))
    print("methvars     : %d" % len(methvars))
    print("written      : %s.tsv, %s_funcs.tsv, %s_methvars.tsv" % (prefix, prefix, prefix))

    if len(funcs) < 1000:
        print()
        print("WARNING: only %d functions. For an IL2CPP build expect 300k-1M."
              % len(funcs))
        print("         Usually a mismatched PDB or a wrong --mask.")
    return 0


def _from_dbghelp(dll, pdb_dir, mask, quiet):
    if not dbghelp.available():
        print("\ndbghelp is only available on Windows.")
        print("Use --from-pdb for the portable reader (loses function/data tags).")
        return []
    progress = None
    if not quiet:
        def progress(count, kept):
            sys.stderr.write("   ... %d symbols scanned, %d kept\n" % (count, kept))
    symbols, base = dbghelp.export_symbols(dll, pdb_dir, mask=mask,
                                           progress=progress)
    print("load base: 0x%X" % base)
    return symbols


def _from_pdb(dll, pdb_dir):
    directory = pdb_dir or os.path.dirname(os.path.abspath(dll))
    candidates = [os.path.join(directory, "GameAssembly.pdb")]
    if not os.path.exists(candidates[0]):
        candidates = [os.path.join(directory, f)
                      for f in os.listdir(directory) if f.lower().endswith(".pdb")]
    if not candidates:
        raise SystemExit("no .pdb found in %s" % directory)

    module = pe_mod.PE(dll)
    with pdb.PDB(candidates[0]) as reader:
        out = []
        for sym in reader.public_symbols(module.section_vas()):
            # S_PUB32 does not distinguish code from data reliably; the CODE
            # flag is the best signal available.
            tag = TAG_FUNCTION if sym.looks_like_function else TAG_DATA
            out.append(_to_symbol(sym, tag))
        return out


def _to_symbol(pub, tag):
    from il2cpprpc.table import Symbol
    return Symbol(pub.rva, 0, tag, pub.name)


if __name__ == "__main__":
    sys.exit(main())
