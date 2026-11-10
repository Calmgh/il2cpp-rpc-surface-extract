#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Dump the string heap of ``global-metadata.dat`` around a known member name.

Usage::

    python tools/metadata_dump.py <global-metadata.dat> --anchor AddStyleRank

Options::

    --anchor TEXT     known member name (repeatable, or comma-separated)
    --before N        bytes to scan before the anchor (default 0x300)
    --after N         bytes after the anchor (default 0x700)
    --occurrence N    which hit to use when the anchor repeats (default 0)
    --min-len N       shortest string to keep (default 3)
    --classify        group output into attributes / methods / properties / fields

IL2CPP groups metadata strings by owner, so one class's method names, field
names, attribute names and enum values sit next to each other. Locate one member
and read the neighbourhood.

This surfaces things a decompiler hides: enum values (``Publish`` / ``Dev``),
attribute class names that drive permission tiers, UI grouping fields.
"""
import argparse
import sys

import _common  # noqa: F401

from il2cpprpc import metadata as md


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--anchor", action="append", required=True,
                    help="repeatable; comma-separated also accepted")
    ap.add_argument("--before", default="0x300")
    ap.add_argument("--after", default="0x700")
    ap.add_argument("--occurrence", type=int, default=0)
    ap.add_argument("--min-len", type=int, default=3)
    ap.add_argument("--classify", action="store_true")
    ap.add_argument("--limit", type=int, default=400)
    args = ap.parse_args(argv)

    anchors = []
    for item in args.anchor:
        anchors.extend(a.strip() for a in item.split(",") if a.strip())

    before = int(args.before, 0)
    after = int(args.after, 0)

    if len(anchors) > 1:
        offsets, strings = md.neighbour_map(
            args.path, anchors, before=before, after=after, min_len=args.min_len)
        print("file    : %s" % args.path)
        print("anchors : %d found" % len(offsets))
        for anchor, offset in offsets.items():
            print("   0x%-10X %s" % (offset, anchor))
        print("strings : %d unique" % len(strings))
        print()
        _emit(strings, args)
        return 0

    anchor = anchors[0]
    try:
        offset, strings = md.dump_around(
            args.path, anchor, before=before, after=after,
            min_len=args.min_len, occurrence=args.occurrence)
    except KeyError as exc:
        print(exc)
        print()
        print("The anchor is not in this file. Check spelling, or try a shorter")
        print("fragment -- metadata strings are not case-folded, so")
        print("'AddStyleRank' and 'addstylerank' are different bytes.")
        return 2

    print("file    : %s" % args.path)
    print("anchor  : %s  at 0x%X" % (anchor, offset))
    print("window  : -0x%X .. +0x%X" % (before, after))
    print("strings : %d" % len(strings))
    print()
    _emit(strings, args)
    return 0


def _emit(strings, args):
    if args.classify:
        buckets = md.classify(strings)
        for name, items in buckets.items():
            if not items:
                continue
            print("## %s (%d)" % (name, len(items)))
            for item in items[:args.limit]:
                print("   %s" % item)
            if len(items) > args.limit:
                print("   ... %d more" % (len(items) - args.limit))
            print()
    else:
        for item in strings[:args.limit]:
            print("   %s" % item)
        if len(strings) > args.limit:
            print("   ... %d more" % (len(strings) - args.limit))


if __name__ == "__main__":
    sys.exit(main())
