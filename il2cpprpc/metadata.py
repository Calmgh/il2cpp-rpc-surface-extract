#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Dump the string heap of ``global-metadata.dat`` around a known member name.

IL2CPP stores metadata strings grouped by owner: one class's method names,
field names, attribute names and enum values sit next to each other. Locate any
single member name and the neighbourhood gives you the rest, including things a
decompiler will not show you -- attribute class names, permission enum values,
UI grouping fields.

This is a byte-range reader, not a metadata parser: it does not understand the
header, the string-literal table, or the type definitions. That is the point.
It works on any build without chasing offsets that move between versions.
"""
import collections

DEFAULT_MIN_LEN = 3


def find_all(data, needle):
    """Offsets of *needle* in *data* (bytes or str)."""
    if isinstance(needle, str):
        needle = needle.encode("utf-8")
    out = []
    pos = data.find(needle)
    while pos >= 0:
        out.append(pos)
        pos = data.find(needle, pos + 1)
    return out


def read_region(path, offset, before, after):
    """Read ``[offset-before, offset+after)`` clamped to the file."""
    with open(path, "rb") as f:
        size = f.seek(0, 2)
        start = max(0, offset - before)
        end = min(size, offset + after)
        f.seek(start)
        return start, f.read(end - start)


def iter_strings(blob, min_len=DEFAULT_MIN_LEN, ascii_only=True):
    """Split a heap fragment on NUL and yield plausible strings."""
    for raw in blob.split(b"\x00"):
        if len(raw) < min_len:
            continue
        if ascii_only:
            if not all(32 <= c < 127 for c in raw):
                continue
        try:
            yield raw.decode("utf-8")
        except UnicodeDecodeError:
            continue


def dump_around(path, anchor, before=0x300, after=0x700,
                min_len=DEFAULT_MIN_LEN, ascii_only=True, occurrence=0):
    """Return the strings surrounding *anchor* in the metadata file.

    Returns ``(offset, strings)``. ``occurrence`` selects which hit to use when
    the anchor appears more than once.
    """
    with open(path, "rb") as f:
        data = f.read()
    hits = find_all(data, anchor)
    if not hits:
        raise KeyError("anchor %r not found in %s" % (anchor, path))
    if occurrence >= len(hits):
        occurrence = 0
    offset = hits[occurrence]
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    strings = list(iter_strings(data[start:end], min_len=min_len,
                                ascii_only=ascii_only))
    return offset, strings


def classify(strings):
    """Rough grouping so a 500-name dump is readable.

    The buckets are heuristics; their job is to let a human scan, not to be
    authoritative.
    """
    buckets = collections.OrderedDict([
        ("attributes", []),
        ("methods", []),
        ("properties", []),
        ("fields", []),
        ("other", []),
    ])
    for name in strings:
        lowered = name.lower()
        if name.endswith("Attribute") or "Attribute" in name:
            buckets["attributes"].append(name)
        elif "(" in name or name.startswith(("get_", "set_", "add_", "remove_")):
            buckets["properties"].append(name)
        elif name[:1].isupper() and "_" in name and all(
                part[:1].isupper() for part in name.split("_") if part):
            buckets["methods"].append(name)
        elif name[:1].isupper():
            buckets["methods"].append(name)
        elif name[:1].islower():
            buckets["fields"].append(name)
        else:
            buckets["other"].append(name)
    return buckets


def neighbour_map(path, anchors, before=0x200, after=0x400,
                  min_len=DEFAULT_MIN_LEN):
    """Dump around several anchors and merge, de-duplicated in encounter order.

    Useful for reconstructing a whole type: pass the few member names you
    already know from a decompiler and read back the union of their
    neighbourhoods.
    """
    seen = set()
    ordered = []
    offsets = {}
    for anchor in anchors:
        try:
            offset, strings = dump_around(path, anchor, before, after,
                                          min_len=min_len)
        except KeyError:
            continue
        offsets[anchor] = offset
        for s in strings:
            if s not in seen:
                seen.add(s)
                ordered.append(s)
    return offsets, ordered
