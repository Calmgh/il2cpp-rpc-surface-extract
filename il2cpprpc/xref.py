#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Find call sites that target a given RVA.

Used for the two questions that decide whether an RPC is worth testing:

* **Who calls this wrapper?** The caller tells you the real entry path. A
  wrapper reached only from a UI button that appears at close range cannot be
  driven remotely, no matter how the RPC itself is written.
* **Who reads this field?** If the reads are all in UI code, the field is local
  display state and there is no client-side gate; if a read appears in a send
  or validation function, there is a check to bypass.

Scanning is byte-level (``E8``/``E9`` + rel32) rather than full disassembly:
it covers sections that capstone cannot follow linearly and it is an order of
magnitude faster on a 180 MB module. The trade-off is false positives from
immediate data that happens to look like a call, which ``verify=True`` filters
by checking that the site lies inside a known function.
"""
import collections
import struct

CallSite = collections.namedtuple("CallSite", "site target kind")

OP_CALL = 0xE8
OP_JMP = 0xE9


def find_callers(pe, targets, verify_table=None, max_hits_per_target=64):
    """Return :class:`CallSite` entries whose target is in *targets*.

    *verify_table* is an optional :class:`il2cpprpc.table.SymbolTable`; when
    given, a hit is only kept if its site falls inside a known function.
    """
    wanted = set(targets)
    hits = []
    seen = collections.Counter()

    for section in pe.executable_sections():
        data = pe.section_data(section)
        if len(data) < 5:
            continue
        for opcode, kind in ((OP_CALL, "call"), (OP_JMP, "jmp")):
            needle = bytes([opcode])
            pos = data.find(needle)
            while pos >= 0 and pos + 5 <= len(data):
                site = section.va + pos
                rel, = struct.unpack_from("<i", data, pos + 1)
                target = site + 5 + rel
                if target in wanted:
                    if verify_table is None or verify_table.owner(site) is not None:
                        if seen[target] < max_hits_per_target:
                            seen[target] += 1
                            hits.append(CallSite(site, target, kind))
                pos = data.find(needle, pos + 1)
    hits.sort(key=lambda c: (c.target, c.site))
    return hits


def describe_callers(pe, table, hits):
    """Attach the enclosing function name to each call site."""
    out = []
    for site in hits:
        owner = table.owner(site.site) if table is not None else None
        out.append({
            "site": site.site,
            "target": site.target,
            "kind": site.kind,
            "owner": owner.name if owner else None,
            "owner_rva": owner.rva if owner else None,
        })
    return out


def call_sites_by_target(hits):
    grouped = collections.defaultdict(list)
    for hit in hits:
        grouped[hit.target].append(hit.site)
    return collections.OrderedDict(sorted(grouped.items()))


def string_refs(pe, needle):
    """Offsets where *needle* appears in readable sections.

    Useful when you have a literal (a UI hint, a config key) and want the code
    that references it: find the string's RVA, then look for ``lea reg,
    [rip+disp]`` pointing at it.
    """
    if isinstance(needle, str):
        needle = needle.encode("utf-8")
    found = []
    for section in pe.sections:
        if not (section.characteristics & 0x40000000):   # IMAGE_SCN_MEM_READ
            continue
        data = pe.section_data(section)
        pos = data.find(needle)
        while pos >= 0:
            found.append(section.va + pos)
            pos = data.find(needle, pos + 1)
    return found


def lea_targets(pe, section=None):
    """Map of ``lea reg, [rip+disp]`` sites to the address they reference.

    Cheap two-byte prefix scan (``48 8D``) followed by a length decode. Good
    enough to find "which code loads this string/global", which is the question
    that matters; not a full instruction decoder.
    """
    out = {}
    for sec in ([section] if section else pe.executable_sections()):
        data = pe.section_data(sec)
        pos = data.find(b"\x48\x8d")
        while pos >= 0 and pos + 7 <= len(data):
            modrm = data[pos + 2]
            # mod=00, rm=101 -> rip-relative disp32
            if (modrm & 0xC7) == 0x05:
                disp, = struct.unpack_from("<i", data, pos + 3)
                site = sec.va + pos
                out[site] = site + 7 + disp
            pos = data.find(b"\x48\x8d", pos + 1)
    return out
