#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Recover the RPC registration table from its static constructor.

IL2CPP builds one ``Dictionary<int, RpcInfo>`` per entity type, populated by a
``*RpcInfo__cctor`` function. The constructor is ordinary linear code: for each
entry it creates an ``RpcInfo``, then calls ``Dictionary.Add(this, methodId,
value, methodInfo)``.

The call sequence, in the x64 fastcall convention, is::

    mov  r8, rdi          ; TValue  = the RpcInfo object
    mov  r9, [rip+C]      ; TMethod = Dictionary_2_Add_RuntimeMethod_var
    mov  edx, <methodId>  ; TKey    -- a 4-byte immediate, this is what we want
    mov  rcx, rbx         ; this    = the dictionary
    call <Dictionary_2_Add>

So the signature is ``mov edx, imm32`` + ``mov rcx, reg`` + ``call``. Collecting
those immediates gives the complete key set of the table.

What this does **not** give you: the handler function for each key. Handlers are
resolved at runtime and are not present in the static registration code. Map
keys to wrapper functions with :mod:`il2cpprpc.mapping` instead.
"""
import collections

from . import disasm


class MethodIdEntry(object):
    __slots__ = ("method_id", "site_rva", "ctor")

    def __init__(self, method_id, site_rva, ctor):
        self.method_id = method_id
        self.site_rva = site_rva
        self.ctor = ctor

    def __repr__(self):
        return "<methodId 0x%08X @0x%X in %s>" % (
            self.method_id, self.site_rva, self.ctor)


def find_registration_ctors(table, pattern=r"RpcInfo__cctor", ignore_case=True):
    """Functions that look like RPC registration table constructors.

    Names typically end in ``__cctor`` and contain a type-ish prefix, e.g.
    ``WorldRpcInfo__cctor``. The function size correlates with the number of
    registered entries (roughly 0x5A bytes each), which is a useful sanity
    check: a 0x1184D-byte constructor is not a 3-entry table.
    """
    hits = [s for s in table.functions() if _matches(s.name, pattern, ignore_case)]
    hits.sort(key=lambda s: -s.size)
    return hits


def _matches(name, pattern, ignore_case):
    if hasattr(pattern, "search"):
        return bool(pattern.search(name))
    if ignore_case:
        return pattern.lower() in name.lower()
    return pattern in name


def extract_method_ids(pe, symbol, key_reg="EDX", this_reg="RCX",
                       gap=0, limit=None, size=None):
    """Return the methodIds registered by *symbol*.

    *gap* allows that many instructions between the key load and the ``call``;
    the default 0 encodes the exact three-instruction shape. Raising it trades
    precision for recall -- the registration code is generated, so the strict
    form matches in practice.

    *size* bounds the disassembly; pass
    ``SymbolTable.effective_size(symbol)`` when the table stores 0, otherwise
    adjacent functions contribute their immediates.
    """
    insns = disasm.disassemble_symbol(pe, symbol, size=size)
    if not insns:
        return []

    found = []
    n = len(insns)
    for i, insn in enumerate(insns):
        if not disasm.is_mov_imm_to_reg(insn, key_reg):
            continue
        # Look for `mov this_reg, reg` followed by a call, within the gap budget.
        for j in range(i + 1, min(i + 2 + gap, n)):
            if not disasm.is_mov_reg_to_reg(insns[j], this_reg):
                continue
            for k in range(j + 1, min(j + 1 + gap + 1, n)):
                if insns[k].mnemonic == "call":
                    found.append(MethodIdEntry(
                        disasm.imm32(insn), insn.address, symbol.name))
                    break
            break
        if limit is not None and len(found) >= limit:
            break
    return found


def extract_all(pe, ctors, **kwargs):
    """Run :func:`extract_method_ids` over many constructors.

    Returns ``(entries, per_ctor_counts)``. Duplicate methodIds across
    constructors are kept: the same key can legitimately appear in more than
    one table when a type is reachable through several channels.
    """
    entries = []
    counts = collections.OrderedDict()
    for ctor in ctors:
        got = extract_method_ids(pe, ctor, **kwargs)
        counts[ctor.name] = len(got)
        entries.extend(got)
    return entries, counts


def unique_ids(entries):
    """Sorted unique methodIds."""
    return sorted({e.method_id for e in entries})


def table_size_hint(symbol, bytes_per_entry=0x5A):
    """Rough entry count implied by a constructor's size."""
    if not symbol.size:
        return None
    return int(round(symbol.size / float(bytes_per_entry)))
