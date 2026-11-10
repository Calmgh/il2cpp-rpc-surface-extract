#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Map methodIds to the client wrapper functions that send them.

Every generated RPC wrapper passes its methodId as an immediate to the shared
send/record helper, so the value appears in the wrapper's own code. That is the
whole trick:

1. enumerate ``*_RemoteCall*`` functions from the symbol table
2. disassemble each one and collect every ``mov reg32, imm32``
3. intersect those immediates with the key set recovered from the registration
   constructors

Anything in the intersection is a real binding. A wrapper with no hit is
usually a generic or ``gshared`` instantiation whose key is loaded indirectly
rather than embedded -- measured hit rate on a production build is around 94%
(471/501), and the misses cluster in exactly those instantiation bodies.

Wrappers frequently carry several hits when one function forwards to more than
one RPC; all of them are reported rather than picking one.
"""
import collections

from . import disasm


class Binding(object):
    __slots__ = ("method_id", "wrapper", "value_rva")

    def __init__(self, method_id, wrapper, value_rva):
        self.method_id = method_id
        self.wrapper = wrapper
        self.value_rva = value_rva

    def __repr__(self):
        return "<0x%08X -> %s>" % (self.method_id, self.wrapper.name)


def find_wrappers(table, pattern="_RemoteCall", ignore_case=False):
    """Client-side RPC wrapper functions.

    Case sensitivity is not cosmetic: symbol names mix cases (``...Load`` next
    to ``...LOad``), and a case-sensitive grep silently drops entries. The
    default here is case-insensitive for that reason; pass
    ``ignore_case=False`` only when you know the exact casing.
    """
    if hasattr(pattern, "search"):
        hits = table.search(pattern)
    else:
        hits = table.search(pattern, ignore_case=ignore_case)
    return [s for s in hits if s.is_function]


def collect_ids(pe, wrapper, size=None):
    """methodId candidates embedded in *wrapper*, most likely first.

    Immediates loaded into ``edx``/``rdx`` are ranked first: that is the
    argument register the send helper uses for the key.
    """
    insns = disasm.disassemble_symbol(pe, wrapper, size=size)
    loads = disasm.imm32_loads(insns)
    primary = []
    secondary = []
    for reg, value, addr in loads:
        if reg in ("edx", "rdx", "dx"):
            primary.append((value, addr))
        else:
            secondary.append((value, addr))
    return primary + secondary


def build_mapping(pe, wrappers, known_ids, table=None):
    """Intersect wrapper immediates with *known_ids*.

    Pass *table* to bound each wrapper by its effective size; without it a
    wrapper whose stored size is 0 is read generously and may absorb the next
    function's constants.

    Returns ``(bindings, unmatched)`` where *unmatched* is the list of wrappers
    that yielded no known key.
    """
    known = set(known_ids)
    bindings = []
    unmatched = []
    for wrapper in wrappers:
        size = table.effective_size(wrapper) if table is not None else None
        hits = [(value, addr) for value, addr in collect_ids(pe, wrapper, size=size)
                if value in known]
        if not hits:
            unmatched.append(wrapper)
            continue
        seen = set()
        for value, addr in hits:
            if value in seen:
                continue
            seen.add(value)
            bindings.append(Binding(value, wrapper, addr))
    return bindings, unmatched


def group_by_id(bindings):
    """``{method_id: [wrapper names]}``, sorted."""
    grouped = collections.defaultdict(list)
    for b in bindings:
        if b.wrapper.name not in grouped[b.method_id]:
            grouped[b.method_id].append(b.wrapper.name)
    return collections.OrderedDict(sorted(grouped.items()))


def group_by_component(bindings):
    """Group by the ``<Component>`` prefix of ``<Component>_RemoteCall<Name>``.

    This is the view that turns a flat list into an attack surface: components
    with many wrappers are where the protocol is dense and worth reading first.
    """
    grouped = collections.defaultdict(list)
    for b in bindings:
        grouped[component_of(b.wrapper.name)].append(b)
    return collections.OrderedDict(
        sorted(grouped.items(), key=lambda kv: -len(kv[1])))


def component_of(name):
    """``WorldXxx_RemoteCallFoo`` -> ``WorldXxx``."""
    marker = "_RemoteCall"
    if marker in name:
        return name.split(marker, 1)[0]
    if "_" in name:
        return name.split("_", 1)[0]
    return name


def coverage(bindings, wrappers):
    """Fraction of wrappers that received at least one binding."""
    if not wrappers:
        return 0.0
    matched = {b.wrapper.name for b in bindings}
    return len(matched) / float(len(wrappers))
