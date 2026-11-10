#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Compare two functions to decide whether they were generated from one template.

RPC wrappers come in families. When two wrappers have the same size and differ
only in immediates and ``rel32`` displacements, they are the same template with
substituted constants -- which means the argument register layout of one can be
reused for the other. That saves a whole round of runtime calibration.

The converse is just as useful: if the instruction counts differ, or the
mnemonics diverge, the functions are not siblings and their parameter semantics
must not be assumed identical.
"""
from . import disasm


class FunDiff(object):
    def __init__(self):
        self.a = None
        self.b = None
        self.a_size = 0
        self.b_size = 0
        self.byte_ranges = []
        self.insn_equal = None
        self.insn_diffs = []
        self.immediate_diffs = []

    @property
    def same_size(self):
        return self.a_size == self.b_size

    @property
    def isomorphic(self):
        """Same instruction stream apart from constants and branch targets."""
        if self.insn_equal is False:
            return False
        return self.same_size and all(
            d["kind"] in ("immediate", "address") for d in self.insn_diffs)

    def summary(self):
        return {
            "a": self.a, "b": self.b,
            "a_size": self.a_size, "b_size": self.b_size,
            "same_size": self.same_size,
            "byte_diff_bytes": sum(e - s for s, e in self.byte_ranges),
            "byte_diff_ranges": len(self.byte_ranges),
            "isomorphic": self.isomorphic,
            "immediate_diffs": len(self.immediate_diffs),
        }


def diff_ranges(da, db):
    """Byte ranges where two buffers differ, as ``[(start, end)]``."""
    ranges = []
    limit = min(len(da), len(db))
    start = None
    for i in range(limit):
        if da[i] != db[i]:
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, limit))
    return ranges


def compare(pe, a_rva, b_rva, a_size=None, b_size=None):
    """Diff the functions at *a_rva* and *b_rva*."""
    result = FunDiff()
    result.a, result.b = a_rva, b_rva

    a_size = a_size or 0x400
    b_size = b_size or 0x400
    da = disasm.read_code(pe, a_rva, a_size)
    db = disasm.read_code(pe, b_rva, b_size)
    result.a_size = len(da)
    result.b_size = len(db)

    result.byte_ranges = diff_ranges(da, db)

    ia = disasm.disassemble_bytes(da, a_rva)
    ib = disasm.disassemble_bytes(db, b_rva)

    if len(ia) != len(ib):
        result.insn_equal = False
        result.insn_diffs.append({
            "kind": "length",
            "a_count": len(ia),
            "b_count": len(ib),
        })
        return result

    result.insn_equal = True
    for idx, (x, y) in enumerate(zip(ia, ib)):
        if x.mnemonic != y.mnemonic:
            result.insn_equal = False
            result.insn_diffs.append({
                "kind": "mnemonic", "index": idx,
                "offset": x.address - a_rva,
                "a": "%s %s" % (x.mnemonic, x.op_str),
                "b": "%s %s" % (y.mnemonic, y.op_str),
            })
            continue
        if x.op_str != y.op_str:
            entry = {
                "kind": _classify_diff(x, y),
                "index": idx,
                "offset": x.address - a_rva,
                "a": "%s %s" % (x.mnemonic, x.op_str),
                "b": "%s %s" % (y.mnemonic, y.op_str),
            }
            result.insn_diffs.append(entry)
            if entry["kind"] == "immediate":
                result.immediate_diffs.append(entry)
    return result


def _classify_diff(x, y):
    """Why do two same-mnemonic instructions differ?

    ``address``   -- a direct call/jump target. The two functions live at
                     different RVAs, so the absolute target always differs
                     while the encoding may be identical; this is not a
                     semantic difference.
    ``immediate`` -- a constant operand. This is the interesting case: it is
                     usually the substituted methodId.
    ``operand``   -- anything else (register, memory form), i.e. the functions
                     are not the same template.
    """
    if x.mnemonic in ("call", "jmp") and len(x.operands) == 1 and len(y.operands) == 1:
        if _is_direct(x.operands[0]) and _is_direct(y.operands[0]):
            return "address"
    if _imm_only_differs(x, y):
        return "immediate"
    return "operand"


def _is_direct(op):
    return disasm.is_direct(op)


def _imm_only_differs(x, y):
    """True when the only operand difference is an immediate value."""
    if len(x.operands) != len(y.operands):
        return False
    saw_imm = False
    for ox, oy in zip(x.operands, y.operands):
        if getattr(ox, "imm", None) != getattr(oy, "imm", None):
            if ox.type != oy.type:
                return False
            saw_imm = True
        elif getattr(ox, "reg", None) != getattr(oy, "reg", None):
            return False
    return saw_imm


def compare_with_table(pe, table, a_rva, b_rva):
    """Convenience wrapper that takes sizes from a symbol table.

    Uses :meth:`SymbolTable.effective_size` so a stored size of 0 still yields a
    tight bound -- otherwise the comparison reads to the end of the section and
    every pair of functions looks like it differs in length.
    """
    a = table.exact(a_rva)
    b = table.exact(b_rva)
    return compare(pe, a_rva, b_rva,
                   a_size=table.effective_size(a) if a else None,
                   b_size=table.effective_size(b) if b else None)
