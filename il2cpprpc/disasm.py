#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""capstone helpers.

The one rule that matters: **always start disassembly at a real instruction
boundary**. Starting mid-instruction can produce zero instructions (an invalid
first byte makes capstone bail), so code that indexes into a stream by address
must build the stream from the function start and then look up the address.

Register numbers are not 0-3. ``EDX`` is 24 and ``RCX`` is 38 in capstone's
x86 tables, and they shift between capstone releases, so they are resolved by
name at call time rather than hardcoded.
"""
try:
    import capstone as _cs
    from capstone import x86_const as _x86
except ImportError:  # pragma: no cover - optional dependency
    _cs = None
    _x86 = None


class DisasmError(RuntimeError):
    pass


def available():
    return _cs is not None


def reg(name):
    """Resolve ``"EDX"`` -> the capstone register id."""
    if _x86 is None:
        raise DisasmError("capstone is required: pip install capstone")
    try:
        return getattr(_x86, "X86_REG_" + name.upper())
    except AttributeError:
        raise DisasmError("unknown register name: %s" % name)


def _engine():
    if _cs is None:
        raise DisasmError("capstone is required: pip install capstone")
    md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
    md.detail = True
    return md


def disassemble_bytes(code, base=0):
    """Disassemble *code* to a list of capstone instructions."""
    return list(_engine().disasm(code, base))


def read_code(pe, rva, size):
    """Read up to *size* bytes at *rva*, clamped to the containing section."""
    section = pe.section_for_rva(rva)
    if section is None:
        return b""
    section_end = section.va + max(section.vsize, section.raw_size)
    size = max(0, min(size, section_end - rva))
    return pe.read_rva(rva, size)


def disassemble_symbol(pe, symbol, max_size=0x10000, size=None):
    """Disassemble a whole function, starting at its entry point.

    *size* overrides ``symbol.size``; pass
    :meth:`il2cpprpc.table.SymbolTable.effective_size` when the table stores 0.
    Without a bound the walk can run into the next function's code, which for a
    registration constructor means absorbing its neighbours' immediates.
    """
    if size is None:
        size = symbol.size
    if not size:
        size = max_size
    size = min(size, max_size)
    code = read_code(pe, symbol.rva, size)
    if not code:
        return []
    return disassemble_bytes(code, symbol.rva)


def is_mov_imm_to_reg(insn, reg_name):
    """``mov <reg32>, imm32``."""
    if insn.mnemonic != "mov" or len(insn.operands) != 2:
        return False
    dst, src = insn.operands
    return (dst.type == _cs.CS_OP_REG and dst.reg == reg(reg_name)
            and src.type == _cs.CS_OP_IMM and src.size == 4)


def is_mov_reg_to_reg(insn, dst_reg_name, src_reg_name=None):
    """``mov <dst32>, <src32>``; any source register when *src_reg_name* is None."""
    if insn.mnemonic != "mov" or len(insn.operands) != 2:
        return False
    dst, src = insn.operands
    if dst.type != _cs.CS_OP_REG or dst.reg != reg(dst_reg_name):
        return False
    if src.type != _cs.CS_OP_REG:
        return False
    return src_reg_name is None or src.reg == reg(src_reg_name)


def imm32(insn, index=1):
    return insn.operands[index].imm & 0xFFFFFFFF


def is_direct(operand):
    """True for a direct (immediate) branch target operand."""
    return _cs is not None and operand.type == _cs.CS_OP_IMM


def imm32_loads(insns):
    """Every ``mov <reg32>, imm32`` as ``(register_name, value, address)``."""
    out = []
    for insn in insns:
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if dst.type != _cs.CS_OP_REG or src.type != _cs.CS_OP_IMM:
            continue
        if src.size != 4:
            continue
        try:
            name = insn.reg_name(dst.reg)
        except Exception:
            continue
        out.append((name, src.imm & 0xFFFFFFFF, insn.address))
    return out


def direct_calls(insns):
    """Map of instruction address -> target address, for direct ``call``."""
    out = {}
    for insn in insns:
        if insn.mnemonic == "call" and insn.operands:
            op = insn.operands[0]
            if op.type == _cs.CS_OP_IMM:
                out[insn.address] = op.imm
    return out


def direct_jumps(insns):
    out = {}
    for insn in insns:
        if insn.mnemonic == "jmp" and insn.operands:
            op = insn.operands[0]
            if op.type == _cs.CS_OP_IMM:
                out[insn.address] = op.imm
    return out


def callers_of(insns, targets):
    """Direct calls whose target is in *targets*: ``[(site, target)]``."""
    wanted = set(targets)
    return [(site, tgt) for site, tgt in direct_calls(insns).items() if tgt in wanted]


# --------------------------------------------------------------------- misc

def segment_info(pe, rva):
    section = pe.section_for_rva(rva)
    if section is None:
        return None
    return {"section": section.name,
            "offset_in_section": rva - section.va,
            "section_va": section.va,
            "section_size": max(section.vsize, section.raw_size)}


TERMINATORS = {0xC3, 0xC2, 0xCC, 0x90, 0xEB, 0xE9}
PROLOGUES = (b"\x48\x89\x5C\x24", b"\x40\x53", b"\x55\x48\x8B\xEC",
             b"\x48\x8B\xC4", b"\x48\x83\xEC", b"\x48\x81\xEC")


def check_entry(pe, rva):
    """Collect the evidence for "is this really a function entry?"."""
    head = read_code(pe, rva, 8)
    if not head:
        return {"ok": False, "reason": "no code at rva"}
    prev = read_code(pe, rva - 1, 1) if rva > 0 else b""
    prologue = any(head.startswith(p) for p in PROLOGUES)
    terminator = bool(prev) and prev[0] in TERMINATORS
    return {
        "ok": prologue and terminator,
        "prologue": prologue,
        "terminator_before": terminator,
        "first_bytes": head.hex(" "),
        "prev_byte": prev.hex() if prev else None,
    }


def jmp_patchable(pe, rva, patch_len=5):
    """Can a 5-byte ``E9 rel32`` land on an instruction boundary here?"""
    code = read_code(pe, rva, 32)
    if len(code) < patch_len:
        return {"ok": False, "reason": "not enough bytes"}
    insns = disassemble_bytes(code, rva)
    if not insns:
        return {"ok": False, "reason": "cannot decode"}
    consumed = 0
    displaced = []
    for insn in insns:
        consumed += insn.size
        displaced.append("%s %s" % (insn.mnemonic, insn.op_str))
        if consumed == patch_len:
            return {"ok": True, "boundary": rva + patch_len, "displaced": displaced}
        if consumed > patch_len:
            return {"ok": False, "reason": "patch would split an instruction",
                    "split_at": insn.address, "displaced": displaced}
    return {"ok": False, "reason": "ran out of instructions"}
