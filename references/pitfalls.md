# Pitfalls: environment, tooling, and format edges

Companion to the main `SKILL.md`. Everything here is a failure that costs real
time and is not obvious from the documentation.

---

## 1. `dbghelp` needs explicit `argtypes` on x64

**Symptom**

```
OverflowError: int too long to convert
```

or, worse, a module base that is silently truncated to 32 bits and every RVA
computed as `Address - base` comes out negative or wildly large.

**Cause** — `ctypes` defaults a return value to `c_int`. `SymLoadModuleEx`
returns a 64-bit base. Without `restype`/`argtypes` the high half is lost.

**Fix**

```python
dbghelp.SymLoadModuleEx.restype = ctypes.c_ulonglong
dbghelp.SymLoadModuleEx.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_ulonglong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
]
```

Implemented in `il2cpprpc/dbghelp.py`.

## 2. `SYMBOL_INFO` offsets (x64)

If you read the structure by hand instead of declaring it with `ctypes`:

| field | offset |
|---|---|
| `Size` | 28 |
| `Address` | 56 |
| `Tag` | 72 |
| `NameLen` | 76 |
| `MaxNameLen` | 80 |
| `Name` | **84** |

`Name` is 84, not 80. Using `MaxNameLen`'s offset truncates the first four
characters of every symbol name, and because MSVC names start with `?` this is
easy to spot — but only if you look.

Declaring the struct with `ctypes.Structure` and letting the platform insert
padding is safer than hardcoding.

## 3. With `mask="*"`, the first 800k symbols all report `tag=7`

**Symptom** — you abort the export thinking it failed, because the function
counter is still zero after a minute.

**Cause** — IL2CPP emits `_RuntimeMethod_var` data symbols first. They are
`SymTagData` (7). Functions come later.

**Fix** — let it run. Roughly 1.7M symbols for a 179 MB module, ~90 seconds.
Progress output every 200k symbols is enough to tell "slow" from "stuck".

## 4. Symbol tables legitimately contain negative addresses

**Symptom** — `ValueError: invalid literal for int()` or a parsed RVA around
`0x-17FFFFFFC`.

**Fix** — wrap parsing in `try/except` and drop anything outside
`0 < rva < 2^47`. One bad row must not invalidate 1.7 million good ones.
`il2cpprpc.table.SymbolTable.load_tsv` does this.

## 5. `_m<HASH>` suffixes make names unreadable

IL2CPP appends a 32-hex-digit instance hash:

```
Foo_RemoteCallBar_m1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D
```

Strip it with a 16+ hex-digit match, not a fixed length — shorter hashes exist
in older builds. `_RuntimeMethod_var` symbols need the hash removed from the
middle, keeping the suffix.

## 6. capstone returns zero instructions from a bad start address

**Symptom** — `len(insns) == 0` for an address you know is inside a function.

**Cause** — decoding starts mid-instruction. If the first byte happens to be
invalid in x64 (`0x07` is `pop es`, illegal in 64-bit mode), capstone gives up
rather than resynchronising.

**Fix** — always disassemble from the function start, then index by address:

```python
insns = disassemble(pe, func_entry, func_size)
target = next(i for i, x in enumerate(insns) if x.address == rva)
```

Never pass an arbitrary interior RVA to the decoder.

## 7. Register ids are not 0-3

`EDX` is **24**, `RCX` is **38** in capstone's x86 tables, and the numbering
moves between releases. Resolve by name:

```python
from capstone import x86_const
x86_const.X86_REG_EDX
```

Hardcoding `2` for `edx` produces code that looks right and matches nothing.

## 8. `Dictionary.Add` recognition needs the right three-instruction shape

The generated sequence is:

```
mov edx, imm32     ; key
mov rcx, reg       ; this
call ...
```

Allowing a gap makes recall better and precision worse. Keep `gap=0` for the
registration table: the code is machine-generated and strictly regular. Use a
gap only when you have evidence that a specific build pads the sequence.

False-positive risk is real: a scan for the raw byte pattern
`BA <mid:4> 48 8B CB E8` across the whole module hits small values constantly
(methodId `0x1` matched 806 times in one build). The pattern is corroboration,
never the primary source.

## 9. IDA MCP freezes on large databases

`list_funcs` / `func_query` are implemented roughly as
`[get_function(a) for a in idautils.Functions()]`. At 580k functions that runs
for minutes **on IDA's main thread**, so every later MCP call queues behind it
and the health endpoint degrades from 0.6s to 15s.

**Fix** — only use address-based queries: `lookup_funcs` (by address),
`decompile` / `disasm` (by `addr`), `xrefs_to` (by `addrs`). All name-based
lookup goes to the local `*_funcs.tsv`.

## 10. `.nam` is locked while IDA is open

IDA holds an exclusive handle on its `.nam`. External symbol readers fail until
IDA closes.

**Fix** — use `dbghelp` against the PDB, or parse the PDB directly. Do not try
to read `.nam`.

## 11. Do not background long jobs with `nohup ... &`

The process is cleaned up when the shell session ends: logs stop updating and
there is no completion marker, so you cannot tell "finished" from "died".

**Fix** — a full export takes 60–90 seconds; run it in the foreground. For
genuinely long jobs use the session's own background-task mechanism so exit
status is preserved.

## 12. `SymEnumSymbols` mask is a single glob

It accepts one pattern, with no exclusion and no alternation. To filter several
tags, accept everything and filter inside the callback on `Tag`.

## 13. IL2CPP code is not always in a PE section

Some builds place generated code in a mapping described as `il2cpp` rather than
a named PE section. A caller scan that only walks `IMAGE_SCN_MEM_EXECUTE`
sections will miss those call sites.

**Fix** — treat "executable" as "code section or executable flag", and when a
scan returns nothing for a wrapper you know is called, enumerate the other
mappings before concluding the wrapper is unreachable.

## 14. PDB and DLL must be the same link, not just the same name

An incremental rebuild keeps the CodeView GUID and bumps the age. Symbol names
stay valid; every RVA shifts by a *different* amount. Nothing looks wrong until
hooks land in the middle of unrelated functions.

**Fix** — compare GUID **and** age (PE debug directory vs PDB info stream). See
the `pdb-symbol-extract` project for a ready-made check; the reasoning is in its
`docs/PITFALLS.md`.

## 15. Stale RVAs in old notes are worse than no RVAs

An address from a previous build often still points inside `.text`, so it does
not error — it silently yields the wrong function.

**Fix** — every time you take an RVA from a note, run `tools/check_entry.py` on
it. The combination of "preceding byte terminates a function" and "starts with a
standard prologue" catches most stale addresses in one second.
