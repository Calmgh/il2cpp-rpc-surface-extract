# il2cpp-rpc-surface-extract

**Recover the client RPC attack surface of an IL2CPP game from its PDB.**
No IDA. No disassembler GUI. About five minutes on a 179 MB `GameAssembly.dll`
with 900k functions.

Given `GameAssembly.dll` + its matching `GameAssembly.pdb`, this produces:

* a **full symbol table** — function name ↔ RVA — queryable in milliseconds
* the **complete methodId key set** of every RPC registration table, read out of
  the `*RpcInfo__cctor` initialisers
* a **`methodId` ↔ `*_RemoteCall*` binding** for the client wrappers that send
  them (≈94% coverage on a production build)
* the **call graph around each wrapper**, which is what actually decides whether
  an entry point is reachable at all

It is also a written record of the reasoning: what makes an RPC worth testing,
and the three ways an enumeration silently loses entries.

```console
$ python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv --registry registry.tsv
symbols        : 1723401
registry keys  : 1249
wrappers       : 501  (pattern '_RemoteCall', case-insensitive)
bound          : 471 wrappers (94.0%)
bindings       : 471

methodId     wrapper
0x11111111   ?WorldEntity_RemoteCallDoThing@UWorldEntity@@QEAAXXZ
...
```

---

## Why

IDA is the right tool for reading one function. It is the wrong tool for
"which of these 500 wrappers are worth a second look". A 180 MB IL2CPP module
takes minutes to open, and the MCP bridge freezes for minutes more if you ask it
to enumerate functions, because the query runs on IDA's main thread.

The PDB already contains everything needed for prioritisation: names, RVAs,
sizes. The registration constructors are ordinary linear code that a 40-line
disassembler loop can read. So this toolchain reads the PDB, decodes the
constructors, and leaves IDA for the handful of functions that survive triage.

## Install

```bash
git clone https://github.com/Calmgh/il2cpp-rpc-surface-extract
cd il2cpp-rpc-surface-extract
pip install -r requirements.txt   # capstone; only needed for analysis, not export
```

Python 3.8+. Symbol export uses `dbghelp`, which is built into Windows — the
portable fallback (`--from-pdb`) works anywhere but cannot classify symbols as
function or data.

## Quick start

```bash
# 1. name -> RVA, RVA -> name
python tools/export_symbols.py GameAssembly.dll --out sym

# 2. the registration tables and their methodId keys
python tools/rpc_registry.py GameAssembly.dll --symbols sym_funcs.tsv --out registry.tsv

# 3. which wrapper sends which key
python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv --registry registry.tsv

# 4. is this wrapper reachable, and from where?
python tools/find_callers.py GameAssembly.dll --symbols sym_funcs.tsv --target 0x1A2B3C0
```

## The tools

| Tool | Question it answers |
|---|---|
| `export_symbols.py` | What is in this module? (name, RVA, size, function vs data) |
| `rpc_registry.py` | What are the valid methodIds? |
| `rpc_map.py` | Which client function sends methodId X? |
| `rva_query.py` | What function contains this address? |
| `find_callers.py` | Who invokes this function? |
| `func_cmp.py` | Are these two functions the same template? |
| `check_entry.py` | Is this RVA really a function entry on this build? |
| `metadata_dump.py` | What else is in this class? (string heap neighbourhood) |

Each is standalone and prints readable output; `--json` is available where it
matters (`find_callers`, `func_cmp`, `check_entry`) for scripting.

## The reasoning that matters more than the tooling

Enumerating RPCs is the easy half. The hard half is knowing which of them are
worth testing. Three specific failure modes, all of which cost real time:

**Enumeration loses entries silently.** Filtering by class-name prefix misses
RPCs that live on another class — an action belonging to a vehicle can hang off
`PlayerEntity`. And symbol names mix case (`VehicleLoad` next to `VehicleLOad`),
so a case-sensitive `grep` drops entries with no error. Both are fixed by
scanning on business keywords with `-i`, then cross-checking the count against
the packet sequence for that feature end to end.

**Reachability beats severity.** A wrapper that looks like a perfect target —
client-authoritative, no rate limit, movement-related — can be worthless if its
only call site is a button that appears at close range, because "remote" is
contradicted by "only reachable nearby". Three questions filter most of these:
*can the input get here?*, *is the argument player-chosen?*, *is there a second
candidate value?* A single-instance object has no second value to forge.

**"No ownership check" is not automatically a bug.** For shared containers
(ammo racks, public storage, shared furnaces), check whether the concept of
ownership exists at all. If there is no owner field, no "whose is this" UI, and
no automatic return on exit, then not validating ownership is the faithful
implementation of the design, not a vulnerability.

The full workflow, with the register-level detail of the `Dictionary.Add`
sequence and the reasoning behind each check, is in **[SKILL.md](SKILL.md)**
(Chinese). It is written to be used as a Claude-style skill: drop the directory
into a skills folder and the agent picks it up.

## How the registration table is read

Generated code, one entry at a time:

```asm
mov  r8, rdi            ; value  = RpcInfo
mov  r9, [rip+C]        ; method = Dictionary_2_Add_RuntimeMethod_var
mov  edx, <methodId>    ; key    <-- the value we want
mov  rcx, rbx           ; this   = the dictionary
call <Dictionary_2_Add>
```

Collect every `mov edx, imm32` that sits two instructions before a `call`, and
you have the complete key set of that table. The handler pointer is **not**
there — it is resolved at runtime — which is why step 3 exists: the wrapper
functions embed their own key as an immediate, and intersecting the two sets
gives the binding.

## Relationship to `pdb-symbol-extract`

[`pdb-symbol-extract`](https://github.com/Calmgh/pdb-symbol-extract) is the
lower layer: a pure-Python MSF/PDB reader with no Windows dependency. This
project embeds a trimmed version of it for the portable path and adds the
analysis on top. Use that one if you only need symbol tables from arbitrary
PDBs; use this one if you need RPC surface from an IL2CPP build.

## Scope and boundaries

This is **static analysis of a local binary you already have**. Nothing here
attaches to a process, sends traffic, patches memory, or talks to a server.

What it does not do:

* **It does not decide whether a server validates anything.** It produces a
  candidate list. Whether a specific RPC is exploitable is a runtime question
  and must be tested separately, in an authorized environment.
* **It does not cover static/internal functions.** Public symbols only; use
  module streams or runtime signature scanning for those.
* **It does not decompile.** `func_cmp` compares bytes and instructions, not
  logic. For reading a function, use IDA — that is what it is good at.

Use it on targets you own or are authorized to assess.

## Tests

The test suite assembles a synthetic IL2CPP-style module from scratch — one PE
with four hand-encoded functions, one matching PDB, one metadata heap — and
round-trips every parser and CLI. No third-party binaries, no checked-in
fixtures.

```bash
python -m unittest discover -s tests -v
```

Coverage: container parsing, symbol classification, RVA/owner lookup,
registration-key extraction, wrapper binding and the unmatched path, call-site
scanning, isomorphic comparison, entry-point heuristics, and metadata string
neighbourhoods.

## Prior art

The IL2CPP metadata layout and the PDB format are documented across
[Il2CppDumper](https://github.com/Perfare/Il2CppDumper), LLVM's
`DebugInfo/MSF` and `DebugInfo/CodeView`, and a long tail of small tools. The
novel part here is narrower: reading the RPC registry out of generated
constructors to get the key set without a runtime, and the triage discipline
around what to do with it.

## License

MIT. See [LICENSE](LICENSE).
