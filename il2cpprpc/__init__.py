#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""il2cpprpc -- recover the client RPC attack surface of an IL2CPP game.

The pipeline, in the order you would actually run it:

1. :func:`il2cpprpc.dbghelp.export_symbols` -- PDB -> symbol table (Windows)
   or :meth:`il2cpprpc.pdb.PDB.public_symbols` for the portable fallback
2. :class:`il2cpprpc.table.SymbolTable` -- RVA queries, owner lookup, search
3. :func:`il2cpprpc.registry.extract_method_ids` -- the ``RpcInfo__cctor``
   registration table -> the complete methodId key set
4. :func:`il2cpprpc.mapping.build_mapping` -- ``*_RemoteCall*`` wrappers ->
   ``methodId -> function`` bindings
5. :func:`il2cpprpc.xref.find_callers` -- who triggers each wrapper, which is
   what decides whether it is reachable at all

Everything is read-only static analysis. Nothing here talks to a game, a
server, or a running process.
"""

__version__ = "1.0.0"

from .table import Symbol, SymbolTable, TAG_DATA, TAG_FUNCTION
from .pdb import PDB, PublicSymbol
from .pe import PE, Section
from . import compare, disasm, mapping, metadata, registry, xref

__all__ = [
    "Symbol", "SymbolTable", "TAG_FUNCTION", "TAG_DATA",
    "PDB", "PublicSymbol",
    "PE", "Section",
    "compare", "disasm", "mapping", "metadata", "registry", "xref",
    "__version__",
]
