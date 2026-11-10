#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Symbol table: build an index, then answer the four questions that matter.

* "What is the function at this RVA?"       -> :meth:`SymbolTable.exact`
* "Which function contains this RVA?"       -> :meth:`SymbolTable.owner`
* "Which symbols match this pattern?"        -> :meth:`SymbolTable.search`
* "What is this methodId's wrapper?"         -> :meth:`SymbolTable.by_method_id`

The ``owner`` query is the one people forget. A call site lands inside a
function, not on a symbol boundary, so mapping an xref back to its enclosing
function needs range logic -- and most symbol tables store size as 0, which
means the range has to be inferred from the next symbol's start.
"""
import bisect
import re

TAG_FUNCTION = 5
TAG_DATA = 7

TAG_NAMES = {5: "function", 7: "data"}


class Symbol(object):
    __slots__ = ("rva", "size", "tag", "name")

    def __init__(self, rva, size, tag, name):
        self.rva = rva
        self.size = size
        self.tag = tag
        self.name = name

    @property
    def is_function(self):
        return self.tag == TAG_FUNCTION

    def __repr__(self):
        return "<Symbol 0x%X tag=%d %s>" % (self.rva, self.tag, self.name)


class SymbolTable(object):
    def __init__(self, symbols):
        self.symbols = sorted(symbols, key=lambda s: (s.rva, -s.size))
        self._rvas = [s.rva for s in self.symbols]
        self._by_rva = {}
        for s in self.symbols:
            # Keep the largest symbol at a given RVA: ICF aliases overlap and the
            # bigger one almost always describes the real function.
            current = self._by_rva.get(s.rva)
            if current is None or s.size > current.size:
                self._by_rva[s.rva] = s

    # ------------------------------------------------------------------ query

    def __len__(self):
        return len(self.symbols)

    def exact(self, rva):
        """The symbol that starts exactly at *rva*, or ``None``."""
        return self._by_rva.get(rva)

    def owner(self, rva):
        """The symbol whose range contains *rva* (largest wins).

        Sizes of 0 are common: the range is then taken to end at the next
        symbol's start. If the RVA is past the last symbol, the nearest
        preceding symbol is returned, which is the best available answer.
        """
        i = bisect.bisect_right(self._rvas, rva) - 1
        if i < 0:
            return None

        best = None
        # A few large symbols can contain the same address, and the containing
        # symbol may start well before the nearest one, so walk back a bounded
        # number of entries looking for an exact range match.
        for j in range(i, max(-1, i - 512), -1):
            sym = self.symbols[j]
            if sym.rva > rva:
                continue
            end = sym.rva + sym.size if sym.size else self._next_start(j)
            if end is not None and end > rva:
                if best is None or sym.size > best.size:
                    best = sym
            elif sym.size == 0 and best is None:
                # No size and no following symbol: nearest preceding wins.
                best = sym
        return best or self.symbols[i]

    def _next_start(self, index):
        if index + 1 < len(self._rvas):
            return self._rvas[index + 1]
        return None

    def effective_size(self, symbol):
        """Size to use when disassembling *symbol*.

        Symbol tables frequently store 0 for size. Blindly using a large
        fallback then reads straight into the next function and, in a
        registration constructor, starts picking up its neighbours' immediates
        as if they were keys. Bounding by the next symbol's start avoids that.

        Returns ``None`` when nothing bounds the symbol.
        """
        if symbol.size:
            return symbol.size
        i = bisect.bisect_right(self._rvas, symbol.rva)
        while i < len(self._rvas) and self._rvas[i] == symbol.rva:
            i += 1
        if i < len(self._rvas):
            return self._rvas[i] - symbol.rva
        return None

    def search(self, pattern, ignore_case=True):
        """Symbols whose name matches *pattern* (substring or compiled regex)."""
        if hasattr(pattern, "search"):
            rx = pattern
        else:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        return [s for s in self.symbols if rx.search(s.name)]

    def functions(self):
        return [s for s in self.symbols if s.tag == TAG_FUNCTION]

    def by_method_id(self, method_id, mapping):
        """Best-effort reverse lookup inside a ``{method_id: [wrapper]}`` map."""
        return mapping.get(method_id, [])

    # ------------------------------------------------------------------- i/o

    def save_tsv(self, path, symbols=None):
        """Write ``0xrva<TAB>0xsize<TAB>tag<TAB>name`` rows."""
        rows = self.symbols if symbols is None else symbols
        with open(path, "w", encoding="utf-8") as f:
            for s in rows:
                f.write("0x%X\t0x%X\t%d\t%s\n" % (s.rva, s.size, s.tag, s.name))

    @classmethod
    def load_tsv(cls, path, tags=None):
        """Load a table written by :meth:`save_tsv`.

        Malformed rows are skipped rather than fatal: symbol dumps from real
        builds occasionally contain negative or overflowed addresses, and one
        bad row should not invalidate 1.7 million good ones.
        """
        symbols = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 4:
                    continue
                try:
                    rva = int(parts[0], 16)
                    size = int(parts[1], 16)
                except ValueError:
                    continue
                if rva < 0 or rva > (1 << 48):
                    continue
                try:
                    tag = int(parts[2])
                except ValueError:
                    tag = TAG_FUNCTION if "?" in parts[3] else TAG_DATA
                if tags is not None and tag not in tags:
                    continue
                symbols.append(Symbol(rva, size, tag, parts[3]))
        return cls(symbols)
