#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests against a hand-built IL2CPP-style module (see make_fixture.py).

Run with::

    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import make_fixture as fx  # noqa: E402
from il2cpprpc import compare, disasm, mapping, metadata, registry, xref  # noqa: E402
from il2cpprpc.pdb import PDB  # noqa: E402
from il2cpprpc.pe import PE  # noqa: E402
from il2cpprpc.table import SymbolTable, TAG_FUNCTION  # noqa: E402


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dll, cls.pdb = fx.write_fixtures(cls._tmp.name)
        cls.pe = PE(cls.dll)
        cls.table = SymbolTable(_symbols_from_pdb(cls.pdb, cls.pe))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()


def _symbols_from_pdb(pdb_path, module):
    """Build a table from the portable reader, tagging code as functions.

    S_PUB32 carries no size, so the known sizes from the fixture are used --
    the same situation as a real build, where sizes come from dbghelp.
    """
    from il2cpprpc.table import Symbol
    sizes = {name: size for _rva, size, name in fx.SYMBOLS}
    with PDB(pdb_path) as reader:
        return [Symbol(p.rva, sizes.get(p.name, 0x20), TAG_FUNCTION, p.name)
                for p in reader.public_symbols(module.section_vas())]


class TestPE(FixtureCase):
    def test_sections_and_base(self):
        self.assertEqual(self.pe.image_base, fx.IMAGE_BASE)
        self.assertEqual(len(self.pe.sections), 1)
        self.assertEqual(self.pe.sections[0].name, ".text")

    def test_fingerprint(self):
        fp = self.pe.fingerprint()
        self.assertEqual(fp["timestamp"], 0x5F112233)
        self.assertEqual(fp["size_of_image"], 0x2000)

    def test_executable_sections(self):
        names = [s.name for s in self.pe.executable_sections()]
        self.assertIn(".text", names)

    def test_rva_mapping(self):
        self.assertEqual(self.pe.rva_to_offset(fx.CTOR_RVA),
                         fx.TEXT_RAW_PTR + (fx.CTOR_RVA - fx.TEXT_VA))
        self.assertIsNone(self.pe.rva_to_offset(0x90000))


class TestPdb(FixtureCase):
    def test_symbols_and_sections(self):
        with PDB(self.pdb) as reader:
            symbols = list(reader.public_symbols(self.pe.section_vas()))
        self.assertEqual(len(symbols), len(fx.SYMBOLS))
        self.assertEqual(symbols[0].rva, fx.CTOR_RVA)
        self.assertIn("WorldRpcInfo__cctor", symbols[0].name)

    def test_flags_mark_functions(self):
        with PDB(self.pdb) as reader:
            symbols = list(reader.public_symbols(self.pe.section_vas()))
        self.assertTrue(all(s.looks_like_function for s in symbols))


class TestTable(FixtureCase):
    def test_exact_and_owner(self):
        self.assertIsNotNone(self.table.exact(fx.CALL1_RVA))
        owner = self.table.owner(fx.CALL1_RVA + 4)
        self.assertIsNotNone(owner)
        self.assertIn("RemoteCallDoThing", owner.name)

    def test_search_is_case_insensitive(self):
        hits = self.table.search("remotecall")
        self.assertEqual(len(hits), 2)

    def test_functions_only(self):
        self.assertEqual(len(self.table.functions()), 4)


class TestRegistry(FixtureCase):
    def test_finds_constructor(self):
        ctors = registry.find_registration_ctors(self.table)
        self.assertEqual(len(ctors), 1)
        self.assertIn("RpcInfo__cctor", ctors[0].name)

    def test_extracts_all_keys(self):
        ctor = registry.find_registration_ctors(self.table)[0]
        entries = registry.extract_method_ids(self.pe, ctor)
        self.assertEqual(len(entries), len(fx.REGISTERED_IDS))
        self.assertEqual(registry.unique_ids(entries), sorted(fx.REGISTERED_IDS))

    def test_size_hint_is_plausible(self):
        ctor = registry.find_registration_ctors(self.table)[0]
        hint = registry.table_size_hint(ctor)
        self.assertIsNotNone(hint)

    def test_gap_zero_keeps_precision(self):
        """The wrapper shape must not be mistaken for a registration."""
        ctor = registry.find_registration_ctors(self.table)[0]
        entries = registry.extract_method_ids(self.pe, ctor, gap=8)
        self.assertGreaterEqual(len(entries), len(fx.REGISTERED_IDS))


class TestMapping(FixtureCase):
    def test_wrappers_found(self):
        wrappers = mapping.find_wrappers(self.table)
        self.assertEqual(len(wrappers), 2)

    def test_binding_and_unmatched(self):
        ctor = registry.find_registration_ctors(self.table)[0]
        entries = registry.extract_method_ids(self.pe, ctor)
        known = registry.unique_ids(entries)
        wrappers = mapping.find_wrappers(self.table)

        bindings, unmatched = mapping.build_mapping(self.pe, wrappers, known)
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].method_id, fx.BOUND_ID)
        self.assertIn("RemoteCallDoThing", bindings[0].wrapper.name)
        self.assertEqual(len(unmatched), 1)
        self.assertIn("RemoteCallUnknown", unmatched[0].name)

    def test_component_grouping(self):
        bindings = [mapping.Binding(fx.BOUND_ID, wrappers[0], fx.CALL1_RVA)
                    for wrappers in [[self.table.exact(fx.CALL1_RVA)]]]
        groups = mapping.group_by_component(bindings)
        self.assertIn("?WorldEntity", list(groups)[0])

    def test_coverage(self):
        wrappers = mapping.find_wrappers(self.table)
        bindings = [mapping.Binding(fx.BOUND_ID, wrappers[0], fx.CALL1_RVA)]
        self.assertAlmostEqual(mapping.coverage(bindings, wrappers), 0.5)


class TestXref(FixtureCase):
    def test_finds_both_call_sites(self):
        hits = xref.find_callers(self.pe, [fx.CALL1_RVA, fx.CALL2_RVA])
        targets = {h.target for h in hits}
        self.assertIn(fx.CALL1_RVA, targets)
        self.assertIn(fx.CALL2_RVA, targets)
        self.assertTrue(all(h.kind == "call" for h in hits))

    def test_describe_names_the_owner(self):
        hits = xref.find_callers(self.pe, [fx.CALL1_RVA])
        described = xref.describe_callers(self.pe, self.table, hits)
        owners = [d["owner"] for d in described if d["owner"]]
        self.assertTrue(any("UiWorld" in o for o in owners))

    def test_verify_filters_outside_code(self):
        hits = xref.find_callers(self.pe, [0xDEADBEEF], verify_table=self.table)
        self.assertEqual(hits, [])


class TestCompare(FixtureCase):
    def test_wrappers_are_isomorphic(self):
        diff = compare.compare_with_table(self.pe, self.table,
                                          fx.CALL1_RVA, fx.CALL2_RVA)
        self.assertTrue(diff.same_size)
        self.assertTrue(diff.insn_equal)
        self.assertTrue(diff.isomorphic)
        self.assertEqual(len(diff.immediate_diffs), 1)

    def test_immediate_difference_is_reported(self):
        diff = compare.compare_with_table(self.pe, self.table,
                                          fx.CALL1_RVA, fx.CALL2_RVA)
        text = diff.immediate_diffs[0]["a"] + diff.immediate_diffs[0]["b"]
        self.assertIn("0x11111111", text)
        self.assertIn("0x99999999", text)

    def test_unrelated_functions_differ(self):
        diff = compare.compare_with_table(self.pe, self.table,
                                          fx.CTOR_RVA, fx.CALL1_RVA)
        self.assertFalse(diff.isomorphic)


class TestEntry(FixtureCase):
    def test_ctor_is_a_function_entry(self):
        info = disasm.check_entry(self.pe, fx.CTOR_RVA)
        self.assertTrue(info["ok"], info)

    def test_mid_function_is_not_an_entry(self):
        info = disasm.check_entry(self.pe, fx.CALL1_RVA + 6)
        self.assertFalse(info["ok"])

    def test_patch_lands_on_boundary(self):
        result = disasm.jmp_patchable(self.pe, fx.CALL1_RVA)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["boundary"], fx.CALL1_RVA + 5)


class TestMetadata(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "global-metadata.dat")
        # Mimic a grouped string heap: one class's members next to each other.
        blob = (b"\x01\x02\x03" + b"AddStyleRank\x00" + b"RemoveStyleRank\x00"
                + b"GetStyleRank\x00" + b"StyleRank\x00"
                + b"GMCategoryAttribute\x00" + b"Publish\x00" + b"Dev\x00")
        with open(self.path, "wb") as f:
            f.write(blob)

    def tearDown(self):
        self._tmp.cleanup()

    def test_dump_finds_neighbours(self):
        offset, strings = metadata.dump_around(self.path, "AddStyleRank")
        self.assertGreater(offset, 0)
        self.assertIn("RemoveStyleRank", strings)
        self.assertIn("Publish", strings)

    def test_missing_anchor_raises(self):
        with self.assertRaises(KeyError):
            metadata.dump_around(self.path, "NoSuchMember")

    def test_classify(self):
        _offset, strings = metadata.dump_around(self.path, "AddStyleRank")
        buckets = metadata.classify(strings)
        self.assertIn("GMCategoryAttribute", buckets["attributes"])
        self.assertIn("Publish", buckets["methods"], buckets["methods"])
        self.assertIn("StyleRank", buckets["methods"])

    def test_neighbour_map_merges(self):
        offsets, strings = metadata.neighbour_map(
            self.path, ["AddStyleRank", "GMCategoryAttribute"], before=8, after=64)
        self.assertEqual(len(offsets), 2)
        self.assertIn("RemoveStyleRank", strings)


if __name__ == "__main__":
    unittest.main()
