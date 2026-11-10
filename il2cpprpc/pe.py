#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Minimal PE reader: sections, image base, and the build fingerprint.

The fingerprint matters more than it looks. Two copies of the same DLL can
differ in file size (compression, signature padding) while being the same
build, and can be the same size while being different builds. Compare
``TimeDateStamp`` and ``SizeOfImage``, never file size.
"""
import collections
import struct

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020

Section = collections.namedtuple(
    "Section", "name va vsize raw_ptr raw_size characteristics")

#: Pseudo-section name used for IL2CPP code that lives outside the PE sections
#: in some builds. Kept as a constant so callers can recognise it.
IL2CPP_SECTION = "il2cpp"


class PeError(ValueError):
    """Not a PE file we can parse."""


class PE(object):
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self._header = f.read(0x2000)
        self._parse()

    def _parse(self):
        d = self._header
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PeError("not a PE file (no MZ header): %s" % self.path)
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PeError("not a PE file (no PE signature): %s" % self.path)

        coff = e_lfanew + 4
        self.machine, self.num_sections = struct.unpack_from("<HH", d, coff)
        self.timestamp, = struct.unpack_from("<I", d, coff + 4)
        size_of_optional_header, = struct.unpack_from("<H", d, coff + 16)

        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:
            self.is_64 = True
            self.image_base, = struct.unpack_from("<Q", d, opt + 24)
            self.size_of_image, = struct.unpack_from("<I", d, opt + 56)
        elif magic == 0x10B:
            self.is_64 = False
            self.image_base, = struct.unpack_from("<I", d, opt + 28)
            self.size_of_image, = struct.unpack_from("<I", d, opt + 56)
        else:
            raise PeError("unknown optional header magic 0x%X" % magic)

        sec_off = opt + size_of_optional_header
        self.sections = []
        for i in range(self.num_sections):
            o = sec_off + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<4I", d, o + 8)
            characteristics, = struct.unpack_from("<I", d, o + 36)
            self.sections.append(
                Section(name, va, vsize, raw_ptr, raw_size, characteristics))

    # ---------------------------------------------------------------- lookup

    def section_for_rva(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def rva_to_offset(self, rva):
        s = self.section_for_rva(rva)
        if s is None:
            return None
        delta = rva - s.va
        if delta >= s.raw_size:
            return None
        return s.raw_ptr + delta

    def read_rva(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            return b""
        with open(self.path, "rb") as f:
            f.seek(off)
            return f.read(size)

    def section_data(self, section):
        with open(self.path, "rb") as f:
            f.seek(section.raw_ptr)
            return f.read(min(section.raw_size, max(section.vsize, section.raw_size)))

    def executable_sections(self):
        """Sections that can hold code, wide definition included.

        ``IMAGE_SCN_MEM_EXECUTE`` is the authoritative flag, but some packers
        and IL2CPP builds leave it off or split code across sections. Include
        anything marked as code or executable, and let the caller decide.
        """
        return [s for s in self.sections
                if s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)]

    def section_vas(self):
        """1-based section VA list, matching S_PUB32 section numbering."""
        return [s.va for s in self.sections]

    # ------------------------------------------------------------- fingerprint

    def fingerprint(self):
        """The pair to compare when asking "same build?"."""
        return {"timestamp": self.timestamp, "size_of_image": self.size_of_image}

    def __repr__(self):
        return "<PE %s %s sections=%d>" % (
            self.path, "x64" if self.is_64 else "x86", len(self.sections))
