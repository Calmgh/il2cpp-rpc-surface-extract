#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Minimal MSF 7.0 PDB reader: public symbols as (RVA, name).

This is the portable fallback. On Windows, :mod:`il2cpprpc.dbghelp` is
preferred because ``dbghelp`` classifies each symbol as function or data
(``SymTagFunction`` / ``SymTagData``), which ``S_PUB32`` records do not carry
in a usable form.

Layout reminders that matter here (full write-up in references/pitfalls.md):

* stream block lists have no count prefix -- the count is ``ceil(size/block)``
* a stream size of ``0xFFFFFFFF`` means empty
* ``S_PUB32`` payload is ``flags(4) offset(4) section(2) name``

Only public symbols are available here. IL2CPP static functions are not in this
stream; for those, use the ``dbghelp`` path or runtime signature scanning.
"""
import struct

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
MAGIC_MSF2 = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0"
EMPTY_STREAM = 0xFFFFFFFF
S_PUB32 = 0x110E

#: S_PUB32 flags (CV_PUBSYMFLAGS). ``FUNCTION`` is set by some linkers only.
CVPSF_CODE = 0x0001
CVPSF_FUNCTION = 0x0002
CVPSF_MANAGED = 0x0004


class PdbError(ValueError):
    """The file does not follow the MSF 7.0 layout we expect."""


class PublicSymbol(object):
    __slots__ = ("rva", "flags", "name")

    def __init__(self, rva, flags, name):
        self.rva = rva
        self.flags = flags
        self.name = name

    @property
    def looks_like_function(self):
        return bool(self.flags & (CVPSF_CODE | CVPSF_FUNCTION))

    def __repr__(self):
        return "<PublicSymbol 0x%X %s>" % (self.rva, self.name)


class PDB(object):
    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb")
        try:
            self._read_superblock()
            self._read_directory()
        except Exception:
            self._f.close()
            raise

    # ------------------------------------------------------------- container

    def _read_superblock(self):
        hdr = self._f.read(64)
        if hdr[:32] == MAGIC_MSF2:
            raise PdbError("MSF 2.0 PDB is not supported: %s" % self.path)
        if hdr[:32] != MAGIC:
            raise PdbError("not an MSF 7.0 container: %s" % self.path)
        (self.block_size, _free_map, self.num_blocks,
         self.dir_bytes, _unknown, self.block_map_addr) = struct.unpack_from("<6I", hdr, 32)

    def _read_directory(self):
        bs = self.block_size
        n_dir = -(-self.dir_bytes // bs)
        n_map = -(-(n_dir * 4) // bs)
        block_map = b"".join(self._block(self.block_map_addr + i) for i in range(n_map))
        dir_blocks = struct.unpack_from("<%dI" % n_dir, block_map, 0)
        directory = b"".join(self._block(b) for b in dir_blocks)

        self.num_streams = struct.unpack_from("<I", directory, 0)[0]
        self.stream_sizes = list(struct.unpack_from("<%dI" % self.num_streams, directory, 4))

        pos = 4 + self.num_streams * 4
        self.stream_blocks = []
        for i in range(self.num_streams):
            size = self.stream_sizes[i]
            if size == EMPTY_STREAM:
                size = 0
            n = -(-size // bs)
            self.stream_blocks.append(
                struct.unpack_from("<%dI" % n, directory, pos) if n else ())
            pos += n * 4

    def _block(self, index):
        self._f.seek(index * self.block_size)
        data = self._f.read(self.block_size)
        if len(data) != self.block_size:
            raise PdbError("truncated block %d" % index)
        return data

    def stream(self, index, limit=None):
        size = self.stream_sizes[index]
        if size == EMPTY_STREAM:
            size = 0
        blocks = self.stream_blocks[index]
        if limit is not None:
            size = min(size, limit)
            blocks = blocks[: -(-size // self.block_size)]
        return b"".join(self._block(b) for b in blocks)[:size]

    def dbi_header(self):
        data = self.stream(3, limit=64)
        (_sig, _hdr, _age) = struct.unpack_from("<III", data, 0)
        (global_stream, _build, public_stream, _dll_ver,
         sym_record_stream, _rbld) = struct.unpack_from("<6H", data, 12)
        (_flags, machine) = struct.unpack_from("<HH", data, 56)
        return {
            "global_stream": global_stream,
            "public_stream": public_stream,
            "sym_record_stream": sym_record_stream,
            "machine": machine,
        }

    # --------------------------------------------------------------- symbols

    def public_symbols(self, section_vas):
        """Yield :class:`PublicSymbol` for every ``S_PUB32`` record.

        *section_vas* is the 1-based section virtual address list from the PE.
        """
        dbi = self.dbi_header()
        index = dbi["sym_record_stream"]
        if index == 0xFFFF:
            raise PdbError("DBI header reports no symbol record stream")

        data = self.stream(index)
        total = len(data)
        n_sections = len(section_vas)

        i = 0
        while i + 4 <= total:
            length = data[i] | (data[i + 1] << 8)
            if length < 2:
                i += 2
                continue
            kind = data[i + 2] | (data[i + 3] << 8)
            if kind == S_PUB32:
                rec = data[i + 4:i + 2 + length]
                if len(rec) >= 10:
                    flags, = struct.unpack_from("<I", rec, 0)
                    offset, section = struct.unpack_from("<IH", rec, 4)
                    if 0 < section <= n_sections:
                        name = rec[10:].split(b"\0")[0].decode("latin-1", "replace")
                        yield PublicSymbol(section_vas[section - 1] + offset, flags, name)
            i += 2 + length

    # ------------------------------------------------------------- lifecycle

    def close(self):
        if not self._f.closed:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
