"""Doc container OLE (CFB) lay ten va du lieu tung stream, phuc vu trich xuat text cua DOC/PPT/XLS/OST."""

from __future__ import annotations

import struct
from dataclasses import dataclass

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NO_SID = 0xFFFFFFFF
ENTRY_SIZE = 128
MAX_CHAIN = 1_000_000


@dataclass(frozen=True)
class OleStream:
    name: str
    size: int
    data: bytes


class CompoundFile:
    """Bo phan tich CFB toi gian: FAT, MiniFAT, DIFAT, directory; du 8.3 va 64 bit header."""

    def __init__(self, data: bytes):
        if not data.startswith(SIGNATURE):
            raise ValueError("Khong phai container OLE")
        self.data = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 30)[0]
        self.mini_size = 1 << struct.unpack_from("<H", data, 32)[0]
        self.first_dir = struct.unpack_from("<I", data, 48)[0]
        self.mini_cutoff = struct.unpack_from("<I", data, 56)[0]
        self.first_minifat = struct.unpack_from("<I", data, 60)[0]
        self.first_difat = struct.unpack_from("<I", data, 68)[0]
        self.num_difat = struct.unpack_from("<I", data, 72)[0]
        self._fat = self._read_fat()
        self._entries = self._read_directory()
        self._mini_fat = self._read_minifat()
        self._mini_stream = b""
        for entry in self._entries:
            if entry[1] == 5:
                self._mini_stream = self._chain_bytes(entry[2], entry[3])

    def _sector(self, index: int) -> bytes:
        start = (index + 1) * self.sector_size
        return self.data[start : start + self.sector_size]

    def _read_fat(self) -> dict[int, int]:
        fat_sectors: list[int] = []
        for offset in range(76, 76 + 109 * 4, 4):
            value = struct.unpack_from("<I", self.data, offset)[0]
            if value not in (FREESECT, ENDOFCHAIN) and value < len(self.data) // self.sector_size + 2:
                fat_sectors.append(value)
        current, guard = self.first_difat, 0
        while current not in (FREESECT, ENDOFCHAIN) and guard < MAX_CHAIN:
            guard += 1
            block = self._sector(current)
            per = self.sector_size // 4
            for i in range(per - 1):
                value = struct.unpack_from("<I", block, i * 4)[0]
                if value not in (FREESECT, ENDOFCHAIN):
                    fat_sectors.append(value)
            current = struct.unpack_from("<I", block, (per - 1) * 4)[0]
            if current in (FREESECT, ENDOFCHAIN):
                break
        fat: dict[int, int] = {}
        for index, sector in enumerate(fat_sectors):
            block = self._sector(sector)
            for i in range(self.sector_size // 4):
                fat[index * (self.sector_size // 4) + i] = struct.unpack_from("<I", block, i * 4)[0]
        return fat

    def _chain_indices(self, start: int) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT, NO_SID) and current not in seen and len(chain) < MAX_CHAIN:
            seen.add(current)
            chain.append(current)
            current = self._fat.get(current, ENDOFCHAIN)
        return chain

    def _chain_bytes(self, start: int, size: int | None = None) -> bytes:
        raw = b"".join(self._sector(index) for index in self._chain_indices(start))
        return raw if size is None else raw[:size]

    def _read_directory(self) -> list[tuple[str, int, int, int]]:
        raw = self._chain_bytes(self.first_dir)
        entries: list[tuple[str, int, int, int]] = []
        for offset in range(0, len(raw) - ENTRY_SIZE + 1, ENTRY_SIZE):
            block = raw[offset : offset + ENTRY_SIZE]
            name_len = struct.unpack_from("<H", block, 64)[0]
            name = block[: max(0, name_len - 2)].decode("utf-16-le", errors="replace") if name_len > 2 else ""
            obj_type = block[66]
            start = struct.unpack_from("<I", block, 116)[0]
            size = struct.unpack_from("<I", block, 120)[0]
            if obj_type in (1, 2, 5):
                entries.append((name, obj_type, start, size))
        return entries

    def streams(self) -> list[OleStream]:
        out: list[OleStream] = []
        for name, obj_type, start, size in self._entries:
            if obj_type != 2 or size <= 0:
                continue
            if size < self.mini_cutoff:
                chain = self._mini_chain(start)
                data = b"".join(self._mini_stream[i * self.mini_size : (i + 1) * self.mini_size] for i in chain)[:size]
            else:
                data = self._chain_bytes(start, size)
            out.append(OleStream(name=name, size=size, data=data))
        return out

    def entry_names(self) -> list[str]:
        return [entry[0] for entry in self._entries if entry[0]]

    def _read_minifat(self) -> dict[int, int]:
        per = self.sector_size // 4
        mini_fat: dict[int, int] = {}
        for index, sector in enumerate(self._chain_indices(self.first_minifat)):
            block = self._sector(sector)
            for i in range(per):
                mini_fat[index * per + i] = struct.unpack_from("<I", block, i * 4)[0]
        return mini_fat

    def _mini_chain(self, start: int) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT, NO_SID) and current not in seen and len(chain) < MAX_CHAIN:
            seen.add(current)
            chain.append(current)
            current = self._mini_fat.get(current, ENDOFCHAIN)
        return chain
