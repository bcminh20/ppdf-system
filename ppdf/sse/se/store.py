"""Doc/ghi san pham trung gian: chi muc ma hoa phia server, vault nhi phan, manifest phia nguoi giu du lieu."""

from __future__ import annotations

import json
import os
from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerRecord:
    """Mot ban ghi chi muc khong dinh danh: handle cua tai lieu, vung tag trong tags.bin, vung blob trong vault.bin."""

    handle: str
    tag_offset: int
    tag_count: int
    offset: int
    length: int
    nonce: str
    truncated: bool = False


@dataclass
class ServerIndex:
    params: dict[str, Any]
    records: list[ServerRecord] = field(default_factory=list)


def save_json(path: os.PathLike | str, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def load_json(path: os.PathLike | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


class BinaryWriter:
    """Ghi lien tiep cac blob nhi phan, tra ve (offset, length) de chi muc ruy."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "wb")
        self.offset = 0

    def append(self, blob: bytes) -> tuple[int, int]:
        self._handle.write(blob)
        position, size = self.offset, len(blob)
        self.offset += size
        return position, size

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "BinaryWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_region(path: Path, offset: int, length: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(length)


class TagSequence(Sequence):
    """Vung tag nhi phan trong tags.bin coi nhu day tag co do dai co dinh, da sap xep tang dan.

    Giup phep tim nhi phan tren tai lieu hang trieu tag ma khong tao tap hop the nhat cua chung.
    """

    def __init__(self, raw: bytes, width: int):
        self.raw = raw
        self.width = width

    def __len__(self) -> int:
        return len(self.raw) // self.width

    def __getitem__(self, index: int) -> bytes:
        if index < 0:
            index += len(self)
        start = index * self.width
        if start + self.width > len(self.raw):
            raise IndexError(index)
        return self.raw[start : start + self.width]

    def __contains__(self, tag: bytes) -> bool:
        position = bisect_left(self, tag)
        return position < len(self) and self[position] == tag


def write_server_index(directory: Path, params: dict[str, Any], records: list[ServerRecord]) -> Path:
    path = directory / "index.json"
    save_json(path, {"params": params, "records": [record.__dict__ for record in records]})
    return path


def load_server_index(directory: Path) -> tuple[ServerIndex, Path]:
    path = directory / "index.json"
    payload = load_json(path)
    records = [ServerRecord(**row) for row in payload["records"]]
    return ServerIndex(params=payload["params"], records=records), path


def encode_trapdoor(trapdoor, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mode": trapdoor.mode,
        "slots": [{"slot": label, "v": value.hex()} for label, value in trapdoor.slots],
    }
    if extra:
        payload.update(extra)
    return payload


def decode_trapdoor(payload: dict[str, Any]):
    from .peke import Trapdoor

    slots = tuple((slot["slot"], bytes.fromhex(slot["v"])) for slot in payload["slots"])
    return Trapdoor(slots=slots, mode=payload.get("mode", "disjunctive"))
