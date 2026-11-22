"""Lõi tìm kiếm mã hoá đối xứng theo mKEES (Goyal et al., NDSS 2012).

Chỉ mục: r_i = PRF_K(i); tag(i, w) = PRF_{v_w}(r_i) với t_w = PRF_K(w), v_w = PRF_K(t_w).
Trapdoor cho từ khoá w: tk_w = (t_w, v_w); server kiểm tra PRF_{v_w}(r_i) có nằm trong tag của tài liệu i.
Server không có K nên không sinh được tag cho từ khoá tuỳ ý, và không đọc được nội dung hay từ khoá.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
TAG_BYTES = 16
DOMAIN_FILE = b"mkees/v1/file/"
DOMAIN_TERM = b"mkees/v1/term/"
DOMAIN_VERIFY = b"mkees/v1/verify/"
DOMAIN_DATAKEY = b"mkees/v1/datakey/"
DOMAIN_BLOB = b"mkees/v1/blob/"


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def load_or_create_key(path: os.PathLike | str) -> bytes:
    path = os.fspath(path)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            key = handle.read()
        if len(key) != KEY_BYTES:
            raise ValueError(f"Khoa master sai do dai: {path}")
        return key
    key = generate_key()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(key)
    return key


def _prf(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


@dataclass(frozen=True)
class IndexRecord:
    """Một bản ghi chỉ mục không định danh mà server nắm giữ."""

    handle: bytes
    tags: list[bytes]
    offset: int
    length: int
    nonce: bytes
    tag_count: int
    truncated: bool


@dataclass(frozen=True)
class Trapdoor:
    """Token tim kiem: chi chua gia tri kiem tra v_w, khong chua tu khoai th."""

    slots: tuple[tuple[str, bytes], ...]
    mode: str

    def values(self) -> list[bytes]:
        return [v for _, v in self.slots]


class PEKE:
    def __init__(self, key: bytes):
        if len(key) != KEY_BYTES:
            raise ValueError("Khoa master phai dai 32 byte")
        self.key = key

    def file_handle(self, doc_id: str) -> bytes:
        return _prf(self.key, DOMAIN_FILE + doc_id.encode("utf-8"))

    def term_values(self, gram: str) -> tuple[bytes, bytes]:
        t_w = _prf(self.key, DOMAIN_TERM + gram.encode("utf-8"))
        v_w = _prf(self.key, DOMAIN_VERIFY + t_w)
        return t_w, v_w

    def trapdoor_value(self, gram: str) -> bytes:
        return self.term_values(gram)[1]

    def term_tag(self, doc_handle: bytes, gram: str) -> bytes:
        return _prf(self.trapdoor_value(gram), doc_handle)[:TAG_BYTES]

    def data_key(self, doc_id: str) -> bytes:
        return HKDF(algorithm=SHA256(), length=32, info=DOMAIN_DATAKEY + doc_id.encode("utf-8"), salt=None).derive(self.key)

    def encrypt_blob(self, doc_id: str, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.data_key(doc_id)).encrypt(nonce, plaintext, DOMAIN_BLOB + aad)
        return nonce, ct

    def decrypt_blob(self, doc_id: str, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return AESGCM(self.data_key(doc_id)).decrypt(nonce, ciphertext, DOMAIN_BLOB + aad)


def search_record(doc_handle: bytes, record_tags: Sequence[bytes], trapdoor: Trapdoor) -> list[str]:
    """Phia server: kiem tra tag sinh ra tu trapdoor co nam trong tai lieu hay khong, khong can khoa master.

    `record_tags` la vung tag cua rieng tai lieu do; TagSequence dung phep tim nhi phan nen
    khong phai tap hop hoa hang trieu tag khi doi chieu.
    """
    matched: list[str] = []
    for label, value in trapdoor.slots:
        if _prf(value, doc_handle)[:TAG_BYTES] in record_tags:
            matched.append(label)
    return matched


def record_is_hit(matched: Sequence[str], trapdoor: Trapdoor) -> bool:
    if trapdoor.mode == "conjunctive":
        return len(matched) == len(trapdoor.slots)
    return len(matched) > 0
