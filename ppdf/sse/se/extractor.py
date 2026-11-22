"""Truy xuất toàn bộ dữ liệu trong kho bàn giao: nhận diện loại file theo magic, tách text, băm, khử trùng lặp."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import os
import re
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Sequence

from .olefile import CompoundFile

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".eml", ".mht", ".mhtml", ".html", ".htm", ".vcf", ".srt", ".reg", ".dif", ".slk",
}
OOXML_PREFIXES = ("word/", "xl/", "ppt/", "docProps/", "visio/", "shapes/", "customXml/")
TEXT_NODE_NAMES = {"t", "v", "instrText", "s", "content", "value", "code"}
ASCII_RUN = re.compile(rb"[\x20-\x7e\x09]{6,}")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
MAX_SCAN_BYTES = 64 * 1024 * 1024
HEAD_SAMPLE_BYTES = 256
MAX_TERM_GRAMS = 2_000_000

DEFAULT_EXCLUDES = (
    "*/KeywordHits/*",
    "*/hits_*.csv",
    "*/doi_duoi_log.csv",
    "*/BANG_BAN_GIAO_*.md",
    "*/KET_QUA_GOOGLE_DRIVE.md",
    "*/MANIFEST_SHA256.json",
)


@dataclass
class ExtractedDoc:
    doc_id: str
    sha256: str
    size: int
    file_type: str
    parser: str
    canonical_path: str
    aliases: list[str] = field(default_factory=list)
    text_chars: int = 0
    text_truncated: bool = False
    read_error: str = ""
    text: str = field(default="", repr=False)


MEDIA_SIGNATURES = (
    b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"BM", b"II*\x00", b"MM\x00*", b"RIFF", b"ID3", b"\x1aE\xdf\xa3",
    b"\x00\x00\x01\xba", b"\x00\x00\x00\x18ftyp", b"OggS", b"fLaC", b"\xff\xfb", b"\xff\xf3", b"PAR ", b"\x01\x00\x00\x00",
)
DOCUMENT_TYPES = {"ooxml", "zip", "ole", "sqlite", "pst", "pdf", "text", "xml"}


def sniff(head: bytes) -> str:
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if head.startswith(b"!BDN"):
        return "pst"
    if head.startswith(b"%PDF"):
        return "pdf"
    if any(head.startswith(sig) for sig in MEDIA_SIGNATURES):
        return "media"
    if head[:4] in {b"{\x01\r\x02", b"\x00\x00\x00\x01"}:
        return "onenote"
    if head.lstrip(b" \t\r\n\xef\xbb\xbf").startswith(b"<?xml"):
        return "xml"
    if _looks_texty(head):
        return "text"
    return "binary"


def _looks_texty(head: bytes) -> bool:
    """Van ban ASCII duoi 85% hoac UTF-8 hop le (tieng Viet co dau) du dieu kien de doc nhou text."""
    if not head:
        return False
    sample = head[:-4] if len(head) > 32 else head
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    if printable / len(sample) > 0.85:
        return True
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    readable = sum(1 for ch in decoded if ch.isprintable() or ch in "\t\n\r\x0b\x0c")
    return readable / len(decoded) > 0.85


def decode_bytes(data: bytes) -> str:
    for codec in ("utf-8", "cp1252"):
        try:
            return data.decode(codec)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def strings_scan(data: bytes) -> str:
    parts: list[str] = []
    for match in ASCII_RUN.finditer(data):
        parts.append(match.group().decode("ascii", errors="replace"))
    for match in UTF16_RUN.finditer(data):
        parts.append(match.group().decode("utf-16-le", errors="replace"))
    return "\n".join(parts)


def _xml_text(raw: bytes) -> str:
    chunks: list[str] = []
    try:
        import xml.etree.ElementTree as ET

        for element, _, text in ET.iterparse(io.BytesIO(raw), events=("end",)):
            if text and text.strip():
                local = element.tag.rsplit("}", 1)[-1]
                if local in TEXT_NODE_NAMES:
                    chunks.append(text)
    except Exception:
        chunks.append(re.sub(rb"<[^>]+>", b" ", raw).decode("utf-8", errors="replace"))
    return " ".join(chunks)


def extract_ooxml(data: bytes) -> tuple[str, str]:
    """Trả về (text, parser). Đuôi file có thể bị ngụy trang nên chỉ tin cấu trúc bên trong."""
    names = {name for name in zipfile.ZipFile(io.BytesIO(data)).namelist()}
    if "[Content_Types].xml" not in names:
        return "", "zip:not-ooxml"
    chunks: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in sorted(archive.namelist()):
            if name.startswith(OOXML_PREFIXES) and name.endswith(".xml"):
                try:
                    chunks.append(_xml_text(archive.read(name)))
                except Exception:
                    continue
    kind = "docx" if any(n.startswith("word/") for n in names) else (
        "xlsx" if any(n.startswith("xl/") for n in names) else (
            "pptx" if any(n.startswith("ppt/") for n in names) else "ooxml"
        )
    )
    return "\n".join(chunks), f"ooxml:{kind}"


def extract_zip_generic(data: bytes) -> tuple[str, str]:
    chunks: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in sorted(archive.namelist()):
            chunks.append(name.replace("/", " ").replace("\\", " "))
            if name.lower().endswith((".xml", ".txt", ".csv")):
                try:
                    chunks.append(_xml_text(archive.read(name)) or decode_bytes(archive.read(name)))
                except Exception:
                    continue
    return "\n".join(chunks), "zip:list"


BINARY_OLE_STREAMS = {"pictures", "\x01compobj", "\x01ole", "\x03objinfo", "\x02ole"}


def extract_ole(data: bytes, content_policy: str = "documents") -> tuple[str, str]:
    """Mo container CFB, lay text tung stream.

    Stream anh nhung (Pictures) bi bo qua theo mac dinh vi la du lieu bitmap, khong chuat text
    tim kiem duoc; dinh danh bang `strings` toan bo se sinh hang tram ngan n-gram nhieu.
    """
    try:
        cf = CompoundFile(data)
        kept, skipped = 0, 0
        chunks: list[str] = []
        for stream in cf.streams():
            if content_policy == "documents" and stream.name.lower() in BINARY_OLE_STREAMS:
                skipped += 1
                continue
            chunks.append(strings_scan(stream.data))
            kept += 1
        return "\n".join(chunks), f"ole:streams={kept},skipped={skipped}"
    except Exception as error:
        return strings_scan(data), f"strings:ole-error:{type(error).__name__}"


def extract_document(data: bytes, name: str, content_policy: str = "documents") -> tuple[str, str]:
    """Tra ve (text, parser). documents: bo noi dung file media; all: strings moi file; names: khong doc noi dung."""
    file_type = sniff(data[:HEAD_SAMPLE_BYTES])
    suffix = Path(name).suffix.lower()
    if content_policy == "names":
        return "", "skipped:names-only"
    if file_type == "zip":
        try:
            text, parser = extract_ooxml(data)
            if parser != "zip:not-ooxml":
                return text, parser
            return extract_zip_generic(data)
        except zipfile.BadZipFile:
            return strings_scan(data), "strings:badzip"
    if file_type == "ole":
        return extract_ole(data, content_policy)
    if file_type in {"pst", "sqlite", "pdf"}:
        return strings_scan(data), f"strings:{file_type}"
    if suffix in TEXT_EXTENSIONS or file_type in {"text", "xml"}:
        return decode_bytes(data), "text"
    if content_policy == "documents" and file_type in {"media", "onenote"}:
        return "", f"skipped:{file_type}"
    # File không nhận diện được dấu hiệu cấu trúc: thường là mảnh carve / dữ liệu chưa phân bổ.
    # Autopsy tìm được từ khoá trong các mảnh này (cactus.png, boudicca.bmp, BAMBOO~1.GIF) nên vẫn strings.
    return strings_scan(data), f"strings:{file_type}"


def hash_and_head(path: Path) -> tuple[str, bytes, int]:
    digest = hashlib.sha256()
    head = b""
    size = 0
    with open(path, "rb") as handle:
        head = handle.read(16)
        handle.seek(0)
        while chunk := handle.read(4 * 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), head, size


def is_excluded(rel_path: str, patterns: Sequence[str]) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def walk_corpus(
    roots: list[Path],
    evidence_dir: Path,
    exclude_patterns: Sequence[str],
    skip_slack: bool = True,
    limit: int | None = None,
    max_scan_bytes: int = MAX_SCAN_BYTES,
    max_text_bytes: int = 8_000_000,
    content_policy: str = "documents",
    progress: Callable[[int, ExtractedDoc], None] | None = None,
) -> list[ExtractedDoc]:
    """Duyệt toàn bộ file, đọc nội dung, khử trùng lặp theo SHA-256 (một bản ghi, nhiều alias)."""
    records: dict[str, ExtractedDoc] = {}
    order: list[str] = []
    seen = 0
    for root in roots:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if limit is not None and seen >= limit:
                    return [records[sha] for sha in order]
                if skip_slack and filename.endswith("-slack"):
                    continue
                if path.is_symlink() or not path.is_file():
                    continue
                rel = path.relative_to(evidence_dir).as_posix()
                if is_excluded(rel, exclude_patterns):
                    continue
                seen += 1
                try:
                    sha256, _, size = hash_and_head(path)
                except OSError as error:
                    records[rel] = ExtractedDoc(
                        doc_id=hashlib.sha256(rel.encode()).hexdigest()[:32],
                        sha256=f"unreadable:{type(error).__name__}",
                        size=0,
                        file_type="unreadable",
                        parser="error",
                        canonical_path=rel,
                        aliases=[rel],
                        read_error=str(error),
                    )
                    order.append(rel)
                    continue
                existing = records.get(sha256)
                if existing is not None:
                    if rel not in existing.aliases:
                        existing.aliases.append(rel)
                    if progress:
                        progress(seen, existing)
                    continue
                try:
                    data = path.read_bytes()[:max_scan_bytes]
                    text, parser = extract_document(data, filename, content_policy)
                    error = ""
                except Exception as read_error:
                    data = b""
                    text, parser, error = "", "error", f"{type(read_error).__name__}: {read_error}"
                truncated = len(text) > max_text_bytes
                if truncated:
                    text = text[:max_text_bytes]
                doc = ExtractedDoc(
                    doc_id=sha256[:32],
                    sha256=sha256,
                    size=size,
                    file_type=sniff(data[:HEAD_SAMPLE_BYTES]),
                    parser=parser,
                    canonical_path=rel,
                    aliases=[rel],
                    text_chars=len(text),
                    text_truncated=truncated,
                    read_error=error,
                    text=text,
                )
                records[sha256] = doc
                order.append(sha256)
                if progress:
                    progress(seen, doc)
    return [records[sha] for sha in order]


def manifest_rows(docs: list[ExtractedDoc]) -> list[dict]:
    rows = []
    for doc in docs:
        row = asdict(doc)
        row.pop("text", None)
        rows.append(row)
    return rows
