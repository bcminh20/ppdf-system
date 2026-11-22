"""Dong chay: truy xuat toan bo du lieu -> lap chi muc ma hoa -> sinh trapdoor -> tim kiem mu -> giai an -> doi chung."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import secrets
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .extractor import ExtractedDoc, manifest_rows, walk_corpus
from .keywords import Keyword, KeywordList, load_keyword_lists
from .peke import PEKE, TAG_BYTES, Trapdoor, load_or_create_key, record_is_hit, search_record
from .store import (
    BinaryWriter,
    ServerRecord,
    TagSequence,
    decode_trapdoor,
    encode_trapdoor,
    load_json,
    load_server_index,
    read_region,
    save_json,
    write_server_index,
)
from .tokens import doc_grams, phrase_to_regex, slugify, tokenize

MODE_LABEL = {"disjunctive": "OR", "conjunctive": "AND"}
# Parser mà byte thô không phải là text liên tục, nên hoặc từ khoá không xuất hiện liền mạch trong byte.
COMPRESSED_PARSERS = ("ooxml:", "zip:", "strings:pdf", "skipped:")


def parser_of(doc_by_id: dict[str, ExtractedDoc], doc_id: str) -> str:
    doc = doc_by_id.get(doc_id)
    return doc.parser if doc else ""


@dataclass
class WorkDirs:
    root: Path
    client: Path
    server: Path
    queries: Path
    results: Path
    text: Path
    released: Path

    @classmethod
    def open(cls, cfg: Config) -> "WorkDirs":
        root = Path(cfg.work_dir)
        dirs = {
            "root": root,
            "client": root / "client",
            "server": root / "server",
            "queries": root / "queries",
            "results": root / "results",
            "text": root / "client" / "extracted_text",
            "released": root / "results" / "released",
        }
        for path in dirs.values():
            path.mkdir(parents=True, exist_ok=True)
        return cls(**dirs)

    def paths_for(self, uid: str, mode: str) -> tuple[Path, Path, Path]:
        stem = f"{uid}_{MODE_LABEL[mode]}"
        return (
            self.queries / f"token_{stem}.json",
            self.queries / f"expectation_{stem}.json",
            self.results / f"search_{stem}.json",
        )

    def tags_path(self) -> Path:
        return self.server / "tags.bin"


def searchable_text(doc: ExtractedDoc) -> str:
    """Chuoi duoc lap chi muc va doi chung: noi dung rut xuat cong voi duong dan, ten file."""
    return doc.text + "\n" + "\n".join(doc.aliases)


def _peke(cfg: Config, work: WorkDirs) -> PEKE:
    if cfg.master_key:
        return PEKE(Path(cfg.master_key).read_bytes())
    return PEKE(load_or_create_key(work.client / "master.key"))


def load_lists(cfg: Config) -> list[KeywordList]:
    lists = load_keyword_lists(cfg.resolved_keyword_files(), cfg.case_sensitive)
    if not lists:
        raise FileNotFoundError(f"Khong doc duoc danh sach tu khoa nao tu {cfg.evidence_dir}")
    return lists


def load_docs_from_manifest(work: WorkDirs) -> list[ExtractedDoc]:
    rows = load_json(work.client / "corpus_manifest.json")["documents"]
    docs: list[ExtractedDoc] = []
    for row in rows:
        text_path = work.text / f"{row['doc_id']}.txt.gz"
        text = ""
        if text_path.exists():
            with gzip.open(text_path, "rt", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        docs.append(ExtractedDoc(**{**row, "text": text}))
    return docs


def stage_extract(cfg: Config, work: WorkDirs) -> list[ExtractedDoc]:
    excludes = cfg.active_excludes()
    started = time.perf_counter()

    def progress(index: int, doc: ExtractedDoc) -> None:
        if index % 25 == 0:
            print(f"  truy xuat {index} file | {doc.canonical_path}")

    docs = walk_corpus(
        roots=cfg.corpus_roots(),
        evidence_dir=cfg.evidence_dir,
        exclude_patterns=excludes,
        skip_slack=cfg.skip_slack,
        limit=cfg.limit_docs,
        max_scan_bytes=cfg.max_scan_bytes,
        max_text_bytes=cfg.max_text_bytes,
        content_policy=cfg.content_policy,
        progress=progress,
    )
    for doc in docs:
        if doc.text:
            with gzip.open(work.text / f"{doc.doc_id}.txt.gz", "wt", encoding="utf-8", errors="replace") as handle:
                handle.write(doc.text)
    payload = {
        "meta": {
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "corpus_roots": [str(p) for p in cfg.corpus_roots()],
            "excluded_patterns": excludes,
            "skip_slack": cfg.skip_slack,
            "unique_documents": len(docs),
            "total_bytes": sum(d.size for d in docs),
            "unreadable": sum(1 for d in docs if d.parser == "error"),
        },
        "documents": manifest_rows(docs),
    }
    save_json(work.client / "corpus_manifest.json", payload)
    print(f"[extract] {len(docs)} tai lieu doc lap, {payload['meta']['total_bytes']:,} byte, {payload['meta']['elapsed_seconds']}s")
    return docs


def query_depth(cfg: Config, lists: list[KeywordList]) -> int:
    return cfg.max_query_tokens or max((kw_list.max_token_count for kw_list in lists), default=1)


def stage_build(cfg: Config, work: WorkDirs, docs: list[ExtractedDoc], lists: list[KeywordList]) -> dict[str, Any]:
    peke = _peke(cfg, work)
    depth = query_depth(cfg, lists)
    started = time.perf_counter()
    records: list[ServerRecord] = []
    handle_map: dict[str, str] = {}
    total_tags = 0
    truncated = 0
    with BinaryWriter(work.server / "vault.bin") as vault, BinaryWriter(work.tags_path()) as tag_store:
        for position, doc in enumerate(docs, start=1):
            if position % 25 == 0:
                print(f"  ma hoa + lap chi muc {position}/{len(docs)}")
            handle = peke.file_handle(doc.doc_id)
            grams, is_truncated = doc_grams(tokenize(searchable_text(doc), cfg.case_sensitive), depth, cfg.max_terms_per_doc)
            truncated += int(is_truncated)
            tags = sorted(peke.term_tag(handle, gram) for gram in grams)
            total_tags += len(tags)
            meta = {
                "doc_id": doc.doc_id,
                "sha256": doc.sha256,
                "size": doc.size,
                "file_type": doc.file_type,
                "parser": doc.parser,
                "canonical_path": doc.canonical_path,
                "aliases": doc.aliases,
                "text_chars": doc.text_chars,
                "tag_count": len(tags),
            }
            header = json.dumps(meta, ensure_ascii=False).encode("utf-8")
            body = len(header).to_bytes(4, "big") + header + _read_original(cfg, doc)
            nonce, ciphertext = peke.encrypt_blob(doc.doc_id, body, handle)
            offset, length = vault.append(nonce + ciphertext)
            tag_offset, tag_bytes = tag_store.append(b"".join(tags))
            records.append(
                ServerRecord(
                    handle=handle.hex(),
                    tag_offset=tag_offset,
                    tag_count=len(tags),
                    offset=offset,
                    length=length,
                    nonce=nonce.hex(),
                    truncated=is_truncated,
                )
            )
            handle_map[handle.hex()] = doc.doc_id
    index_path = write_server_index(
        work.server,
        {
            "scheme": "mKEES - PRF/HMAC-SHA256 blind index + AES-256-GCM",
            "depth": depth,
            "tag_bytes": TAG_BYTES,
            "case_sensitive": cfg.case_sensitive,
            "content_mode": cfg.content_mode,
            "content_policy": cfg.content_policy,
            "records": len(records),
            "total_tags": total_tags,
            "truncated_records": truncated,
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "keyword_files": [str(p) for p in cfg.resolved_keyword_files()],
        },
        records,
    )
    save_json(work.client / "handle_map.json", handle_map)
    params = load_json(index_path)["params"]
    params["index_bytes"] = index_path.stat().st_size
    params["vault_bytes"] = (work.server / "vault.bin").stat().st_size
    params["tags_bytes"] = work.tags_path().stat().st_size
    print(f"[index] {len(records)} ban ghi, {total_tags:,} tag ({params['tags_bytes']:,} byte), do sau L={depth}, {params['elapsed_seconds']}s")
    return params


def _read_original(cfg: Config, doc: ExtractedDoc) -> bytes:
    if cfg.content_mode == "index-only":
        return b""
    try:
        return (cfg.evidence_dir / doc.canonical_path).read_bytes()
    except OSError:
        return b""


def stage_token(cfg: Config, work: WorkDirs, kw_list: KeywordList) -> tuple[Path, Path]:
    """Data holder sinh token; slot duoc dat nhan trung tinh de server khong gan duoc voi tu khoa."""
    peke = _peke(cfg, work)
    prefix = f"{kw_list.uid}_k"
    labels = [secrets.token_hex(4) if cfg.blind_slots else f"{prefix}{i + 1:03d}" for i in range(len(kw_list.keywords))]
    trapdoor = Trapdoor(
        slots=tuple((labels[i], peke.trapdoor_value(kw.gram)) for i, kw in enumerate(kw_list.keywords)),
        mode=cfg.mode,
    )
    token_path, expectation_path, _ = work.paths_for(kw_list.uid, cfg.mode)
    save_json(token_path, encode_trapdoor(trapdoor, {"created": time.strftime("%Y-%m-%d %H:%M:%S"), "keyword_count": len(labels)}))
    save_json(
        expectation_path,
        {
            "uid": kw_list.uid,
            "list_name": kw_list.name,
            "mode": cfg.mode,
            "source_xml": str(kw_list.source),
            "slots": [
                {"slot": labels[i], "keyword": kw.text, "whole": kw.whole, "literal": kw.literal, "tokens": kw.token_count}
                for i, kw in enumerate(kw_list.keywords)
            ],
        },
    )
    print(f"[token] {len(labels)} tu khoa cua {kw_list.name} -> {token_path.name}")
    return token_path, expectation_path


def stage_search(work: WorkDirs, token_path: Path) -> dict[str, Any]:
    """Chay tren may phan tich: chi doc index.json va token, khong cham khoa master hay ban ro."""
    index, _ = load_server_index(work.server)
    trapdoor = decode_trapdoor(load_json(token_path))
    width = int(index.params.get("tag_bytes", TAG_BYTES))
    started = time.perf_counter()
    hits: list[dict[str, Any]] = []
    with open(work.tags_path(), "rb") as tags_file:
        for record in index.records:
            tags_file.seek(record.tag_offset)
            raw = tags_file.read(record.tag_count * width)
            matched = search_record(bytes.fromhex(record.handle), TagSequence(raw, width), trapdoor)
            if record_is_hit(matched, trapdoor):
                hits.append({"handle": record.handle, "slots": matched, "tag_count": record.tag_count})
    elapsed = round(time.perf_counter() - started, 4)
    result = {
        "token_file": str(token_path),
        "mode": trapdoor.mode,
        "operator": MODE_LABEL[trapdoor.mode],
        "records_scanned": len(index.records),
        "prf_calls": len(index.records) * len(trapdoor.slots),
        "elapsed_seconds": elapsed,
        "hits": hits,
    }
    out_path = work.results / f"search_{token_path.stem.removeprefix('token_')}.json"
    save_json(out_path, result)
    print(f"[search] khop {len(hits)}/{len(index.records)} tai lieu theo phep {MODE_LABEL[trapdoor.mode]}, {elapsed}s")
    return result


def stage_release(cfg: Config, work: WorkDirs, result: dict[str, Any], expectation: dict[str, Any]) -> list[dict[str, Any]]:
    """Data holder quy hoach ve duong dan that va giai noi dung bi khop."""
    peke = _peke(cfg, work)
    index, _ = load_server_index(work.server)
    records = {r.handle: r for r in index.records}
    handle_map = load_json(work.client / "handle_map.json")
    slot_keyword = {entry["slot"]: entry["keyword"] for entry in expectation["slots"]}
    rows: list[dict[str, Any]] = []
    for hit in result["hits"]:
        record = records[hit["handle"]]
        handle_bytes = bytes.fromhex(record.handle)
        blob = read_region(work.server / "vault.bin", record.offset, record.length)
        body = peke.decrypt_blob(handle_map[record.handle], blob[:12], blob[12:], handle_bytes)
        header_length = int.from_bytes(body[:4], "big")
        meta = json.loads(body[4 : 4 + header_length].decode("utf-8"))
        content = body[4 + header_length :]
        released = ""
        if content:
            target = work.released / f"{meta['doc_id'][:12]}__{Path(meta['canonical_path']).name}"
            target.write_bytes(content)
            released = target.name
        rows.append(
            {
                "blind_handle": record.handle,
                "file_path": meta["canonical_path"],
                "aliases": "|".join(a for a in meta["aliases"] if a != meta["canonical_path"]),
                "sha256": meta["sha256"],
                "size": meta["size"],
                "type": meta["file_type"],
                "parser": meta["parser"],
                "matched_keywords": "; ".join(sorted({slot_keyword.get(s, s) for s in hit["slots"]})),
                "decrypt_hash_check": "MATCH" if content and hashlib.sha256(content).hexdigest() == meta["sha256"] else ("EMPTY" if not content else "MISMATCH"),
                "released_file": released,
            }
        )
    rows.sort(key=lambda r: r["file_path"])
    out_csv = work.results / f"released_{Path(result['token_file']).stem.removeprefix('token_')}.csv"
    write_csv(out_csv, rows)
    print(f"[release] giai ma {len(rows)} tai lieu khop -> {out_csv.name}")
    return rows


def stage_selective_release(
    cfg: Config,
    work: WorkDirs,
    selected_doc_ids: set[str],
    label: str = "selective_evidence",
) -> list[dict[str, Any]]:
    """Giai ma CO CHON LOC chi nhung file duoc xac dinh la chung cu nguy co cao (Stage 4.2).
    
    Bao ve quyen rieng tu bang cach giu nguyen ban ma trong vault.bin cho cac file khong thuoc danh sach.
    """
    peke = _peke(cfg, work)
    index, _ = load_server_index(work.server)
    handle_map = load_json(work.client / "handle_map.json")
    id_to_handle = {v: k for k, v in handle_map.items()}
    records = {r.handle: r for r in index.records}

    selective_dir = work.results / "selective_evidence"
    selective_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for doc_id in selected_doc_ids:
        handle = id_to_handle.get(doc_id)
        if not handle or handle not in records:
            continue
        record = records[handle]
        handle_bytes = bytes.fromhex(record.handle)
        blob = read_region(work.server / "vault.bin", record.offset, record.length)
        body = peke.decrypt_blob(doc_id, blob[:12], blob[12:], handle_bytes)
        header_length = int.from_bytes(body[:4], "big")
        meta = json.loads(body[4 : 4 + header_length].decode("utf-8"))
        content = body[4 + header_length :]
        released_path = ""
        if content:
            target = selective_dir / f"{meta['doc_id'][:12]}__{Path(meta['canonical_path']).name}"
            target.write_bytes(content)
            released_path = target.name
        rows.append(
            {
                "doc_id": meta["doc_id"],
                "file_path": meta["canonical_path"],
                "sha256": meta["sha256"],
                "size": meta["size"],
                "status": "APPROVED_DECRYPTED",
                "released_file": released_path,
            }
        )
    out_csv = work.results / f"{label}.csv"
    write_csv(out_csv, rows)
    print(f"[selective_release] Chi giai ma {len(rows)} file bang chung phu hop -> {out_csv.name}")
    return rows


def ground_truth(docs: list[ExtractedDoc], keyword: str, whole: bool, literal: bool, case_sensitive: bool) -> dict[str, int]:
    """Tim truc tiep tren ban ro, doc lap voi may n-gram + HMAC dung trong chi muc."""
    pattern = phrase_to_regex(keyword, whole, literal, case_sensitive)
    counts: dict[str, int] = {}
    for doc in docs:
        found = len(pattern.findall(searchable_text(doc)))
        if found:
            counts[doc.doc_id] = found
    return counts


def raw_views(data: bytes) -> list[str]:
    """Ba cach doc byte tho: latin-1 gi vi tri byte, hai lenh UTF-16LE bat ca text dan tinh."""
    views = [data.decode("latin-1", "replace"), data.decode("utf-16-le", "ignore")]
    if len(data) > 1:
        views.append(data[1:].decode("utf-16-le", "ignore"))
    return views


def raw_keyword_hits(cfg: Config, docs: list[ExtractedDoc], keywords: list[Keyword]) -> dict[str, set[str]]:
    """Orac thu ba: tim trong byte tho cua file, bo qua hoan toan buoc rut xuat text.

    Dung de phat hien tu khoa van ton tai trong file nhung khong vao duoc ban ro tim kiem
    (vung nen, anh hoa, chuat khong phai text) - can lech nay thuoc ve buoc doc file, khong phai chi muc.
    Loc nhanh bang chuoi byte truoc, chi chay regex theo nghia whole/literal cua Autopsy
    tren nhung file thuc su chua chuoi do.
    """
    hits: dict[str, set[str]] = {kw.text: set() for kw in keywords}
    by_text = {kw.text: kw for kw in keywords}
    needles = []
    for kw in keywords:
        needle = kw.text.lower().encode("utf-8", "ignore")
        if needle.isascii():
            needles.append((kw.text, needle, kw.text.lower().encode("utf-16-le")))
    for doc in docs:
        try:
            data = (cfg.evidence_dir / doc.canonical_path).read_bytes()
        except OSError:
            continue
        lowered = data.lower()
        candidates = [text for text, needle, needle16 in needles if needle in lowered or needle16 in lowered]
        if not candidates:
            continue
        views = raw_views(data)
        for text in candidates:
            kw = by_text[text]
            pattern = phrase_to_regex(kw.text, kw.whole, kw.literal, cfg.case_sensitive)
            if any(pattern.search(view) for view in views):
                hits[text].add(doc.doc_id)
    return hits


def stage_verify(cfg: Config, work: WorkDirs, docs: list[ExtractedDoc], lists: list[KeywordList]) -> dict[str, Any]:
    handle_map = load_json(work.client / "handle_map.json")
    doc_by_id = {d.doc_id: d for d in docs}
    keyword_rows: list[dict[str, Any]] = []
    doc_rows: list[dict[str, Any]] = []
    list_rows: list[dict[str, Any]] = []
    for kw_list in lists:
        _, expectation_path, result_path = work.paths_for(kw_list.uid, cfg.mode)
        if not result_path.exists():
            continue
        search_result = load_json(result_path)
        slot_keyword = {e["slot"]: e["keyword"] for e in load_json(expectation_path)["slots"]}
        blind_by_keyword: dict[str, set[str]] = {}
        for hit in search_result["hits"]:
            doc_id = handle_map[hit["handle"]]
            for slot in hit["slots"]:
                keyword = slot_keyword.get(slot)
                if keyword:
                    blind_by_keyword.setdefault(keyword, set()).add(doc_id)
        plain_by_keyword = {
            kw.text: ground_truth(docs, kw.text, kw.whole, kw.literal, cfg.case_sensitive) for kw in kw_list.keywords
        }
        raw_by_keyword = raw_keyword_hits(cfg, docs, kw_list.keywords)
        blind_docs = {doc_id for matched in blind_by_keyword.values() for doc_id in matched}
        if cfg.mode == "conjunctive":
            # Trong chế độ AND (Conjunctive), tài liệu kỳ vọng phải chứa ĐỦ TẤT CẢ từ khóa trong danh sách
            plain_doc_sets = [set(counts.keys()) for counts in plain_by_keyword.values()]
            plain_docs = set.intersection(*plain_doc_sets) if plain_doc_sets else set()
            raw_doc_sets = [set(matched) for matched in raw_by_keyword.values()]
            raw_docs = set.intersection(*raw_doc_sets) if raw_doc_sets else set()
        else:
            # Trong chế độ OR (Disjunctive), tài liệu kỳ vọng chỉ cần chứa ÍT NHẤT MỘT từ khóa
            plain_docs = {doc_id for counts in plain_by_keyword.values() for doc_id in counts}
            raw_docs = {doc_id for matched in raw_by_keyword.values() for doc_id in matched}

        for kw in kw_list.keywords:
            blind = blind_by_keyword.get(kw.text, set())
            plain = set(plain_by_keyword[kw.text])
            if cfg.mode == "conjunctive":
                # Ở phép AND, kết quả tìm mù bị ràng buộc bởi điều kiện đồng thời tất cả từ khóa
                target_plain = plain & plain_docs
                fp = len(blind - target_plain)
                fn = len(target_plain - blind)
                recall = round(len(blind & target_plain) / len(target_plain), 4) if target_plain else "n/a"
            else:
                fp = len(blind - plain)
                fn = len(plain - blind)
                recall = round(len(blind & plain) / len(plain), 4) if plain else "n/a"
            keyword_rows.append(
                {
                    "keyword_list": kw_list.name,
                    "keyword": kw.text,
                    "tokens": kw.token_count,
                    "blind_docs": len(blind),
                    "plaintext_docs": len(plain),
                    "raw_bytes_docs": len(raw_by_keyword[kw.text]),
                    "false_positive": fp,
                    "false_negative": fn,
                    "recall": recall,
                }
            )
        for doc_id in sorted(blind_docs | plain_docs | raw_docs):
            doc = doc_by_id.get(doc_id)
            blind_keywords = sorted(k for k, matched in blind_by_keyword.items() if doc_id in matched)
            plain_keywords = sorted(k for k, counts in plain_by_keyword.items() if doc_id in counts)
            raw_keywords = sorted(k for k, matched in raw_by_keyword.items() if doc_id in matched)
            if doc_id in blind_docs and doc_id in plain_docs:
                status = "KHOP_CA_HAI"
            elif doc_id in blind_docs:
                status = "CHI_TU_KIEM_MU"
            elif doc_id in plain_docs:
                status = "CHI_BAN_RO"
            else:
                status = "CHI_CON_TRONG_BYTE_THO"
            doc_rows.append(
                {
                    "keyword_list": kw_list.name,
                    "file_path": doc.canonical_path if doc else "(ngoai manifest)",
                    "sha256": doc.sha256 if doc else "",
                    "size": doc.size if doc else 0,
                    "type": doc.file_type if doc else "",
                    "parser": doc.parser if doc else "",
                    "blind_match": "YES" if doc_id in blind_docs else "NO",
                    "plaintext_match": "YES" if doc_id in plain_docs else "NO",
                    "raw_bytes_match": "YES" if doc_id in raw_docs else "NO",
                    "blind_keywords": "; ".join(blind_keywords),
                    "plaintext_keywords": "; ".join(plain_keywords),
                    "raw_keywords": "; ".join(raw_keywords),
                    "status": status,
                }
            )
        raw_only = raw_docs - blind_docs - plain_docs
        gap_container = sum(1 for doc_id in raw_only if parser_of(doc_by_id, doc_id).startswith(COMPRESSED_PARSERS))
        list_rows.append(
            {
                "keyword_list": kw_list.name,
                "operator": MODE_LABEL[cfg.mode],
                "keywords": len(kw_list.keywords),
                "records_scanned": search_result["records_scanned"],
                "search_seconds": search_result["elapsed_seconds"],
                "blind_docs": len(blind_docs),
                "plaintext_docs": len(plain_docs),
                "raw_bytes_docs": len(raw_docs),
                "false_positive": len(blind_docs - plain_docs),
                "false_negative": len(plain_docs - blind_docs),
                "text_extraction_gap": len(raw_only),
                "gap_compressed_container": gap_container,
                "gap_other": len(raw_only) - gap_container,
                "recall": round(len(blind_docs & plain_docs) / len(plain_docs), 4) if plain_docs else "n/a",
                "precision": round(len(blind_docs & plain_docs) / len(blind_docs), 4) if blind_docs else "n/a",
            }
        )
    totals = {
        "blind_docs": sum(r["blind_docs"] for r in list_rows),
        "plaintext_docs": sum(r["plaintext_docs"] for r in list_rows),
        "raw_bytes_docs": sum(r["raw_bytes_docs"] for r in list_rows),
        "false_positive": sum(r["false_positive"] for r in list_rows),
        "false_negative": sum(r["false_negative"] for r in list_rows),
        "text_extraction_gap": sum(r["text_extraction_gap"] for r in list_rows),
        "gap_compressed_container": sum(r["gap_compressed_container"] for r in list_rows),
        "gap_other": sum(r["gap_other"] for r in list_rows),
    }
    write_csv(work.results / "verify_by_keyword.csv", keyword_rows)
    write_csv(work.results / "verify_by_doc.csv", doc_rows)
    report = {"lists": list_rows, "keywords": keyword_rows, "docs": doc_rows, "totals": totals}
    save_json(work.results / "verify.json", report)
    print(f"[verify] false_positive={totals['false_positive']} false_negative={totals['false_negative']} tren {len(doc_rows)} tai lieu khop")
    return report


def index_records(work: WorkDirs) -> list[ServerRecord]:
    return load_server_index(work.server)[0].records


def leakage_profile(cfg: Config, work: WorkDirs, lists: list[KeywordList]) -> dict[str, Any]:
    """Do lo bang ke (table pattern) va the tich chi muc ma hoa."""
    tags = [r.tag_count for r in index_records(work)]
    docs_per_slot: dict[str, int] = {}
    for kw_list in lists:
        _, expectation_path, result_path = work.paths_for(kw_list.uid, cfg.mode)
        if not result_path.exists():
            continue
        slot_keyword = {e["slot"]: e["keyword"] for e in load_json(expectation_path)["slots"]}
        for hit in load_json(result_path)["hits"]:
            for slot in hit["slots"]:
                key = f"{kw_list.name} / {slot_keyword.get(slot, slot)}"
                docs_per_slot[key] = docs_per_slot.get(key, 0) + 1
    return {
        "records": len(tags),
        "total_tags": sum(tags),
        "tags_mean": round(statistics.fmean(tags), 2) if tags else 0,
        "tags_max": max(tags, default=0),
        "index_bytes": (work.server / "index.json").stat().st_size,
        "vault_bytes": (work.server / "vault.bin").stat().st_size,
        "docs_per_slot": docs_per_slot,
        "server_sees": "handle của tài liệu, danh sách tag đã mã hóa và số ô slot khớp",
        "server_cannot_see": "đường dẫn, tên file, chuỗi từ khoá và nội dung bản rõ",
    }


def write_markdown_report(cfg: Config, work: WorkDirs, params: dict[str, Any], report: dict[str, Any], leak: dict[str, Any]) -> Path:
    lines = [
        "# Tìm kiếm mù trên dữ liệu mã hóa (Searchable Encryption, phép OR)",
        "",
        f"Ngày chạy: {time.strftime('%Y-%m-%d %H:%M:%S')} | Phạm vi: {', '.join(cfg.sources)} | Chế độ nội dung: {params['content_mode']} | Chính sách đọc: {params['content_policy']}",
        "",
        "## Tham số",
        "",
        "| Tham số | Giá trị |",
        "|---|---|",
        f"| Thuật toán | {params['scheme']} |",
        f"| Độ sâu n-gram (L) | {params['depth']} |",
        f"| Số tài liệu trong chỉ mục | {params['records']} |",
        f"| Số tag của chỉ mục | {params['total_tags']:,} |",
        f"| Bản ghi bị giới hạn số term | {params['truncated_records']} |",
        f"| Thời gian xây chỉ mục | {params['elapsed_seconds']} s |",
        f"| Kích thước index.json | {leak['index_bytes']:,} byte |",
        f"| Kích thước tags.bin | {params.get('tags_bytes', 0):,} byte |",
        f"| Kích thước vault.bin (mã hóa) | {leak['vault_bytes']:,} byte |",
        "",
        "## Kết quả theo danh sách từ khóa",
        "",
        "| Danh sách | Phép | Từ khóa | Bản ghi quét | Tìm thấy (mù) | Bản rõ | Dương tính giả | Âm tính giả | Recall | Precision |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in report["lists"]:
        lines.append(
            f"| {row['keyword_list']} | {row['operator']} | {row['keywords']} | {row['records_scanned']} | {row['blind_docs']} | {row['plaintext_docs']} "
            f"| {row['false_positive']} | {row['false_negative']} | {row['recall']} | {row['precision']} |"
        )
    lines += [
        "",
        "## Đối chiếu từng từ khóa",
        "",
        "| Danh sách | Từ khóa | Token | Thấy (mù) | Bản rõ | Trong byte thô | Recall |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report["keywords"]:
        lines.append(
            f"| {row['keyword_list']} | `{row['keyword']}` | {row['tokens']} | {row['blind_docs']} | {row['plaintext_docs']} | {row['raw_bytes_docs']} | {row['recall']} |"
        )
    lines += [
        "",
        "## Bất đối khớp giữa tìm kiếm mù và bản rõ",
        "",
    ]
    mismatches = [row for row in report["docs"] if row["status"] != "KHOP_CA_HAI"]
    if mismatches:
        lines += ["| Danh sách | Đường dẫn | Trạng thái | Khớp (mù) | Bản rõ | Byte thô |", "|---|---|---|---|---|---|"]
        for row in mismatches:
            lines.append(
                f"| {row['keyword_list']} | {row['file_path']} | {row['status']} | {row['blind_keywords'] or '-'} "
                f"| {row['plaintext_keywords'] or '-'} | {row['raw_keywords'] or '-'} |"
            )
    else:
        lines.append("Toàn bộ tài liệu khớp trùng giữa tìm kiếm mù và tìm kiếm bản rõ (0 dương tính giả, 0 âm tính giả).")
    gap_rows = [row for row in report["docs"] if row["status"] == "CHI_CON_TRONG_BYTE_THO"]
    lines += [
        "",
        "## Từ khóa chỉ còn trong byte thô (giới hạn của bước đọc file)",
        "",
        "Bộ ba con số: tìm kiếm mù / bản rõ rút xuất / byte thô. Lệch ở cột byte thô thuộc bước đọc file, không thuộc chỉ mục mã hóa.",
        "",
        f"- Tổng lệch so với byte thô: {report['totals']['text_extraction_gap']}"
        f" (chứa trong container nén hoặc file bị bỏ qua theo chính sách: {report['totals']['gap_compressed_container']},"
        f" còn lại: {report['totals']['gap_other']}).",
    ]
    if gap_rows:
        lines += ["| Danh sách | Đường dẫn | Kiểu | Bộ phân tích | Từ khóa |", "|---|---|---|---|---|"]
        for row in gap_rows:
            lines.append(
                f"| {row['keyword_list']} | {row['file_path']} | {row['type']} | {row['parser']} | {row['raw_keywords']} |"
            )
    else:
        lines.append("- Không có tài liệu nào chứa từ khóa trong byte thô mà bước rút xuất bỏ sót.")
    lines += [
        "",
        "## Lộ thông tin",
        "",
        f"- Server thấy: {leak['server_sees']}.",
        f"- Server không thấy: {leak['server_cannot_see']}.",
        f"- Thể tích chỉ mục: trung bình {leak['tags_mean']} tag mỗi tài liệu, lớn nhất {leak['tags_max']} tag.",
        f"- Số tài liệu khớp theo từng ô slot: {leak['docs_per_slot']}.",
        "",
        "## Hạn chế",
        "",
        "- File OLE và Office cũ dùng phương pháp strings (ASCII, UTF-16LE) trên từng stream, không mở hết cấu trúc container; nội dung bị nén hoặc nhúng trong object không lấy được.",
        "- File ảnh, audio, video chỉ được chỉ mục tên và đường dẫn theo chính sách `documents`.",
        "- Kết quả có thể lệch với Autopsy trên ảnh gốc vì Autopsy đọc cả unallocated space và cấu trúc file, còn kho ở đây là bản export.",
        f"- Độ sâu chỉ mục L={params['depth']} lấy từ từ khóa dài nhất trong XML; từ khóa dài hơn L ở lần tìm sau sẽ bị bỏ sót.",
        "- Khi một bản ghi đạt trần `max_terms_per_doc`, chỉ mục bị cắt và có thể bỏ sót từ khóa ở cuối tài liệu; cột 'Bản ghi bị giới hạn số term' ở trên là bằng chứng cho lần chạy này.",
        "",
    ]
    path = work.results / f"{cfg.report_label}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[report] {path}")
    return path


def run_all(cfg: Config) -> dict[str, Any]:
    work = WorkDirs.open(cfg)
    lists = load_lists(cfg)
    docs = stage_extract(cfg, work)
    params = stage_build(cfg, work, docs, lists)
    for kw_list in lists:
        token_path, expectation_path = stage_token(cfg, work, kw_list)
        result = stage_search(work, token_path)
        stage_release(cfg, work, result, load_json(expectation_path))
    report = stage_verify(cfg, work, docs, lists)
    leak = leakage_profile(cfg, work, lists)
    write_markdown_report(cfg, work, params, report, leak)
    return {"params": params, "report": report, "leakage": leak}


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8-sig")
        return
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
