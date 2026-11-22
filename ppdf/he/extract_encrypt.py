"""Read the cleaned forensic handoff, extract features, run PPDF step 2.2b.

Only the public key is loaded. Evidence is read in place and never modified.
Plaintext provenance stays in audit/; share/ contains opaque IDs and ciphertext.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import sys
import uuid
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .encrypt import Algorithm2
from .keygen import load_public_key


FEATURE_ORDER = ["keyword_count", "concealment_score"]
RUBRIC = {"extension_mismatch": 3, "recovered_path": 2, "slack_path": 1}
EXCLUDED_NAMES = {"rm#1.png", "Verify RM2.png", "Verify PC.png", "doi_duoi_log.csv"}


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def verify_manifest(root: Path) -> dict[str, dict]:
    entries = json.loads((root / "MANIFEST_SHA256.json").read_text(encoding="utf-8-sig"))
    checked = {}
    for entry in entries:
        rel = entry["path"].replace("\\", "/")
        path = root / rel
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"manifest path escapes input directory: {rel}")
        if rel in checked:
            raise ValueError(f"duplicate manifest path: {rel}")
        if not path.is_file() or path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"].lower():
            raise ValueError(f"manifest verification failed: {rel}")
        checked[rel] = entry
    return checked


def load_keywords(path: Path) -> list[str]:
    elements = ET.parse(path).getroot().iter("keyword")
    result = []
    for node in elements:
        if node.get("literal") != "true" or node.get("whole") != "true":
            raise ValueError(f"only literal, whole-word keywords are supported: {path}")
        keyword = (node.text or "").strip().casefold()
        if keyword and keyword not in result:
            result.append(keyword)
    if not result:
        raise ValueError(f"empty keyword dictionary: {path}")
    return result


def keyword_matches(text: str, keywords: list[str]) -> set[str]:
    normalized = text.casefold()
    return {kw for kw in keywords if re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", normalized)}


def detect_format(path: Path) -> str:
    with path.open("rb") as handle:
        magic = handle.read(16)
    if magic.startswith(b"PK\x03\x04") and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            for marker, kind in [("word/document.xml", "docx"), ("ppt/presentation.xml", "pptx"), ("xl/workbook.xml", "xlsx")]:
                if marker in names:
                    return kind
        return "zip"
    if magic.startswith(bytes.fromhex("d0cf11e0a1b11ae1")):
        return "ole"  # Container recognition does not establish DOC vs PPT vs XLS.
    for signature, kind in [(b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"BM", "bmp"), (b"%PDF", "pdf"), (b"!BDN", "ost")]:
        if magic.startswith(signature):
            return kind
    return "unknown"


def extract_text(path: Path, kind: str) -> tuple[str, str]:
    """Read OOXML text/metadata, or use a documented partial binary fallback."""
    if kind in {"docx", "pptx", "xlsx"}:
        parts = []
        total_size = 0
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.filename.endswith(".xml") or not info.filename.startswith(("word/", "ppt/", "xl/", "docProps/")):
                    continue
                total_size += info.file_size
                if total_size > 128 * 1024 * 1024:
                    raise ValueError(f"OOXML extraction exceeds 128 MiB: {path}")
                node = ET.fromstring(archive.read(info))
                # Join runs within paragraphs/cells so split words still match.
                parent_tags = {"p", "si", "c"}
                groups = [n for n in node.iter() if n.tag.rsplit("}", 1)[-1] in parent_tags]
                if groups:
                    # Prefer paragraphs/shared strings to avoid counting a cell twice.
                    for group in groups:
                        parts.append("".join(group.itertext()))
                else:
                    parts.append(" ".join(node.itertext()))
        return "\n".join(parts), "ooxml_text_metadata_no_ocr_or_embedded_objects"
    if path.suffix.lower() in {".log", ".ini", ".csv"} and kind == "unknown":
        return path.read_text(encoding="utf-8-sig", errors="replace"), "utf8_text"
    if kind in {"png", "jpeg", "gif", "bmp"}:
        return "", "image_no_ocr"
    # Read once: invoking GNU strings three times is very slow on mounted disks.
    # The case dictionary is ASCII; these patterns also recognize ASCII in UTF-16
    # at either alignment. This is partial string extraction, not an OST/OLE parser.
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError(f"binary string extraction exceeds 128 MiB: {path}")
    data = path.read_bytes()
    parts = []
    for pattern, encoding in [(rb"[\x09\x20-\x7e]{4,}", "ascii"),
                              (rb"(?:[\x09\x20-\x7e]\x00){4,}", "utf-16-le"),
                              (rb"(?:\x00[\x09\x20-\x7e]){4,}", "utf-16-be")]:
        parts.extend(match.group().decode(encoding) for match in re.finditer(pattern, data))
    return "\n".join(parts), "partial_ascii_utf16le_utf16be_strings"


def concealment(path: str, *, mismatch: bool = False) -> tuple[int, list[str]]:
    # These are observable indicators, not a probability or conclusion of intent.
    flags = []
    if mismatch:
        flags.append("extension_mismatch")
    if any(token in path for token in ("$OrphanFiles/", "$CarvedFiles/")):
        flags.append("recovered_path")
    if path.casefold().endswith("-slack"):
        flags.append("slack_path")
    return sum(RUBRIC[flag] for flag in flags), flags


def is_mismatch(path: Path, kind: str) -> bool:
    extension = path.suffix.casefold()
    if kind == "ole":
        return extension not in {".doc", ".ppt", ".xls", ".msg"}
    expected = {"docx": {".docx"}, "pptx": {".pptx"}, "xlsx": {".xlsx"},
                "png": {".png"}, "jpeg": {".jpg", ".jpeg"}, "gif": {".gif"},
                "bmp": {".bmp"}, "pdf": {".pdf"}, "ost": {".ost", ".pst"}}
    return kind in expected and extension not in expected[kind]


def new_record(source: str, path: str) -> dict:
    identity = source + "\0" + path
    return {"artifact_id": hashlib.sha256(identity.encode()).hexdigest()[:32],
            "source": source, "source_path": path, "local_paths": [],
            "indexed_keywords": [], "index_references": [], "local_keywords": [],
            "sha256": None, "format": None, "extraction": "index_only_not_exported",
            "concealment_coverage": "path_indicators_only_content_unavailable"}


def build_features(root: Path, manifest: dict) -> tuple[list[dict], dict]:
    dictionaries = {"PC": load_keywords(root / "TuKhoa_PC.xml"),
                    "RM2": load_keywords(root / "TuKhoa_RM1_RM2.xml"),
                    "RM1": load_keywords(root / "TuKhoa_RM1_RM2.xml")}
    records = {}
    csv_counts = {}
    for path in sorted((root / "PC/KeywordHits").glob("*.csv")) + sorted((root / "RM2").glob("hits_*.csv")):
        source = path.relative_to(root).parts[0]
        rows = read_csv(path)
        csv_counts[str(path.relative_to(root))] = len(rows)
        for row_number, row in enumerate(rows, 1):
            source_path = row["File Path"]
            record = records.setdefault((source, source_path), new_record(source, source_path))
            keyword = row["Keyword"].strip().casefold()
            if keyword not in dictionaries[source]:
                raise ValueError(f"unexpected keyword in {path}: {keyword}")
            record["indexed_keywords"].append(keyword)
            record["index_references"].append({"csv": str(path.relative_to(root)), "record": row_number})

    # Map exported files to original image paths when the correspondence is unambiguous.
    local_to_source = {}
    for key in records:
        source, source_path = key
        if source == "RM2" and "/$OrphanFiles/" in source_path:
            rel = "RM2/$OrphanFiles/" + source_path.split("/$OrphanFiles/", 1)[1]
            if (root / rel).is_file():
                local_to_source[rel] = key
        if source == "PC" and source_path.endswith("/iaman.informant@nist.gov.ost"):
            local_to_source["PC/EmailNguon/iaman.informant@nist.gov.ost"] = key

    # Collapse renamed export copies only; keep identical bytes on different devices distinct.
    aliases = {}
    rename_log_path = root / "RM2/$OrphanFiles_đổi đuôi/doi_duoi_log.csv"
    if rename_log_path.is_file():
        rename_log = read_csv(rename_log_path)
        renamed_root = root / "RM2/$OrphanFiles_đổi đuôi"
        for path in sorted(renamed_root.rglob("*")):
            if not path.is_file() or path.name == "doi_duoi_log.csv":
                continue
            relative = path.relative_to(renamed_root)
            original = root / "RM2/$OrphanFiles" / relative
            if not original.is_file():
                matching = [row for row in rename_log if row["NewName"] == path.name]
                if len(matching) != 1:
                    raise ValueError(f"cannot resolve renamed export: {path}")
                original = root / "RM2/$OrphanFiles" / relative.parent / matching[0]["OldName"]
                if manifest[str(path.relative_to(root)).replace("\\", "/")]["sha256"].lower() != matching[0]["SHA256"].lower():
                    raise ValueError(f"rename log hash mismatch: {path}")
            old_rel = str(original.relative_to(root)).replace("\\", "/")
            new_rel = str(path.relative_to(root)).replace("\\", "/")
            if manifest[old_rel]["sha256"].lower() != manifest[new_rel]["sha256"].lower():
                raise ValueError(f"renamed copy differs from original: {new_rel}")
            aliases.setdefault(old_rel, []).append(new_rel)

    exclusions = []
    extracted_count = 0
    for rel_raw in sorted(manifest):
        rel = rel_raw.replace("\\", "/")
        path = root / rel
        if rel.startswith("RM2/$OrphanFiles_đổi đuôi/"):
            continue
        if path.suffix.casefold() in {".md", ".xml"} or path.name in EXCLUDED_NAMES or (path.suffix == ".csv" and rel != "PC/emails.csv"):
            exclusions.append({"path": rel, "reason": "handoff_control_or_verification"})
            continue
        source = Path(rel).parts[0]
        if source not in dictionaries:
            continue
        key = local_to_source.get(rel, (source, "export:" + rel))
        record = records.setdefault(key, new_record(*key))
        kind = detect_format(path)
        # Slack is a separate byte artifact; do not interpret its inherited suffix as a format.
        mismatch = not path.name.endswith("-slack") and is_mismatch(path, kind)
        text, extraction = extract_text(path, kind)
        record.update(local_paths=[rel] + aliases.get(rel, []),
                      sha256=manifest[rel]["sha256"].lower(), bytes=manifest[rel]["bytes"],
                      format=kind, extraction=extraction,
                      concealment_coverage="signature_and_path_indicators_no_steganalysis",
                      local_keywords=sorted(keyword_matches(text + "\n" + rel, dictionaries[source])),
                      extension_mismatch=mismatch)
        extracted_count += 1
        if extracted_count % 10 == 0:
            print(f"Extracted {extracted_count} local artifacts", file=sys.stderr, flush=True)

    result = []
    for record in sorted(records.values(), key=lambda item: (item["source"], item["source_path"])):
        record["indexed_keywords"] = sorted(set(record["indexed_keywords"]))
        record["matched_keywords"] = sorted(set(record["indexed_keywords"]) | set(record["local_keywords"]))
        scoring_path = record["local_paths"][0] if record["local_paths"] else record["source_path"]
        score, flags = concealment(scoring_path, mismatch=record.get("extension_mismatch", False))
        record.update(keyword_count=len(record["matched_keywords"]), concealment_score=score,
                      concealment_indicators=flags, selected=bool(record["matched_keywords"]))
        record["V_i"] = [record["keyword_count"], score]
        result.append(record)
    return result, {"dictionaries": dictionaries, "csv_row_counts": csv_counts,
                    "excluded_control_files": exclusions, "renamed_alias_count": sum(map(len, aliases.values()))}


def write_json(path: Path, payload: object, *, private: bool = False) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600 if private else 0o644)


def run(root: Path, public_key_path: Path, output: Path, *, dimension: int = 8, bit_width: int = 8) -> dict:
    root, output = root.resolve(), output.resolve()
    if not root.is_dir():
        raise ValueError(f"input directory does not exist: {root}")
    if output.is_relative_to(root):
        raise ValueError("output must be outside the evidence directory")
    if output.exists():
        raise FileExistsError(f"output already exists; choose a fresh directory: {output}")
    cipher = Algorithm2(load_public_key(public_key_path), dimension)
    print("Verifying source SHA-256 manifest before processing", file=sys.stderr, flush=True)
    manifest = verify_manifest(root)
    before = digest(root / "MANIFEST_SHA256.json")
    print(f"Verified {len(manifest)} files; extracting features", file=sys.stderr, flush=True)
    records, provenance = build_features(root, manifest)
    selected = [record for record in records if record["selected"]]
    if not selected:
        raise ValueError("no OR-matched artifacts to encrypt")
    run_id = str(uuid.uuid4())
    canonical_key = json.dumps(cipher.public_key.as_dict(), sort_keys=True, separators=(",", ":"))
    key_fingerprint = hashlib.sha256(canonical_key.encode()).hexdigest()
    print(f"Encrypting {len(selected)} OR-matched artifacts", file=sys.stderr, flush=True)
    encrypted = [{"artifact_id": record["artifact_id"],
                  "Cr_kwt_prime": cipher.encrypt_vector(record["V_i"], bit_width=bit_width)} for record in selected]
    # Re-read every manifest entry after processing; no evidence writes are performed.
    print("Verifying source SHA-256 manifest after processing", file=sys.stderr, flush=True)
    verify_manifest(root)
    if digest(root / "MANIFEST_SHA256.json") != before:
        raise ValueError("source manifest changed during processing")
    summary = {"run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(),
               "manifest_entries_verified_before_and_after": len(manifest),
               "scored_artifacts": len(records), "encrypted_artifacts": len(selected),
               "zero_keyword_artifacts_audit_only": len(records) - len(selected),
               "indexed_source_paths": sum(bool(r["index_references"]) for r in records),
               "indexed_without_local_bytes": sum(bool(r["index_references"]) and not r["local_paths"] for r in records),
               "artifacts_with_local_bytes": sum(bool(r["local_paths"]) for r in records),
               "by_source_encrypted": dict(Counter(r["source"] for r in selected)),
               "concealment_score_counts_encrypted": dict(Counter(str(r["concealment_score"]) for r in selected)),
               "feature_order": FEATURE_ORDER, "concealment_rubric": RUBRIC,
               "public_key_sha256_canonical_json": key_fingerprint,
               "input_manifest_sha256": before, "dimension": dimension, "bit_width": bit_width,
               "python": platform.python_version(),
               "implementation_sha256": {p.name: digest(p) for p in [Path(__file__), Path(__file__).with_name("encrypt.py"), Path(__file__).with_name("keygen.py")]}}
    output.mkdir(parents=True)
    audit, share = output / "audit", output / "share"
    audit.mkdir(mode=0o700)
    share.mkdir()
    write_json(audit / "features.json", records, private=True)
    write_json(audit / "provenance.json", provenance, private=True)
    write_json(audit / "run_summary.json", summary, private=True)
    with (audit / "features.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        columns = ["artifact_id", "source", "source_path", "keyword_count", "concealment_score", "selected", "matched_keywords", "local_paths", "extraction", "sha256"]
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for record in records:
            writer.writerow({key: json.dumps(record[key], ensure_ascii=False) if isinstance(record[key], list) else record[key] for key in columns})
    (audit / "features.csv").chmod(0o600)
    payload = {"schema": "ppdf.algorithm2.feature_bits.v1", "run_id": run_id,
               "public_key_sha256_canonical_json": key_fingerprint,
               "algorithm": "c = centered_mod(b + 2*sum(u_i*r^i), d)",
               "dimension": dimension, "noise_coefficients": [-1, 0, 1],
               "feature_order": FEATURE_ORDER, "encoding": "unsigned_binary_lsb_first",
               "bit_width": bit_width, "ciphertext_integer_encoding": "signed_decimal_string",
               "security_status": "research_prototype_not_security_audited; decryption_and_noise_budget_not_validated",
               "records": encrypted}
    write_json(share / "Cr_kwt_prime.json", payload)
    write_json(share / "public_key.json", cipher.public_key.as_dict())
    files = {str(p.relative_to(output)): digest(p) for p in sorted(output.rglob("*")) if p.is_file()}
    write_json(output / "OUTPUT_SHA256.json", files, private=True)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="PPDF step 2.2b: extract and encrypt forensic features")
    parser.add_argument("--input", type=Path, default=Path("Data Forensic lọc sạch"))
    parser.add_argument("--public-key", type=Path, default=Path("public_key.json"))
    parser.add_argument("--output", type=Path, default=Path("outputs/he_step_2_2b"))
    parser.add_argument("--dimension", type=int, default=8, help="public lattice dimension; never loaded from .env")
    parser.add_argument("--bit-width", type=int, default=8)
    args = parser.parse_args()
    try:
        result = run(args.input, args.public_key, args.output, dimension=args.dimension, bit_width=args.bit_width)
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Step 2.2b failed: {exc}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
