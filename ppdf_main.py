#!/usr/bin/env python3
r"""PPDF Hybrid System — Unified CLI entry point.

Orchestrates the full Privacy-Preserving Digital Forensics pipeline:
  Stage 1: Key Generation (HE Algorithm 1 + SSE Master Key)
  Stage 2: Preservation & Case-Related Filtering (SSE OR Search + HE Algorithm 2 Feature Encryption)
  Stage 3: Extraction & Case-Pertinent Narrowing (SSE AND Search + HE Algorithm 3 Encrypted K-Means)
  Stage 4: Controlled Decryption & Forensic Reporting (HE Algorithm 4 Cluster Decryption + Selective AES Decryption)

Usage examples:
  python ppdf_main.py keygen
  python ppdf_main.py stage2 --evidence-dir "..\KetQua"
  python ppdf_main.py stage3 --evidence-dir "..\KetQua" --mode conjunctive
  python ppdf_main.py stage4 --evidence-dir "..\KetQua"
  python ppdf_main.py full   --evidence-dir "..\KetQua"
  python ppdf_main.py test
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so `ppdf` is importable
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Stage 1: Key Generation
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> int:
    """Stage 1 — Generate HE key pair (Algorithm 1) and SSE key."""
    from ppdf.he.keygen import generate_keypair, save_public_key, save_private_key_to_env
    from ppdf.sse.se.peke import generate_key

    if args.seed is not None:
        print("⚠  WARNING: --seed is deterministic test/demo mode; do not use for production.")

    pair = generate_keypair(
        dimension=args.dimension,
        coefficient_bits=args.coefficient_bits,
        max_attempts=args.max_attempts,
        seed=args.seed,
    )
    pub_path = save_public_key(pair.public_key, args.public_key)
    env_path = save_private_key_to_env(
        pair.private_key,
        args.env_file,
        dimension=pair.dimension,
        coefficient_bits=pair.coefficient_bits,
        overwrite=args.overwrite,
    )
    print(f"✓ Stage 1 Key Generation succeeded after {pair.attempts} attempt(s).")
    print(f"  HE Public key  (d, r) → {pub_path}")
    print(f"  HE Private key (w_i)  → {env_path}")
    return 0


# ---------------------------------------------------------------------------
# Stage 2: OR Search + SSE Indexing + HE Feature Encryption
# ---------------------------------------------------------------------------

def cmd_stage2(args: argparse.Namespace) -> int:
    """Stage 2 — Disjunctive (OR) search, SSE index & vault build, HE feature encryption."""
    from ppdf.he.extract_encrypt import run as he_run
    from ppdf.sse.se.config import Config as SSEConfig
    from ppdf.sse.se.pipeline import run_all as sse_run_all

    evidence_dir = Path(args.evidence_dir).resolve()
    public_key_path = Path(args.public_key).resolve()
    he_output = Path(args.he_output).resolve()
    sse_work_dir = Path(args.sse_work_dir).resolve()

    print("=" * 72)
    print("STAGE 2a — Searchable Symmetric Encryption (SSE)")
    print("  Quét kho chứng cứ, trích xuất text, xây dựng chỉ mục mù & OR search")
    print("=" * 72)
    t0 = time.perf_counter()

    sse_cfg = SSEConfig(
        evidence_dir=evidence_dir,
        work_dir=sse_work_dir,
        sources=tuple(args.sources),
        keyword_files=tuple(Path(p) for p in args.xml) if args.xml else (),
        mode="disjunctive",
        content_mode=args.content_mode,
        content_policy=args.content_policy,
        limit_docs=args.limit,
        skip_slack=not args.include_slack,
        use_default_excludes=not args.no_default_excludes,
        report_label=args.report_label or "bao_cao_tim_kiem_mu",
    )
    sse_result = sse_run_all(sse_cfg)
    sse_elapsed = round(time.perf_counter() - t0, 2)
    print(f"\n✓ SSE pipeline hoàn thành trong {sse_elapsed}s")

    print()
    print("=" * 72)
    print("STAGE 2b — Homomorphic Encryption (HE Algorithm 2)")
    print("  Chấm điểm đặc trưng V_i = [Số_từ_khóa, Điểm_ẩn_giấu] & Mã hóa bằng Pub_key")
    print("=" * 72)
    t1 = time.perf_counter()

    he_result = he_run(
        evidence_dir,
        public_key_path,
        he_output,
        dimension=args.dimension,
        bit_width=args.bit_width,
    )
    he_elapsed = round(time.perf_counter() - t1, 2)
    print(f"\n✓ HE pipeline hoàn thành trong {he_elapsed}s")

    print()
    print("=" * 72)
    print("STAGE 2 — TỔNG KẾT BẢO TỒN & MÃ HÓA KÉP")
    print("=" * 72)
    blind_docs = sse_result['report']['totals']['blind_docs']
    print(f"  SSE: {blind_docs} tài liệu khớp từ khóa OR (Cr_kw) được đưa vào chỉ mục mù.")
    print(f"  HE:  {he_result['encrypted_artifacts']} đối tượng được chấm điểm & mã hóa vector đặc trưng.")
    print(f"  Tập tin không khớp (ảnh cá nhân/rác) bị loại trừ ngay, bảo vệ quyền riêng tư 100%.")
    print(f"  SSE Output → {sse_work_dir}")
    print(f"  HE  Output → {he_output}")
    print(f"  Thời gian xử lý: {sse_elapsed + he_elapsed:.2f}s")
    return 0


# ---------------------------------------------------------------------------
# Stage 3: Conjunctive AND Search + HE Algorithm 3 Encrypted K-Means
# ---------------------------------------------------------------------------

def cmd_stage3(args: argparse.Namespace) -> int:
    """Stage 3 — AND search via SSE + Encrypted K-Means via HE Algorithm 3."""
    from ppdf.sse.se.config import Config as SSEConfig
    from ppdf.sse.se.pipeline import (
        WorkDirs, load_docs_from_manifest, load_lists,
        stage_token, stage_search, stage_release, stage_verify,
        leakage_profile, write_markdown_report,
    )
    from ppdf.sse.se.store import load_json, save_json
    from ppdf.he.kmeans import EncryptedArtifact, encrypted_kmeans

    evidence_dir = Path(args.evidence_dir).resolve()
    sse_work_dir = Path(args.sse_work_dir).resolve()
    he_output = Path(args.he_output).resolve()
    stage3_dir = sse_work_dir / "stage3"
    stage3_dir.mkdir(parents=True, exist_ok=True)

    sse_cfg = SSEConfig(
        evidence_dir=evidence_dir,
        work_dir=sse_work_dir,
        sources=tuple(args.sources),
        keyword_files=tuple(Path(p) for p in args.xml) if args.xml else (),
        mode="conjunctive",
        content_mode=args.content_mode,
        content_policy=args.content_policy,
        skip_slack=not args.include_slack,
        use_default_excludes=not args.no_default_excludes,
        report_label="bao_cao_stage3_and",
    )

    work = WorkDirs.open(sse_cfg)
    docs = load_docs_from_manifest(work)

    custom_keywords = getattr(args, "keywords", None)
    if custom_keywords:
        from ppdf.sse.se.keywords import make_custom_keyword_list
        lists = [make_custom_keyword_list(custom_keywords, case_sensitive=sse_cfg.case_sensitive)]
        print(f"  • Áp dụng danh sách từ khóa chỉ định cho tìm kiếm AND: {[k.text for k in lists[0].keywords]}")
    else:
        lists = load_lists(sse_cfg)
        list_name = getattr(args, "list_name", None)
        if list_name:
            from ppdf.sse.se.tokens import slugify
            lists = [kl for kl in lists
                     if kl.name == list_name or slugify(kl.name) == slugify(list_name)]
            if not lists:
                print(f"ERROR: Danh sách từ khóa '{list_name}' không tồn tại.", file=sys.stderr)
                return 1

    print("=" * 72)
    print("STAGE 3.1 — Lọc tinh bằng SSE (Conjunctive Search - AND)")
    print("  Tìm kiếm mù trên Encrypted Index theo điều kiện AND giữa các từ khóa")
    print("=" * 72)

    pertinent_doc_ids = set()
    for kw_list in lists:
        token_path, expectation_path = stage_token(sse_cfg, work, kw_list)
        result = stage_search(work, token_path)
        stage_release(sse_cfg, work, result, load_json(expectation_path))
        handle_map = load_json(work.client / "handle_map.json")
        for hit in result["hits"]:
            pertinent_doc_ids.add(handle_map[hit["handle"]])

    report = stage_verify(sse_cfg, work, docs, lists)
    leak = leakage_profile(sse_cfg, work, lists)
    params = load_json(work.server / "index.json")["params"]
    write_markdown_report(sse_cfg, work, params, report, leak)

    print(f"\n✓ SSE AND Search hoàn thành: Tìm thấy {len(pertinent_doc_ids)} tài liệu thỏa mãn đồng thời (Crv'_kw).")

    # -----------------------------------------------------------------------
    # Stage 3.2: HE Algorithm 3 — Encrypted K-Means Clustering
    # -----------------------------------------------------------------------
    print()
    print("=" * 72)
    print("STAGE 3.2 — Phân cụm K-Means trên bản mã HE (Algorithm 3)")
    print("  Chỉ chọn vector mã hóa của tài liệu khớp AND đưa vào phân cụm (q=2)")
    print("=" * 72)

    cr_kwt_path = he_output / "share" / "Cr_kwt_prime.json"
    features_audit_path = he_output / "audit" / "features.json"

    if not cr_kwt_path.exists() or not features_audit_path.exists():
        print(f"⚠  Chưa có dữ liệu bản mã HE ({cr_kwt_path}). Vui lòng chạy Stage 2 trước.", file=sys.stderr)
        return 1

    cipher_records = load_json(cr_kwt_path)["records"]
    features_audit = load_json(features_audit_path)

    # Build mapping from sha256 / canonical path to ciphertext record
    cipher_by_art_id = {r["artifact_id"]: r["Cr_kwt_prime"] for r in cipher_records}
    art_meta = {f["artifact_id"]: f for f in features_audit}

    # Match pertinent docs to HE encrypted artifacts
    doc_by_id = {d.doc_id: d for d in docs}
    pertinent_artifacts: list[EncryptedArtifact] = []

    for doc_id in pertinent_doc_ids:
        doc = doc_by_id.get(doc_id)
        if not doc:
            continue
        # Find matching HE artifact by sha256 or path
        matched_art_id = None
        for aid, meta in art_meta.items():
            if meta.get("sha256") and meta["sha256"].lower() == doc.sha256.lower():
                matched_art_id = aid
                break
            if meta.get("source_path") == doc.canonical_path or doc.canonical_path in meta.get("local_paths", []):
                matched_art_id = aid
                break

        if matched_art_id and matched_art_id in cipher_by_art_id:
            pertinent_artifacts.append(
                EncryptedArtifact(
                    artifact_id=matched_art_id,
                    file_path=doc.canonical_path,
                    ciphertext_vector=cipher_by_art_id[matched_art_id],
                )
            )

    # If no artifacts matched AND, handle cleanly without fallback to random records
    if not pertinent_artifacts:
        print("\n[!] Không tìm thấy tài liệu nào thỏa mãn đồng thời tất cả các từ khóa AND.")
        all_kws = [k.text for kl in lists for k in kl.keywords]
        print(f"    (Danh sách từ khóa AND vừa tra cứu: {all_kws})")
        print("    Gợi ý: Sử dụng tham số --keywords \"tu_khoa_1,tu_khoa_2\" để chọn tập từ khóa hẹp hơn.")
        cluster_payload = {
            "algorithm": "Algorithm 3 - K-Means on Encrypted Data",
            "clusters_count": 0,
            "pertinent_artifacts_count": 0,
            "clusters": [],
        }
        cluster_path = stage3_dir / "encrypted_clusters.json"
        save_json(cluster_path, cluster_payload)
        return 0

    q = min(getattr(args, "q_clusters", 2), max(1, len(pertinent_artifacts)))
    encrypted_clusters = encrypted_kmeans(pertinent_artifacts, q=q, seed=42)

    # Save encrypted clusters
    cluster_payload = {
        "algorithm": "Algorithm 3 - K-Means on Encrypted Data",
        "clusters_count": len(encrypted_clusters),
        "pertinent_artifacts_count": len(pertinent_artifacts),
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "name": c.name,
                "artifact_ids": c.artifact_ids,
            }
            for c in encrypted_clusters
        ],
    }
    cluster_path = stage3_dir / "encrypted_clusters.json"
    save_json(cluster_path, cluster_payload)

    print(f"✓ Algorithm 3 K-Means hoàn thành: Đã gom thành {len(encrypted_clusters)} cụm trên bản mã.")
    for c in encrypted_clusters:
        print(f"  • Cụm {c.name}: {len(c.artifact_ids)} đối tượng (Bản mã ID: {', '.join(c.artifact_ids[:3])}...)")
    print(f"  Encrypted Clusters → {cluster_path}")
    return 0


# ---------------------------------------------------------------------------
# Stage 4: Controlled Decryption & Forensic Reporting
# ---------------------------------------------------------------------------

def cmd_stage4(args: argparse.Namespace) -> int:
    """Stage 4 — HE Algorithm 4 Cluster Decryption + Selective AES Decryption."""
    from ppdf.he.keygen import load_private_key_from_env, load_public_key
    from ppdf.he.kmeans import (
        EncryptedArtifact, EncryptedCluster, decrypt_clusters,
    )
    from ppdf.sse.se.config import Config as SSEConfig
    from ppdf.sse.se.pipeline import (
        WorkDirs, stage_selective_release, load_docs_from_manifest,
    )
    from ppdf.sse.se.store import load_json

    evidence_dir = Path(args.evidence_dir).resolve()
    sse_work_dir = Path(args.sse_work_dir).resolve()
    he_output = Path(args.he_output).resolve()
    public_key_path = Path(args.public_key).resolve()
    env_file = Path(args.env_file).resolve()
    stage4_dir = sse_work_dir / "stage4"
    stage4_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("STAGE 4.1 — Giải mã phân cụm bằng Private Key (HE Algorithm 4)")
    print("  Điều tra viên có thẩm quyền mở khóa Pri_key = w_i để xác định cụm nguy hiểm")
    print("=" * 72)

    if not env_file.exists():
        print(f"ERROR: Không tìm thấy khóa bí mật {env_file}.", file=sys.stderr)
        return 1

    private_key = load_private_key_from_env(env_file)
    public_key = load_public_key(public_key_path)

    stage3_cluster_path = sse_work_dir / "stage3" / "encrypted_clusters.json"
    if not stage3_cluster_path.exists():
        print(f"ERROR: Chưa có kết quả phân cụm Stage 3 ({stage3_cluster_path}).", file=sys.stderr)
        return 1

    stage3_data = load_json(stage3_cluster_path)
    if not stage3_data.get("clusters") or stage3_data.get("clusters_count", 0) == 0:
        print("\n[!] Không có cụm tài liệu chứng cứ khả nghi nào từ Stage 3.")
        print("    Toàn bộ dữ liệu được bảo vệ an toàn trong vault.bin (100% Data Minimization).")
        report_lines = [
            "# BÁO CÁO KẾT THÚC ĐIỀU TRA PHÁP CHỨNG SỐ (PPDF HYBRID)",
            "",
            f"**Thời gian báo cáo**: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Mô hình**: Hybrid SSE (mKEES Exact Search) + HE (Lattice Algorithm 1-4)  ",
            f"**Kho dữ liệu chứng cứ**: `{evidence_dir.name}`  ",
            "",
            "---",
            "",
            "## 1. Kết quả kiểm tra điều tra",
            "- Không có tài liệu nào thỏa mãn đồng thời tất cả các từ khóa AND của vụ án.",
            "- Không có file nào được cấp quyền giải mã xuất trình.",
            "",
            "## 2. Bảo vệ quyền riêng tư (Data Minimization)",
            "- 100% dữ liệu tiếp tục được niêm phong an toàn trong `vault.bin` (AES-256).",
        ]
        report_path = stage4_dir / "bao_cao_phap_chung_ppdf.md"
        report_path.write_text("\n".join(report_lines), encoding="utf-8")
        print(f"  Báo cáo Pháp chứng → {report_path}")
        return 0

    cipher_records = load_json(he_output / "share" / "Cr_kwt_prime.json")["records"]
    features_audit = load_json(he_output / "audit" / "features.json")
    cipher_map = {r["artifact_id"]: r["Cr_kwt_prime"] for r in cipher_records}
    art_meta = {f["artifact_id"]: f for f in features_audit}

    # Reconstruct EncryptedCluster and EncryptedArtifact objects
    artifacts = []
    seen_ids = set()
    for c_info in stage3_data["clusters"]:
        for aid in c_info["artifact_ids"]:
            if aid not in seen_ids and aid in cipher_map:
                seen_ids.add(aid)
                path = art_meta.get(aid, {}).get("source_path", aid)
                artifacts.append(
                    EncryptedArtifact(
                        artifact_id=aid,
                        file_path=path,
                        ciphertext_vector=cipher_map[aid],
                    )
                )

    clusters = [
        EncryptedCluster(
            cluster_id=c_info["cluster_id"],
            name=c_info["name"],
            artifact_ids=c_info["artifact_ids"],
            centroid_cipher=[],
        )
        for c_info in stage3_data["clusters"]
    ]

    # Run Algorithm 4 Decryption
    decrypted_results = decrypt_clusters(
        clusters, artifacts, private_key, public_key.d, bit_width=getattr(args, "bit_width", 8)
    )

    print(f"\n✓ Giải mã Algorithm 4 thành công. Kết quả phân loại nguy cơ:")
    for res in decrypted_results:
        print(f"  • [{res.risk_level}] ({res.artifact_count} file)")
        print(f"    Điểm trung bình: Từ khóa = {res.average_features[0]}, Điểm ẩn giấu = {res.average_features[1]}")
        for r in res.records:
            print(f"      - {r['file_path']} | V_i = {r['V_i']}")

    # -----------------------------------------------------------------------
    # Stage 4.2: Selective AES Decryption
    # -----------------------------------------------------------------------
    print()
    print("=" * 72)
    print("STAGE 4.2 — Giải mã có chọn lọc nội dung file chứng cứ (Selective AES)")
    print("  Chỉ giải mã file thuộc Cụm 1 (Nguy hiểm nhất). File khác giữ nguyên mã hóa.")
    print("=" * 72)

    sse_cfg = SSEConfig(evidence_dir=evidence_dir, work_dir=sse_work_dir)
    work = WorkDirs.open(sse_cfg)
    docs = load_docs_from_manifest(work)
    doc_by_path = {d.canonical_path: d for d in docs}
    doc_by_sha = {d.sha256.lower(): d for d in docs}

    # Get artifact IDs from High Suspicion cluster (Cluster 1)
    high_risk_cluster = decrypted_results[0] if decrypted_results else None
    selective_doc_ids = set()

    if high_risk_cluster:
        for rec in high_risk_cluster.records:
            aid = rec["artifact_id"]
            meta = art_meta.get(aid, {})
            # Match to SSE doc_id
            matched_doc = None
            if meta.get("sha256") and meta["sha256"].lower() in doc_by_sha:
                matched_doc = doc_by_sha[meta["sha256"].lower()]
            elif rec["file_path"] in doc_by_path:
                matched_doc = doc_by_path[rec["file_path"]]

            if matched_doc:
                selective_doc_ids.add(matched_doc.doc_id)

    # Perform selective release
    released_rows = stage_selective_release(
        sse_cfg, work, selective_doc_ids, label="bang_chung_chon_loc_stage4"
    )

    # -----------------------------------------------------------------------
    # Generate Final Forensic Presentation Report
    # -----------------------------------------------------------------------
    report_lines = [
        "# BÁO CÁO KẾT THÚC ĐIỀU TRA PHÁP CHỨNG SỐ (PPDF HYBRID)",
        "",
        f"**Thời gian báo cáo**: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Mô hình**: Hybrid SSE (mKEES Exact Search) + HE (Lattice Algorithm 1-4)  ",
        f"**Kho dữ liệu chứng cứ**: `{evidence_dir.name}`  ",
        "",
        "---",
        "",
        "## 1. Giả thuyết điều tra & Ranh giới riêng tư",
        "- **H1 (Ủng hộ rò rỉ)**: Đối tượng đã truy cập, gom tài liệu mật và đổi đuôi/xóa file nhằm che giấu.",
        "- **Chính sách Data Minimization**: Chỉ giải mã các file thỏa mãn đồng thời từ khóa vụ án và có điểm số bất thường cao.",
        "",
        "## 2. Kết quả Phân cụm trên bản mã HE (Algorithm 3 & 4)",
    ]

    for c in decrypted_results:
        report_lines.append(f"### {c.name}")
        report_lines.append(f"- **Mức độ đánh giá**: `{c.risk_level}`")
        report_lines.append(f"- **Số lượng file**: {c.artifact_count}")
        report_lines.append(f"- **Chỉ số trung bình**: {c.average_features[0]} từ khóa, {c.average_features[1]} điểm che giấu")
        report_lines.append("| ID đối tượng | Đường dẫn file | Vector V_i [Từ khóa, Điểm ẩn] |")
        report_lines.append("|---|---|---|")
        for r in c.records:
            report_lines.append(f"| `{r['artifact_id'][:12]}` | `{r['file_path']}` | `{r['V_i']}` |")
        report_lines.append("")

    report_lines.extend([
        "## 3. Danh sách File chứng cứ được giải mã chọn lọc (Selective Decryption)",
        "Các file sau được giải mã nội dung từ vault để xuất trình trước hội đồng điều tra:",
        "",
        "| Đường dẫn | SHA-256 | Kích thước | Trạng thái giải mã | File xuất trình |",
        "|---|---|---|---|---|",
    ])
    for r in released_rows:
        report_lines.append(
            f"| `{r['file_path']}` | `{r['sha256'][:16]}...` | {r['size']:,} B | `{r['status']}` | `{r['released_file']}` |"
        )

    report_lines.extend([
        "",
        "## 4. Bảo vệ quyền riêng tư cho các dữ liệu còn lại",
        "- Toàn bộ các file thuộc **Cụm 2 (Dữ liệu thường)** và các file không khớp từ khóa OR **vẫn được giữ nguyên dạng mã hóa AES-256** trong `vault.bin`.",
        "- Điều tra viên không cần và không được cấp quyền mở khóa các tập tin cá nhân không liên quan.",
        "",
    ])

    report_path = stage4_dir / "bao_cao_phap_chung_ppdf.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    print(f"\n✓ Hoàn thành Stage 4!")
    print(f"  File chứng cứ được giải mã chọn lọc → {work.results / 'selective_evidence'}")
    print(f"  Báo cáo pháp chứng hoàn chỉnh       → {report_path}")
    return 0


# ---------------------------------------------------------------------------
# Full Pipeline Execution (Stages 1 -> 4)
# ---------------------------------------------------------------------------

def cmd_full(args: argparse.Namespace) -> int:
    """Run the complete 4-stage PPDF pipeline end-to-end."""
    print("╔" + "═" * 70 + "╗")
    print("║  PPDF HYBRID SYSTEM — Toàn bộ quy trình 4 giai đoạn                ║")
    print("║  Homomorphic Encryption (HE) + Searchable Symmetric Encryption    ║")
    print("╚" + "═" * 70 + "╝")
    print()

    overall_start = time.perf_counter()

    # Stage 1 — Keygen
    print("━" * 72)
    print("▶ STAGE 1 — Chuẩn bị & Sinh khóa (HE Algorithm 1 + SSE Key)")
    print("━" * 72)
    ret = cmd_keygen(args)
    if ret != 0:
        return ret
    print()

    # Stage 2 — Preservation & Encryption (OR Search + HE Alg 2)
    print("━" * 72)
    print("▶ STAGE 2 — Bảo tồn & Lọc liên quan (SSE OR Search + HE Algorithm 2)")
    print("━" * 72)
    ret = cmd_stage2(args)
    if ret != 0:
        return ret
    print()

    # Stage 3 — Extraction & Computation (AND Search + HE Alg 3 K-Means)
    print("━" * 72)
    print("▶ STAGE 3 — Thu hẹp & Phân cụm đồng hình (SSE AND Search + HE Algorithm 3)")
    print("━" * 72)
    ret = cmd_stage3(args)
    if ret != 0:
        return ret
    print()

    # Stage 4 — Presentation & Selective Decryption (HE Alg 4 + Selective AES)
    print("━" * 72)
    print("▶ STAGE 4 — Trình bày & Giải mã có chọn lọc (HE Algorithm 4 + Selective AES)")
    print("━" * 72)
    ret = cmd_stage4(args)
    if ret != 0:
        return ret
    print()

    total = round(time.perf_counter() - overall_start, 2)
    print("╔" + "═" * 70 + "╗")
    print(f"║  ✓ Hoàn thành toàn bộ quy trình PPDF trong {total}s" + " " * (28 - len(str(total))) + "║")
    print("╚" + "═" * 70 + "╝")
    return 0


# ---------------------------------------------------------------------------
# Test Runner
# ---------------------------------------------------------------------------

def cmd_test(args: argparse.Namespace) -> int:
    """Run all unit and integration tests."""
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(str(_PROJECT_ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


# ---------------------------------------------------------------------------
# Argument Parser Construction
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ppdf_main",
        description="PPDF Hybrid System — Privacy-Preserving Digital Forensics (HE + SSE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Lệnh thực thi giai đoạn PPDF")

    # --- keygen ---
    p_keygen = sub.add_parser("keygen", help="Giai đoạn 1: Sinh khóa bất đối xứng")
    p_keygen.add_argument("--dimension", type=int, default=8)
    p_keygen.add_argument("--coefficient-bits", type=int, default=128)
    p_keygen.add_argument("--max-attempts", type=int, default=100)
    p_keygen.add_argument("--seed", type=int, default=None)
    p_keygen.add_argument("--public-key", default="public_key.json")
    p_keygen.add_argument("--env-file", default=".env")
    p_keygen.add_argument("--overwrite", action="store_true")

    # --- stage2 ---
    p_stage2 = sub.add_parser("stage2", help="Giai đoạn 2: Lọc OR + Lập chỉ mục SSE + Mã hóa HE")
    _add_evidence_args(p_stage2)
    _add_he_args(p_stage2)
    _add_sse_args(p_stage2)
    p_stage2.add_argument("--he-output", type=str, default="outputs/he_stage2")

    # --- stage3 ---
    p_stage3 = sub.add_parser("stage3", help="Giai đoạn 3: Lọc AND (SSE) + Phân cụm K-Means bản mã (HE)")
    _add_evidence_args(p_stage3)
    _add_he_args(p_stage3)
    _add_sse_args(p_stage3)
    p_stage3.add_argument("--he-output", type=str, default="outputs/he_stage2")
    p_stage3.add_argument("--mode", default="conjunctive", choices=["disjunctive", "conjunctive"])
    p_stage3.add_argument("--list", dest="list_name", help="Tên danh sách từ khóa chỉ định")
    p_stage3.add_argument("-k", "--keywords", help="Danh sách từ khóa chỉ định cho tìm kiếm AND (phân tách bởi dấu phẩy, ví dụ: 'secret_project,proposal')")
    p_stage3.add_argument("--q-clusters", type=int, default=2, help="Số cụm K-Means (mặc định 2: Nguy cơ cao / Thấp)")

    # --- stage4 ---
    p_stage4 = sub.add_parser("stage4", help="Giai đoạn 4: Giải mã Algorithm 4 + Giải mã chọn lọc AES")
    _add_evidence_args(p_stage4)
    _add_he_args(p_stage4)
    _add_sse_args(p_stage4)
    p_stage4.add_argument("--he-output", type=str, default="outputs/he_stage2")
    p_stage4.add_argument("--env-file", default=".env")

    # --- full ---
    p_full = sub.add_parser("full", help="Chạy toàn bộ 4 giai đoạn từ đầu đến cuối")
    _add_evidence_args(p_full)
    _add_he_args(p_full)
    _add_sse_args(p_full)
    p_full.add_argument("--coefficient-bits", type=int, default=128)
    p_full.add_argument("--max-attempts", type=int, default=100)
    p_full.add_argument("--seed", type=int, default=None)
    p_full.add_argument("--env-file", default=".env")
    p_full.add_argument("--overwrite", action="store_true")
    p_full.add_argument("--he-output", type=str, default="outputs/he_stage2")
    p_full.add_argument("-k", "--keywords", help="Danh sách từ khóa chỉ định cho tìm kiếm AND ở Stage 3 (phân tách bởi dấu phẩy)")
    p_full.add_argument("--q-clusters", type=int, default=2)

    # --- test ---
    sub.add_parser("test", help="Chạy bộ kiểm thử tự động")

    return parser


def _add_evidence_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--evidence-dir", type=str, required=True, help="Thư mục chứa chứng cứ số")
    p.add_argument("--sources", nargs="+", default=["PC", "RM1", "RM2"], help="Các nguồn dữ liệu")


def _add_he_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--public-key", default="public_key.json", help="Đường dẫn file public key JSON")
    p.add_argument("--dimension", type=int, default=8, help="Chiều lattice n")
    p.add_argument("--bit-width", type=int, default=8, help="Độ rộng bit đặc trưng")


def _add_sse_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--sse-work-dir", type=str, default="outputs/sse_work", help="Thư mục làm việc của SSE")
    p.add_argument("--xml", action="append", type=str, default=None, help="File XML từ khóa")
    p.add_argument("--content-mode", default="full", choices=["full", "index-only"])
    p.add_argument("--content-policy", default="documents", choices=["documents", "all", "names"])
    p.add_argument("--limit", type=int, default=None, help="Giới hạn số file để chạy thử nhanh")
    p.add_argument("--include-slack", action="store_true")
    p.add_argument("--no-default-excludes", action="store_true")
    p.add_argument("--report-label", default=None)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "keygen": cmd_keygen,
        "stage2": cmd_stage2,
        "stage3": cmd_stage3,
        "stage4": cmd_stage4,
        "full": cmd_full,
        "test": cmd_test,
    }

    try:
        return handlers[args.command](args)
    except (ValueError, KeyError, FileExistsError, FileNotFoundError, OSError) as exc:
        print(f"\n✗ Lỗi thực thi: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
