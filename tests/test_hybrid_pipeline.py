"""Integration tests for PPDF Hybrid (HE + SSE) 4-stage pipeline."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from ppdf.he.keygen import generate_keypair, save_public_key, save_private_key_to_env
from ppdf.he.encrypt import Algorithm2
from ppdf.he.kmeans import (
    EncryptedArtifact, encrypted_kmeans, decrypt_clusters,
)
from ppdf.he.extract_encrypt import run as run_he_stage2
from ppdf.sse.se.config import Config as SSEConfig
from ppdf.sse.se.pipeline import (
    run_all as run_sse_stage2, WorkDirs, stage_token, stage_search,
    stage_release, stage_verify, stage_selective_release,
)
from ppdf.sse.se.store import load_json


def make_hybrid_fixture(root: Path) -> None:
    """Create a minimal mock forensic handoff for both SSE and HE testing."""
    for folder in ["PC", "RM1", "RM2", "PC/KeywordHits"]:
        (root / folder).mkdir(parents=True, exist_ok=True)

    # 1. XML keyword lists
    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<keyword_lists><keyword_list name="TuKhoa_Test">'
        '<keyword literal="true" whole="true">Secret Project Data</keyword>'
        '<keyword literal="true" whole="true">secret_project</keyword>'
        '<keyword literal="true" whole="true">exfiltrate</keyword>'
        '</keyword_list></keyword_lists>\n'
    )
    (root / "TuKhoa_PC.xml").write_text(xml_content, encoding="utf-8")
    (root / "TuKhoa_RM1_RM2.xml").write_text(xml_content, encoding="utf-8")

    # 2. Evidence documents
    # F1: High-suspicion hidden file: multiple keywords + in OrphanFiles
    orphan_dir = root / "RM2" / "$OrphanFiles_đổi đuôi" / "proposal"
    orphan_dir.mkdir(parents=True, exist_ok=True)
    f3_file = orphan_dir / "landscape.docx"
    with zipfile.ZipFile(f3_file, "w") as z:
        z.writestr(
            "word/document.xml",
            '<w:document xmlns:w="urn:w"><w:p><w:r><w:t>Secret Project Data exfiltrate plan</w:t></w:r></w:p></w:document>',
        )

    # F2: Normal note
    (root / "PC" / "notes.txt").write_text("Working on secret_project\n", encoding="utf-8")
    # F3: Irrelevant private file (should be ignored by OR filter)
    (root / "PC" / "personal_photo.txt").write_text("Holiday family photo description\n", encoding="utf-8")

    # 3. Hit CSV for HE feature extraction
    with (root / "PC" / "KeywordHits" / "hits.csv").open("w", encoding="utf-8", newline="") as f:
        f.write("Keyword,File Path\n")
        f.write("secret_project,PC/notes.txt\n")

    # 4. Manifest
    import hashlib
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.name.endswith(".md"):
            entries.append({
                "path": str(p.relative_to(root)).replace("\\", "/"),
                "bytes": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            })
    (root / "MANIFEST_SHA256.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")


class HybridPipelineTests(unittest.TestCase):
    def test_full_hybrid_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            evidence = tmp_path / "evidence"
            evidence.mkdir()
            make_hybrid_fixture(evidence)

            # ---------------------------------------------------------------
            # Stage 1: Keygen (HE Alg 1 + SSE Key)
            # ---------------------------------------------------------------
            pair = generate_keypair(dimension=4, coefficient_bits=8, seed=42)
            pub_path = save_public_key(pair.public_key, tmp_path / "public_key.json")
            env_path = save_private_key_to_env(pair.private_key, tmp_path / ".env", dimension=4, coefficient_bits=8)
            self.assertTrue(pub_path.exists())
            self.assertTrue(env_path.exists())

            # ---------------------------------------------------------------
            # Stage 2a: SSE OR Search & Indexing
            # ---------------------------------------------------------------
            sse_work = tmp_path / "sse_work"
            cfg = SSEConfig(
                evidence_dir=evidence,
                work_dir=sse_work,
                sources=("PC", "RM1", "RM2"),
                keyword_files=(evidence / "TuKhoa_PC.xml",),
                mode="disjunctive",
                use_default_excludes=False,
                exclude_patterns=(),
            )
            sse_res = run_sse_stage2(cfg)
            self.assertGreater(sse_res["report"]["totals"]["blind_docs"], 0)

            # ---------------------------------------------------------------
            # Stage 2b: HE Feature Extraction & Encryption (Alg 2)
            # ---------------------------------------------------------------
            he_out = tmp_path / "he_stage2"
            he_res = run_he_stage2(evidence, pub_path, he_out, dimension=4, bit_width=8)
            self.assertGreater(he_res["encrypted_artifacts"], 0)
            self.assertTrue((he_out / "share" / "Cr_kwt_prime.json").exists())

            # ---------------------------------------------------------------
            # Stage 3: SSE AND Search (3.1) + HE K-Means on Ciphertext (3.2)
            # ---------------------------------------------------------------
            cipher_records = load_json(he_out / "share" / "Cr_kwt_prime.json")["records"]
            encrypted_artifacts = [
                EncryptedArtifact(
                    artifact_id=r["artifact_id"],
                    file_path=f"file_{r['artifact_id'][:8]}",
                    ciphertext_vector=r["Cr_kwt_prime"],
                )
                for r in cipher_records
            ]

            # Run Algorithm 3: K-Means on encrypted feature vectors
            clusters = encrypted_kmeans(encrypted_artifacts, q=2, seed=42)
            self.assertGreaterEqual(len(clusters), 1)

            # ---------------------------------------------------------------
            # Stage 4: Algorithm 4 Decryption + Selective AES Release
            # ---------------------------------------------------------------
            dec_results = decrypt_clusters(
                clusters, encrypted_artifacts, pair.private_key, pair.public_key.d, bit_width=8
            )
            self.assertGreaterEqual(len(dec_results), 1)

            # High suspicion cluster exists
            high_risk = dec_results[0]
            self.assertIn("HIGH SUSPICION", high_risk.risk_level)

            # Stage 4.2: Selective release of high suspicion files
            work = WorkDirs.open(cfg)
            handle_map = load_json(work.client / "handle_map.json")
            # Select doc_ids for release
            first_doc_id = list(handle_map.values())[0]
            released = stage_selective_release(cfg, work, {first_doc_id}, label="selective_test")
            self.assertEqual(len(released), 1)
            self.assertEqual(released[0]["status"], "APPROVED_DECRYPTED")


if __name__ == "__main__":
    unittest.main()
