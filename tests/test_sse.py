import tempfile
import unittest
from pathlib import Path

from ppdf.sse.se.config import Config
from ppdf.sse.se.pipeline import WorkDirs, run_all
from ppdf.sse.se.store import load_json
from ppdf.sse.se.tokens import doc_grams, keyword_gram, phrase_to_regex, tokenize


def make_corpus(root: Path) -> None:
    (root / "RM1").mkdir(parents=True, exist_ok=True)
    (root / "PC").mkdir(parents=True, exist_ok=True)
    (root / "RM1" / "proposal.txt").write_text("This is the Secret Project Data proposal.\n", encoding="utf-8")
    (root / "RM1" / "notes.txt").write_text("secret_project folder and nothing else here.\n", encoding="utf-8")
    (root / "PC" / "drive.log").write_text("uploading happy_holiday.jpg to drive.google.com\n", encoding="utf-8")
    (root / "PC" / "spam.txt").write_text("secret_projectx is not a whole word hit\n", encoding="utf-8")
    (root / "TuKhoa_Test.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<keyword_lists><keyword_list name="TuKhoa_Test">'
        "<keyword literal=\"true\" whole=\"true\">Secret Project Data</keyword>"
        "<keyword literal=\"true\" whole=\"true\">secret_project</keyword>"
        "<keyword literal=\"true\" whole=\"true\">drive.google.com</keyword>"
        "<keyword literal=\"true\" whole=\"true\">happy_holiday.jpg</keyword>"
        "</keyword_list></keyword_lists>\n",
        encoding="utf-8",
    )


class TokenTests(unittest.TestCase):
    def test_phrase_keeps_separators(self) -> None:
        self.assertEqual(tokenize("drive.google.com"), ["drive", ".", "google", ".", "com"])
        self.assertEqual(tokenize("a  b"), ["a", " ", "b"])

    def test_whole_word_boundary(self) -> None:
        self.assertIsNone(phrase_to_regex("secret_project", True, True, False).search("secret_projectx"))
        self.assertEqual(len(phrase_to_regex("secret_project", True, True, False).findall("[secret_project]_x")), 1)

    def test_gram_contains_keyword_phrase(self) -> None:
        gram, _ = keyword_gram("Secret Project Data")
        grams, truncated = doc_grams(tokenize("the Secret Project Data here"), depth=7, cap=10_000)
        self.assertIn(gram, grams)
        self.assertFalse(truncated)


class SchemeTests(unittest.TestCase):
    def setUp(self) -> None:
        from ppdf.sse.se.peke import PEKE, Trapdoor, record_is_hit, search_record

        self.peke = PEKE(b"\x00" * 32)
        self.peke_other = PEKE(b"\x01" * 32)
        self.handle = self.peke.file_handle("doc-1")
        self.grams = ["secret", "secret project", "drive . google"]
        self.tags = [self.peke.term_tag(self.handle, gram) for gram in self.grams]
        self.search_record = search_record
        self.record_is_hit = record_is_hit
        self.Trapdoor = Trapdoor

    def _trapdoor(self, grams, mode="disjunctive", peke=None):
        peke = peke or self.peke
        return self.Trapdoor(slots=tuple((g, peke.trapdoor_value(g)) for g in grams), mode=mode)

    def test_disjunctive_hits(self) -> None:
        trapdoor = self._trapdoor(["secret", "khong co trong tai lieu"])
        self.assertEqual(self.search_record(self.handle, self.tags, trapdoor), ["secret"])
        self.assertTrue(self.record_is_hit(["secret"], trapdoor))

    def test_conjunctive_requires_all(self) -> None:
        trapdoor = self._trapdoor(["secret", "drive . google"], mode="conjunctive")
        matched = self.search_record(self.handle, self.tags, trapdoor)
        self.assertEqual(sorted(matched), ["drive . google", "secret"])
        self.assertTrue(self.record_is_hit(matched, trapdoor))
        partial = self._trapdoor(["secret", "absent"], mode="conjunctive")
        self.assertFalse(self.record_is_hit(self.search_record(self.handle, self.tags, partial), partial))

    def test_wrong_key_does_not_match(self) -> None:
        trapdoor = self._trapdoor(["secret"], peke=self.peke_other)
        self.assertEqual(self.search_record(self.handle, self.tags, trapdoor), [])

    def test_encryption_round_trip(self) -> None:
        nonce, ciphertext = self.peke.encrypt_blob("doc-1", b"evidence", self.handle)
        self.assertNotIn(b"evidence", ciphertext)
        self.assertEqual(self.peke.decrypt_blob("doc-1", nonce, ciphertext, self.handle), b"evidence")


class PipelineTests(unittest.TestCase):
    def test_end_to_end_matches_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            evidence.mkdir()
            make_corpus(evidence)
            cfg = Config(
                evidence_dir=evidence,
                work_dir=Path(tmp) / "work",
                sources=("RM1", "PC"),
                keyword_files=(evidence / "TuKhoa_Test.xml",),
                exclude_patterns=(),
                use_default_excludes=False,
                report_label="test_report",
            )
            output = run_all(cfg)
            totals = output["report"]["totals"]
            self.assertEqual(totals["false_positive"], 0)
            self.assertEqual(totals["false_negative"], 0)
            self.assertEqual(totals["blind_docs"], 3)


if __name__ == "__main__":
    unittest.main()
