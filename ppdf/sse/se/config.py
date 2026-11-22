"""Tham so chay mac dinh cho bo truy xuat + tim kiem mu."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
# PROJECT_DIR is the ppdf-hybrid root (4 levels up: se → sse → ppdf → ppdf-hybrid)
PROJECT_DIR = PACKAGE_DIR.parent.parent.parent
EVIDENCE_DIR = PROJECT_DIR.parent

DEFAULT_SOURCES = ("PC", "RM1", "RM2")
DEFAULT_MAX_TEXT_BYTES = 32_000_000
DEFAULT_MAX_TERMS_PER_DOC = 5_000_000
DEFAULT_EXCLUDES = (
    "*/KeywordHits/*",
    "*/hits_*.csv",
    "*/doi_duoi_log.csv",
    "*/BANG_BAN_GIAO_*.md",
    "*/KET_QUA_GOOGLE_DRIVE.md",
    "*/MANIFEST_SHA256.json",
)


@dataclass
class Config:
    evidence_dir: Path = EVIDENCE_DIR
    work_dir: Path = PROJECT_DIR / "work"
    sources: tuple[str, ...] = DEFAULT_SOURCES
    keyword_files: tuple[Path, ...] = ()
    mode: str = "disjunctive"
    master_key: Path | None = None
    content_mode: str = "full"
    content_policy: str = "documents"
    limit_docs: int | None = None
    use_default_excludes: bool = True
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES
    skip_slack: bool = True
    case_sensitive: bool = False
    blind_slots: bool = False
    max_query_tokens: int | None = None
    max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES
    max_terms_per_doc: int = DEFAULT_MAX_TERMS_PER_DOC
    max_scan_bytes: int = 64 * 1024 * 1024
    report_label: str = "bao_cao"

    def corpus_roots(self) -> list[Path]:
        return [self.evidence_dir / s for s in self.sources]

    def resolved_keyword_files(self) -> list[Path]:
        if self.keyword_files:
            return [Path(p) for p in self.keyword_files]
        return sorted(self.evidence_dir.glob("TuKhoa_*.xml"))

    def active_excludes(self) -> list[str]:
        return list(self.exclude_patterns) if self.use_default_excludes else []
