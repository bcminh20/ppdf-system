"""CLP dieu khien: truy xuat, xay chi muc ma hoa, tim kiem mu disjunctive, doi chieu."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import (
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_TERMS_PER_DOC,
    DEFAULT_MAX_TEXT_BYTES,
    DEFAULT_SOURCES,
    EVIDENCE_DIR,
    PROJECT_DIR,
    Config,
)
from .pipeline import (
    WorkDirs,
    leakage_profile,
    load_docs_from_manifest,
    load_lists,
    run_all,
    stage_build,
    stage_extract,
    stage_release,
    stage_search,
    stage_token,
    stage_verify,
    write_markdown_report,
)
from .store import load_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="se_disjunctive",
        description="Tim kiem mu disjunctive (OR) tren du lieu phong tam bang Searchable Encryption (mKEES).",
    )
    parser.add_argument("command", nargs="?", default="all", choices=["all", "extract", "build", "search", "verify"])
    parser.add_argument("--evidence-dir", type=Path, default=EVIDENCE_DIR, help="Thư mục chứa PC, RM1, RM2 và XML từ khoá")
    parser.add_argument("--work-dir", type=Path, default=PROJECT_DIR / "work", help="Thư mục sản phẩm trung gian")
    parser.add_argument("--sources", nargs="+", default=list(DEFAULT_SOURCES), help="Các nguồn trong kho bàn giao")
    parser.add_argument("--xml", dest="xml", action="append", type=Path, help="File XML từ khoá (lặp lại được); mặc định TuKhoa_*.xml")
    parser.add_argument("--mode", default="disjunctive", choices=["disjunctive", "conjunctive"], help="Phép OR hoặc AND trên bộ từ khoá")
    parser.add_argument("--list", dest="list_name", help="Chỉ chạy một danh sách từ khoá có tên trong XML")
    parser.add_argument("--case-sensitive", action="store_true", help="So khớp phân biệt hoa/thường")
    parser.add_argument("--blind-slots", action="store_true", help="Ẩn nhãn ô trapdoor (server không biết slot nào tương ứng từ khoá nào)")
    parser.add_argument("--content-mode", default="full", choices=["full", "index-only"], help="full: mã hoá cả tệp; index-only: chỉ lập chỉ mục")
    parser.add_argument(
        "--content-policy",
        default="documents",
        choices=["documents", "all", "names"],
        help="documents: bỏ qua nội dung file ảnh/audio/video; all: strings mọi file; names: chỉ ten va duong dan",
    )
    parser.add_argument("--limit", type=int, help="Giới hạn số tệp (chạy thử nhanh)")
    parser.add_argument("--include-slack", action="store_true", help="Gồm cả sidecar *-slack")
    parser.add_argument("--no-default-excludes", action="store_true", help="Không loại các CSV/MD tổng hợp đã có trong kho")
    parser.add_argument("--exclude", action="append", default=[], help="Pattern từ chối thêm (lặp lại được)")
    parser.add_argument("--max-text-bytes", type=int, default=DEFAULT_MAX_TEXT_BYTES, help="Trần độ dài văn bản rút xuất của một tệp")
    parser.add_argument("--max-terms-per-doc", type=int, default=DEFAULT_MAX_TERMS_PER_DOC, help="Trần số n-gram phân biệt được lập chỉ mục cho một tệp")
    parser.add_argument("--master-key", type=Path, help="Tệp khoá master 32 byte (mặc định work/client/master.key)")
    parser.add_argument("--report-label", default="bao_cao_tim_kiem_mu", help="Tên tệp báo cáo MD")
    return parser


def make_config(args: argparse.Namespace) -> Config:
    return Config(
        evidence_dir=args.evidence_dir,
        work_dir=args.work_dir,
        sources=tuple(args.sources),
        keyword_files=tuple(args.xml or ()),
        mode=args.mode,
        master_key=args.master_key,
        content_mode=args.content_mode,
        content_policy=args.content_policy,
        limit_docs=args.limit,
        use_default_excludes=not args.no_default_excludes,
        exclude_patterns=tuple(list(DEFAULT_EXCLUDES) + args.exclude),
        skip_slack=not args.include_slack,
        case_sensitive=args.case_sensitive,
        blind_slots=args.blind_slots,
        max_text_bytes=args.max_text_bytes,
        max_terms_per_doc=args.max_terms_per_doc,
        report_label=args.report_label,
    )


def select_lists(cfg: Config, list_name: str | None):
    lists = load_lists(cfg)
    if not list_name:
        return lists
    matched = [kw_list for kw_list in lists if kw_list.name == list_name or slug_match(kw_list.name, list_name)]
    if not matched:
        available = ", ".join(kw_list.name for kw_list in lists)
        raise SystemExit(f"Không có danh sách từ khoá '{list_name}'. Các danh sách: {available}")
    return matched


def slug_match(name: str, wanted: str) -> bool:
    from .tokens import slugify

    return slugify(name) == slugify(wanted)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = make_config(args)
    work = WorkDirs.open(cfg)
    command = args.command

    if command == "all":
        run_all(cfg)
        return 0
    if command == "extract":
        stage_extract(cfg, work)
        return 0
    if command == "build":
        docs = load_docs_from_manifest(work)
        stage_build(cfg, work, docs, select_lists(cfg, args.list_name))
        return 0
    if command == "search":
        docs = load_docs_from_manifest(work)
        for kw_list in select_lists(cfg, args.list_name):
            token_path, expectation_path = stage_token(cfg, work, kw_list)
            result = stage_search(work, token_path)
            stage_release(cfg, work, result, load_json(expectation_path))
        return 0
    if command == "verify":
        docs = load_docs_from_manifest(work)
        lists = select_lists(cfg, args.list_name)
        report = stage_verify(cfg, work, docs, lists)
        leak = leakage_profile(cfg, work, lists)
        params = load_json(work.server / "index.json")["params"]
        write_markdown_report(cfg, work, params, report, leak)
        return 0
    print(f"Lenh khong ho tro: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
