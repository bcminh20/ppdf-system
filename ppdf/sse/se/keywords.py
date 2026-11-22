"""Doc danh sách từ khoá định dạng Autopsy (keyword_lists / keyword_list / keyword)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .tokens import keyword_gram, slugify


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Keyword:
    text: str
    literal: bool
    whole: bool
    list_name: str
    gram: str = field(default="", compare=False)

    @property
    def token_count(self) -> int:
        return self.gram.count("\x1f") + 1


def build_keyword(text: str, literal: bool, whole: bool, list_name: str, case_sensitive: bool = False) -> Keyword:
    gram, _ = keyword_gram(text, case_sensitive)
    return Keyword(text=text, literal=literal, whole=whole, list_name=list_name, gram=gram)


@dataclass
class KeywordList:
    name: str
    created: str
    modified: str
    source: Path | None
    keywords: list[Keyword] = field(default_factory=list)

    @property
    def max_token_count(self) -> int:
        return max((k.token_count for k in self.keywords), default=1)

    @property
    def uid(self) -> str:
        """Dinh danh duy nhat theo (file XML, ten danh sach) vi hai XML co the trung name."""
        stem = slugify(self.source.stem) if self.source else "xml"
        return f"{stem}__{slugify(self.name)}"


def parse_keyword_xml(path: Path, case_sensitive: bool = False) -> list[KeywordList]:
    root = ET.parse(path).getroot()
    lists: list[KeywordList] = []
    nodes = [root] if root.tag == "keyword_list" else list(root.iter("keyword_list"))
    for node in nodes:
        kw_list = KeywordList(
            name=node.get("name") or path.stem,
            created=node.get("created") or "",
            modified=node.get("modified") or "",
            source=path,
        )
        for kw in node.iter("keyword"):
            text = (kw.text or "")
            if not text.strip():
                continue
            kw_list.keywords.append(
                build_keyword(
                    text=text,
                    literal=_as_bool(kw.get("literal"), True),
                    whole=_as_bool(kw.get("whole"), True),
                    list_name=kw_list.name,
                    case_sensitive=case_sensitive,
                )
            )
        lists.append(kw_list)
    return lists


def load_keyword_lists(paths: list[Path], case_sensitive: bool = False) -> list[KeywordList]:
    out: list[KeywordList] = []
    for path in paths:
        out.extend(parse_keyword_xml(Path(path), case_sensitive))
    return out


def make_custom_keyword_list(
    keywords_str: str,
    name: str = "Custom_Target_Keywords",
    case_sensitive: bool = False,
) -> KeywordList:
    """Tạo KeywordList động từ chuỗi từ khóa phân tách bằng dấu phẩy hoặc chấm phẩy."""
    raw_terms = [t.strip() for t in keywords_str.replace(";", ",").split(",") if t.strip()]
    kws = [
        build_keyword(term, literal=False, whole=False, list_name=name, case_sensitive=case_sensitive)
        for term in raw_terms
    ]
    return KeywordList(
        name=name,
        created="now",
        modified="now",
        source=None,
        keywords=kws,
    )

