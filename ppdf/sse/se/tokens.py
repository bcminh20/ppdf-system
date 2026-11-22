"""Token hoá và sinh n-gram phục vụ khớp từ khoá exact-match (literal + whole word)."""

from __future__ import annotations

import re
from typing import Iterator

_TOK = re.compile(r"\w+|\s+|.", re.UNICODE | re.DOTALL)
SEP = "\x1f"
SPACE_TOKEN = " "


def slugify(name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in name).strip("_") or "list"


def normalize(text: str, case_sensitive: bool = False) -> str:
    return text if case_sensitive else text.casefold()


def tokenize(text: str, case_sensitive: bool = False) -> list[str]:
    """Chuỗi token: từ (dãy \\w+) giữ nguyên, khoảng trắng gộp thành ' ', mỗi ký tự khác là một token.

    Cách tách này bảo đảm whole-word: token là dãy ký tự từ tối đại, nên không khớp một phần từ.
    """
    tokens: list[str] = []
    for match in _TOK.finditer(text):
        raw = match.group(0)
        if raw.isspace():
            tokens.append(SPACE_TOKEN)
        else:
            tokens.append(raw if case_sensitive else raw.casefold())
    return tokens


def grams_from_tokens(tokens: list[str], depth: int) -> Iterator[str]:
    n = len(tokens)
    for start in range(n):
        upper = min(n, start + depth)
        acc: list[str] = []
        for end in range(start, upper):
            acc.append(tokens[end])
            yield SEP.join(acc)


def doc_grams(tokens: list[str], depth: int, cap: int) -> tuple[set[str], bool]:
    """Tap n-gram cua tai lieu, gioi han `cap` term phan biet va bao hieu bi cat."""
    grams: set[str] = set()
    for gram in grams_from_tokens(tokens, depth):
        grams.add(gram)
        if len(grams) >= cap:
            return grams, True
    return grams, False


def keyword_gram(keyword: str, case_sensitive: bool = False) -> tuple[str, list[str]]:
    tokens = tokenize(keyword, case_sensitive)
    if not tokens:
        raise ValueError(f"Từ khoá rỗng: {keyword!r}")
    return SEP.join(tokens), tokens


def phrase_to_regex(keyword: str, whole: bool, literal: bool, case_sensitive: bool) -> re.Pattern[str]:
    """Máy khớp độc lập cho đối chứng: tìm chuỗi cào bằng regex trên text rút xuất."""
    pattern = re.escape(keyword) if literal else keyword
    if whole:
        pattern = rf"(?<!\w){pattern}(?!\w)"
    flags = 0 if case_sensitive else re.IGNORECASE | re.UNICODE
    return re.compile(pattern, flags)


def count_matches(text: str, keyword: str, whole: bool, literal: bool, case_sensitive: bool) -> int:
    return len(phrase_to_regex(keyword, whole, literal, case_sensitive).findall(text))
