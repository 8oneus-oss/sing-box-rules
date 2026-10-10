#!/usr/bin/env python3
"""规则覆盖去重：去掉已被 domain_suffix 覆盖的冗余 domain / 更长 suffix。"""

from __future__ import annotations

from typing import Dict, Iterable, Set, Tuple


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".").lstrip(".")


def covered_by_suffix(host: str, suffixes: Iterable[str]) -> bool:
    h = normalize_host(host)
    if not h:
        return False
    for raw in suffixes:
        s = normalize_host(raw)
        if not s:
            continue
        if h == s or h.endswith("." + s):
            return True
    return False


def collapse_suffixes(suffixes: Iterable[str]) -> Set[str]:
    """保留更宽的 suffix，去掉已被更短 suffix 覆盖的更长项。"""
    items = sorted({normalize_host(s) for s in suffixes if s and s.strip()}, key=lambda x: (x.count("."), len(x), x))
    kept: Set[str] = set()
    for s in items:
        if covered_by_suffix(s, kept):
            continue
        kept.add(s)
    return kept


def guess_apex(host: str) -> str:
    """粗略取 apex（最后两段）。不处理复杂公共后缀表，只求减少噪音。"""
    h = normalize_host(host)
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    return ".".join(parts[-2:])


def collapse_bucket(bucket: Dict[str, Set[str]]) -> Tuple[Dict[str, Set[str]], Dict[str, int]]:
    """
    返回 (去重后 bucket, 统计).
    - domain_suffix: 折叠被更宽规则覆盖的长后缀
    - domain: 删除已被任一 domain_suffix 覆盖的精确域名
    """
    before_domain = len(bucket.get("domain", set()))
    before_suffix = len(bucket.get("domain_suffix", set()))

    suffixes = collapse_suffixes(bucket.get("domain_suffix", set()))
    domains: Set[str] = set()
    for d in bucket.get("domain", set()):
        host = normalize_host(d)
        if not host:
            continue
        if covered_by_suffix(host, suffixes):
            continue
        domains.add(host)

    out = {
        "domain": domains,
        "domain_suffix": suffixes,
        "domain_keyword": set(bucket.get("domain_keyword", set())),
        "domain_regex": set(bucket.get("domain_regex", set())),
        "ip_cidr": set(bucket.get("ip_cidr", set())),
    }
    stats = {
        "domain_before": before_domain,
        "domain_after": len(domains),
        "domain_dropped": before_domain - len(domains),
        "suffix_before": before_suffix,
        "suffix_after": len(suffixes),
        "suffix_dropped": before_suffix - len(suffixes),
    }
    return out, stats
