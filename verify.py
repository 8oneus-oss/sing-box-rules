#!/usr/bin/env python3
"""验证电池：新域名候选的自动验证（实现方案 v3.1 §2）。

决策表（按顺序）：
  1. 仿冒筛查命中            → reject
  2. （跨集合冲突 / 共享黑名单由调用方在此前处理）
  3. 官方源命中              → admit（唯一无条件放行）
  4. DNS 全挂                → quarantine（consecutive_dead+1）
  5. 品牌相关但无法验证      → pending_review（永不自动放行）
  6. 其余                    → quarantine（14 天时间验证）

无外部依赖：不需要 ASN / RDAP / TLS。
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

from coverage import covered_by_suffix, normalize_host
from verify_dns import resolves


def _levenshtein(a: str, b: str, cap: int = 2) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def impersonation_screen(
    apex: str,
    brand: str,
    known_slds: set,
    keywords: tuple = (),
    max_distance: int = 2,
    sub_brands: tuple = (),
) -> Optional[str]:
    """仿冒筛查。命中返回拒因，无问题返回 None。

    实测（50 标注域名）：5/5 钓鱼拦截，对 ground truth 0 误杀。
    brand 取 seeds[0] 的 SLD；brand 为空时无法判断，返回 None。
    sub_brands: 子品牌（如 Apple 的 beats/itunes），同样受筛查保护。
    另检测无分隔符的店铺拼接（如 2013cheapbeatsbydre.com）。
    """
    a = normalize_host(apex)
    if not a or "." not in a:
        return "格式异常"
    if not brand:
        return None
    brand = brand.lower()
    if "--" in a or "xn--" in a:
        return "双连字符/IDN"
    # 主品牌 + 子品牌一起查
    all_brands = [brand] + [b.lower() for b in (sub_brands or ())]
    if keywords:
        kw = "|".join(re.escape(k) for k in keywords)
        for b in all_brands:
            if re.search(rf"{re.escape(b)}[-_]({kw})", a) or re.search(
                rf"({kw})[-_]{re.escape(b)}", a
            ):
                return "品牌+敏感词"
    # 店铺拼接：子品牌 + 商业词无分隔符拼接（如 2013cheapbeatsbydre.com）
    # 主品牌不查此项（避免误伤官方域名，官方域名由 official 放行）
    shop_words = (
        "cheap|shop|store|online|sale|outlet|discount|buy|deals|"
        "wholesale|replica|clearance|blackfriday|cybermonday|"
        # 多语言"礼物/天数"（假货店常用：12diasderegalosdeitunes）
        "regalo|presente|cadeau|dias|jours|gift"
    )
    sld = a.split(".")[0]
    for b in [x for x in all_brands if x != brand]:
        if b in sld:
            # 商业词拼接，或年份+子品牌（如 2013beats）
            if re.search(shop_words, sld, re.I) or re.search(r"19\d{2}|20\d{2}", sld):
                # 排除主品牌官方子域名（如 beats.apple.com）
                if not a.endswith("." + brand + ".com") and brand not in sld:
                    return "仿冒店铺拼接"
    if sld != brand and len(sld) >= 3 and _levenshtein(sld, brand, max_distance) <= max_distance:
        return "疑似 typosquat"
    return None


def needs_human_review(
    apex: str, brand: str, known_slds: set, known_tlds: set
) -> bool:
    """品牌相关但归属无法自动验证 → True（永不自动放行，进待审队列）。

    - SLD 含品牌但 ≠ 品牌（如 binance-bh.com）
    - 同 SLD 但 TLD 不在种子白名单（如 binance.cm）
    归属验证技术上无完美解（WHOIS 脱敏、DV 证书不记名），默认拒绝是最便宜的"完美"。
    """
    a = normalize_host(apex)
    parts = a.split(".")
    if len(parts) < 2:
        return True
    sld, tld = parts[0], parts[-1]
    if not brand:
        return False
    brand = brand.lower()
    if sld == brand:
        return tld not in {t.lower() for t in known_tlds}
    return brand in sld


def dns_alive(host: str, timeout: float = 4.0) -> bool:
    """DNS 存活。复用 verify_dns 的并发安全实现（单点调用）。"""
    return resolves(host, timeout=timeout)


def verify_candidate(apex: str, ctx: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """对单个候选 apex 做验证决策。

    ctx: {
        "brand": str, "known_slds": set, "known_tlds": set,
        "keywords": tuple, "max_distance": int,
        "official": set,            # 官方源 apex（命中则直接 admit）
        "check_dns": bool,          # False 时跳过 DNS（单元测试用）
    }
    返回 (decision, info)：
      decision ∈ {"admit", "quarantine", "pending_review", "reject"}
    """
    a = normalize_host(apex)
    brand = ctx.get("brand") or ""
    known_slds = ctx.get("known_slds") or set()
    known_tlds = ctx.get("known_tlds") or set()
    keywords = tuple(ctx.get("keywords") or ())
    max_distance = int(ctx.get("max_distance", 2))
    sub_brands = tuple(ctx.get("sub_brands") or ())
    official = ctx.get("official") or set()

    rej = impersonation_screen(a, brand, known_slds, keywords, max_distance, sub_brands)
    if rej:
        return "reject", {"reason": rej}
    if a in official or covered_by_suffix(a, official):
        return "admit", {"reason": "official", "signals": ["official"]}
    if ctx.get("check_dns", True) and not dns_alive(a):
        return "quarantine", {"reason": "dns_dead", "dead": True, "signals": []}
    if needs_human_review(a, brand, known_slds, known_tlds):
        return "pending_review", {"reason": "brand_unverifiable", "signals": ["dns_ok"]}
    return "quarantine", {"reason": "time_verify", "signals": ["dns_ok"]}
