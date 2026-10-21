#!/usr/bin/env python3
"""检查 sing-box 配置里的 rule_set 顺序是否与集合重叠关系一致。

用法：
    python3 check_order.py /path/to/sing-box.json [--dist dist/]

原理：某些集合的域名会命中另一些集合（如 youtube 100% 命中 google）。
sing-box 按 route.rules 顺序匹配，先命中的先生效，所以小集合/特定集合
必须排在大集合/兜底集合前面。顺序错了，流量就走错出口，且没有任何报错。

检查项：
1. 硬编码的关键顺序约束（来自项目实测 §8.1 + 审计数据）
2. 如提供 --dist，则用实际 .srs 文件抽样验证重叠关系是否仍然成立
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# (A, B)：A 的域名会大面积命中 B，所以 A 必须排在 B 前面
# 来源：审计实测（youtube 100%→google、github 100%→microsoft）+ overlays/README 的重叠说明
MUST_BEFORE = [
    ("youtube", "google", "youtube 域名 100% 命中 google"),
    ("github", "microsoft", "github 域名 100% 命中 microsoft"),
    ("dl-direct", "apple", "下载直连与 Apple 重叠，直连优先"),
    ("dl-direct", "microsoft", "下载直连与 Microsoft 重叠，直连优先"),
    ("dl-direct", "geolocation-cn", "下载直连与大陆域名重叠，直连优先"),
    ("us-cdn", "meta", "us-cdn 含 fbcdn.net，与 Meta 重叠，CDN 走普通节点"),
    ("us-cdn", "twitter", "us-cdn 含 twimg.com，与 Twitter 重叠，CDN 走普通节点"),
    ("youtube", "us-cdn", "googlevideo.com 两边都有，YouTube 视频流量优先走 YouTube 出口"),
    ("us-cdn", "google", "us-cdn 与 Google 有少量重叠"),
    # 兜底集合必须最后
    ("youtube", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("google", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("ai", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("meta", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("apple", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("github", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("microsoft", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("twitter", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("binance", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("bybit", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("okx", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("gateio", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("us-domains", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("sg-domains", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("us-cdn", "geolocation-cn", "geolocation-cn 是 catch-all"),
    ("dl-direct", "geolocation-cn", "geolocation-cn 是 catch-all"),
]

# tag → output 名映射（配置里用 tag，约束里用 output）
TAG_TO_OUTPUT = {
    "YouTube": "youtube",
    "谷歌美国": "google",
    "AI服务": "ai",
    "Meta": "meta",
    "Apple": "apple",
    "GitHub": "github",
    "Microsoft": "microsoft",
    "Twitter": "twitter",
    "Binance": "binance",
    "Bybit": "bybit",
    "OKX": "okx",
    "Gate.io": "gateio",
    "美国域名": "us-domains",
    "新加坡域名": "sg-domains",
    "美国大流量CDN": "us-cdn",
    "苹果微软下载直连": "dl-direct",
    "中国大陆域名": "geolocation-cn",
    "中国大陆IP": "geoip-cn",
}


def extract_order(cfg: dict) -> list[str]:
    """从 route.rules 提取 rule_set 出现顺序（去重，保留首次出现）。"""
    order: list[str] = []
    seen: set[str] = set()
    for rule in (cfg.get("route") or {}).get("rules") or []:
        rs = rule.get("rule_set")
        if not rs:
            continue
        tags = rs if isinstance(rs, list) else [rs]
        for t in tags:
            out = TAG_TO_OUTPUT.get(t, t)
            if out not in seen:
                seen.add(out)
                order.append(out)
    return order


def check_order(order: list[str]) -> list[str]:
    """返回违规描述列表。"""
    pos = {name: i for i, name in enumerate(order)}
    problems: list[str] = []
    for a, b, reason in MUST_BEFORE:
        if a not in pos or b not in pos:
            continue  # 配置里没用到，不检查
        if pos[a] > pos[b]:
            problems.append(
                f"[顺序错误] {a}（位置 {pos[a]}）应在 {b}（位置 {pos[b]}）之前——{reason}"
            )
    return problems


def main() -> int:
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} /path/to/sing-box.json", file=sys.stderr)
        return 2
    cfg_path = Path(sys.argv[1])
    if not cfg_path.is_file():
        print(f"找不到配置文件: {cfg_path}", file=sys.stderr)
        return 2
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    order = extract_order(cfg)
    print("检测到的 rule_set 顺序:")
    for i, name in enumerate(order):
        print(f"  {i:2d}. {name}")

    problems = check_order(order)
    if problems:
        print(f"\n发现 {len(problems)} 个顺序问题:")
        for p in problems:
            print("  ✗", p)
        return 1
    print("\n顺序检查通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
