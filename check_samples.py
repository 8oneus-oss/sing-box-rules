#!/usr/bin/env python3
"""发布前样本检查：用 sing-box rule-set match 验证「该命中的命中、不该命中的不命中」。

任何一条不符合就返回非 0，工作流据此停止发布（客户端继续用上一次发布的版本）。
样本清单见 samples.json；以后发现哪个域名走错出口，往清单里加一行即可。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def match(sing_box: Path, srs: Path, domain: str) -> bool:
    """规则集是否命中该域名。sing-box 命中时输出以 match 开头的行，未命中则无输出。"""
    r = subprocess.run(
        [str(sing_box), "rule-set", "match", "-f", "binary", str(srs), domain],
        capture_output=True,
        text=True,
        timeout=60,
    )
    out = ANSI.sub("", (r.stdout or "") + (r.stderr or ""))
    if r.returncode != 0 or "FATAL" in out:
        raise RuntimeError(f"sing-box 执行失败（{srs.name} / {domain}）：{out.strip()[:200]}")
    return any(line.startswith("match") for line in out.splitlines())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dist", default=str(ROOT / "dist"), help="build.py 的输出目录")
    ap.add_argument("--sing-box", default=str(ROOT / "tools" / "sing-box"))
    ap.add_argument("--samples", default=str(ROOT / "samples.json"))
    args = ap.parse_args()

    dist, sing_box = Path(args.dist), Path(args.sing_box)
    cfg = json.loads(Path(args.samples).read_text(encoding="utf-8"))
    must_hit: Dict[str, List[str]] = cfg.get("must_hit", {})
    must_not_hit: Dict[str, List[str]] = cfg.get("must_not_hit", {})
    miss_all: List[str] = cfg.get("must_miss_everywhere", [])

    failures: List[str] = []
    checked = 0
    missing_reported: set = set()
    exec_failed: set = set()

    def srs_of(name: str) -> Path | None:
        p = dist / f"{name}.srs"
        if not p.is_file():
            if name not in missing_reported:
                missing_reported.add(name)
                failures.append(f"[缺文件] 找不到集合 {name} 的产物：{p}")
            return None
        return p

    def hit(p: Path, d: str) -> bool | None:
        """命中返回 True，未命中 False；sing-box 执行失败（如产物损坏）记为失败并返回 None。"""
        try:
            return match(sing_box, p, d)
        except Exception as exc:  # noqa: BLE001
            if p.name not in exec_failed:  # 同一个文件只报一次
                exec_failed.add(p.name)
                failures.append(f"[执行失败] {p.name}：{exc}")
            return None

    for name, domains in must_hit.items():
        p = srs_of(name)
        if p is None:
            continue
        for d in domains:
            checked += 1
            if hit(p, d) is False:
                failures.append(f"[该命中没命中] {d} 应该在 {name} 里，但没命中")

    for name, domains in must_not_hit.items():
        p = srs_of(name)
        if p is None:
            continue
        for d in domains:
            checked += 1
            if hit(p, d) is True:
                failures.append(f"[不该命中却命中] {d} 不应该在 {name} 里，但命中了")

    if miss_all:
        all_sets = sorted(set(must_hit) | set(must_not_hit))
        for name in all_sets:
            p = dist / f"{name}.srs"
            if not p.is_file():
                continue
            for d in miss_all:
                checked += 1
                if hit(p, d) is True:
                    failures.append(f"[不该命中却命中] {d} 不应该命中任何集合，但命中了 {name}")

    print(f"样本检查：共 {checked} 项，失败 {len(failures)} 项")
    for line in failures:
        print("  ✗", line)
    if failures:
        print("样本检查未通过，已阻止发布；客户端继续使用上一次发布的版本。", file=sys.stderr)
        return 1
    print("样本检查通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
