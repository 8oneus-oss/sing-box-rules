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
from typing import Dict, List, Set, Tuple

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


def _norm_apex(x: str) -> str:
    return str(x).strip().lower().rstrip(".")


def promoted_apex(dist: Path, output: str) -> Set[str]:
    """本轮转正条目（build.py 写入 dist/promoted-{output}.json；缺失即为空集）。"""
    p = dist / f"promoted-{output}.json"
    if not p.is_file():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {_norm_apex(x) for x in (data or []) if _norm_apex(x)}


def covered_by_suffix(apex: str, suffixes: Set[str]) -> bool:
    """apex 是否被任一 suffix 覆盖（精确相等或 .后缀匹配，与 build.py 同语义）。"""
    return any(s and (apex == s or apex.endswith("." + s)) for s in suffixes)


def report_bad_entries(
    ver: Dict, human_added: Set[str], promoted: Set[str]
) -> List[Tuple[str, str]]:
    """从构建报告拼出“不得出现在产物中”的条目（v3.1 §8），含两处裁决：

    1. 本轮转正竞态：旧记录达标转正的条目，本轮又被再发现记入 quarantine 名单；
       转正是合法结果，quarantine 备注已过时——仅 quarantine 段排除本轮转正条目。
       reject/pending_review 与转正不可能同轮共存（同一筛查、同 ctx 下筛查命中即丢弃、
       待审永不自动转正），若出现必是真冲突，检查必须继续报错，不排除。
    2. 可信来源优先：主上游 / 官方源 / 种子是绕过验证电池的设计（官方 0 丢失、
       官方无条件 admit、种子人工意图），筛查 verdict 不得否决它们；
       verification["trusted"]（build.py 记录）覆盖的条目从 bad 名单剔除。
       旧报告无 trusted 键时退化为旧行为。
    """
    trusted = ver.get("trusted") or {}
    trusted_domain = {_norm_apex(x) for x in (trusted.get("domain") or [])}
    trusted_suffix = {_norm_apex(x) for x in (trusted.get("domain_suffix") or [])}

    def trusted_covered(apex: str) -> bool:
        return apex in trusted_domain or covered_by_suffix(apex, trusted_suffix)

    bad: List[Tuple[str, str]] = []
    disc = ver.get("discover") or {}
    for sec in ("reject", "quarantine", "pending_review"):
        for item in disc.get(sec, []) or []:
            apex = item["apex"] if isinstance(item, dict) else item
            apex = _norm_apex(apex)
            if not apex or apex in human_added or trusted_covered(apex):
                continue
            if sec == "quarantine" and apex in promoted:
                continue
            bad.append((sec, apex))
    # dry_run 下 supplement 的验证决策只是"假设"（实际仍走旧白名单），不检查；
    # 非 dry_run 下 supplement 的 quarantine/pending_review 确实未并入，必须检查
    if not ver.get("dry_run"):
        supp = ver.get("supplement") or {}
        for sec in ("reject", "quarantine", "pending_review"):
            for apex in supp.get(sec, []) or []:
                apex = _norm_apex(apex)
                if not apex or apex in human_added or trusted_covered(apex):
                    continue
                if sec == "quarantine" and apex in promoted:
                    continue
                bad.append((sec, apex))
    return bad


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
    overlay_must_hit: List[str] = cfg.get("overlay_must_hit", [])

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

    # v3.1 §8：构建报告里的 rejected/quarantined/pending_review 不得出现在任何发布的 .srs 中
    # 例外：overlays/<output>.json 里人工显式 add 的条目（人工 override 优先级高于验证电池，§6），不算违规
    def overlay_added(output: str) -> Set[str]:
        p = ROOT / "overlays" / f"{output}.json"
        if not p.is_file():
            return set()
        try:
            ov = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return set()
        out: Set[str] = set()
        for k in ("domain", "domain_suffix"):
            for x in (ov.get("add") or {}).get(k) or []:
                x = str(x).strip().lower().rstrip(".")
                if x:
                    out.add(x)
        return out

    # 人工 overlay 完整性：overlays/<o>.json 里 add 的每一条，必须出现在产物里。
    # 防止手写清单（银行/券商/支付等）在构建过程中被过滤、折叠或误删而无人察觉。
    for name in overlay_must_hit:
        ov_file = ROOT / "overlays" / f"{name}.json"
        if not ov_file.is_file():
            failures.append(f"[缺 overlay] 找不到 overlays/{name}.json")
            continue
        p = srs_of(name)
        if p is None:
            continue
        for d in sorted(overlay_added(name)):
            checked += 1
            if hit(p, d) is False:
                failures.append(f"[人工条目缺失] {d} 写在 overlays/{name}.json 的 add 里，但产物 {name} 没命中")

    report_path = dist / "build-report.json"
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            report = []
        for r in report:
            name = r.get("output")
            if not name:
                continue
            ver = r.get("verification") or {}
            human_added = overlay_added(name)
            bad = report_bad_entries(ver, human_added, promoted_apex(dist, name))
            p = srs_of(name)
            if p is None or not bad:
                continue
            for sec, apex in bad:
                checked += 1
                if hit(p, apex) is True:
                    failures.append(f"[验证{ {'reject':'拒绝','quarantine':'隔离','pending_review':'待审'}[sec] }项却命中] "
                                    f"{apex} 不应该在 {name} 里，但命中了")

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
