#!/usr/bin/env python3
"""构建后同步样本库（独立步骤，不在构建主流程里）。

读取 dist/promoted-*.json（构建时记录的转正域名），
每个 .srs 只反编译一次，批量验证域名是否确实在最终产物里，
只把确认在产物里的追加到 samples.json 的 must_hit。

用法：python3 sync_samples.py [--dist dist] [--samples samples.json]
失败不影响构建（构建已成功），只打印警告。
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def decompile_srs(sing_box: str, srs_path: Path) -> dict:
    """反编译一次 .srs，返回规则数据。"""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "decompiled.json"
        result = subprocess.run(
            [sing_box, "rule-set", "decompile", str(srs_path), "-o", str(out)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"decompile 失败 {srs_path.name}: {result.stderr[:200]}")
        return json.loads(out.read_text(encoding="utf-8"))


def domain_in_rules(domain: str, rules: list) -> bool:
    """检查域名是否命中规则（domain 精确或 domain_suffix 后缀）。"""
    for r in rules:
        if domain in r.get("domain", []):
            return True
        for suffix in r.get("domain_suffix", []):
            if domain == suffix or domain.endswith("." + suffix):
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default=str(ROOT / "dist"))
    ap.add_argument("--samples", default=str(ROOT / "samples.json"))
    ap.add_argument("--sing-box", default="sing-box")
    args = ap.parse_args()

    dist = Path(args.dist)
    samples_path = Path(args.samples)

    if not samples_path.exists():
        print(f"samples.json 不存在，跳过：{samples_path}")
        return 0

    samples = json.loads(samples_path.read_text(encoding="utf-8"))
    must_hit = samples.setdefault("must_hit", {})

    total_added = 0
    for promoted_file in sorted(dist.glob("promoted-*.json")):
        output = promoted_file.stem[len("promoted-"):]
        try:
            domains = json.loads(promoted_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  警告：读 {promoted_file.name} 失败：{e}")
            continue

        srs_path = dist / f"{output}.srs"
        if not srs_path.exists():
            print(f"  警告：{output}.srs 不存在，跳过")
            continue

        # 每个 .srs 只反编译一次
        try:
            data = decompile_srs(args.sing_box, srs_path)
            rules = data.get("rules", [])
        except Exception as e:
            print(f"  警告：反编译 {output}.srs 失败：{e}")
            continue

        lst = must_hit.setdefault(output, [])
        existing = set(lst)
        added = 0
        for domain in sorted(domains):
            if domain in existing:
                continue
            if domain_in_rules(domain, rules):
                lst.append(domain)
                existing.add(domain)
                added += 1
            else:
                print(f"  跳过 {domain}（不在 {output}.srs 里）")

        if len(lst) > 200:
            lst[:] = lst[-200:]
        if added:
            print(f"  样本库追加 {output}: +{added} 条")
            total_added += added

    if total_added:
        samples_path.write_text(json.dumps(samples, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"样本同步完成：共 +{total_added} 条")
    else:
        print("样本同步完成：无新增")
    return 0


if __name__ == "__main__":
    sys.exit(main())
