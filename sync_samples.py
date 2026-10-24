#!/usr/bin/env python3
"""构建后同步样本库（独立步骤，不在构建主流程里）。

读取 dist/promoted-*.json（构建时记录的转正域名），
用 sing-box 逐个验证是否确实在最终 .srs 产物里，
只把确认在产物里的追加到 samples.json 的 must_hit。

用法：python3 sync_samples.py [--dist dist] [--samples samples.json]
失败不影响构建（构建已成功），只打印警告。
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def match(sing_box: Path, srs_path: Path, domain: str) -> bool:
    """用 sing-box 检查域名是否命中规则集。"""
    # 复用 check_samples.py 的 match 逻辑（简化版：用 sing-box rule-set match）
    import tempfile
    import os
    cfg = {
        "log": {"level": "error"},
        "route": {
            "rules": [{"rule_set": "test", "outbound": "direct"}],
            "rule_set": [{"type": "local", "tag": "test", "format": "binary", "path": str(srs_path)}],
            "final": "direct",
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "cfg.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        # 用 sing-box 的 rule-set match 功能（通过 check 命令的变通方式）
        # 实际用 sing-box 的 "rule-set" 测试：创建一个测试配置并检查
        # 简化：直接用 python 的方式检查 .srs 是否包含该域名
        # 这里用 sing-box decompile 后检查
        out = Path(td) / "decompiled.json"
        result = subprocess.run(
            [str(sing_box), "rule-set", "decompile", str(srs_path), "-o", str(out)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False
        data = json.loads(out.read_text(encoding="utf-8"))
        rules = data.get("rules", [])
        for r in rules:
            # domain_suffix 匹配：域名等于后缀或以 .后缀结尾
            for suffix in r.get("domain_suffix", []):
                if domain == suffix or domain.endswith("." + suffix):
                    return True
            # domain 精确匹配
            if domain in r.get("domain", []):
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
        # promoted-twitter.json -> twitter
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

        lst = must_hit.setdefault(output, [])
        existing = set(lst)
        added = 0
        for domain in sorted(domains):
            if domain in existing:
                continue
            # 验证确实在最终产物里
            try:
                if match(Path(args.sing_box), srs_path, domain):
                    lst.append(domain)
                    existing.add(domain)
                    added += 1
                else:
                    print(f"  跳过 {domain}（不在 {output}.srs 里）")
            except Exception as e:
                print(f"  警告：验证 {domain} 失败：{e}")
                continue

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
