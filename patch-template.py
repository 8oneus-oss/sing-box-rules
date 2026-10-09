#!/usr/bin/env python3
"""按 publish.json 把模版里的远程规则集 URL 改成自建 GitHub raw 地址（分目录）。"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLISH = json.loads((ROOT / "publish.json").read_text(encoding="utf-8"))
TEMPLATE = ROOT.parent / "sing-box_1.14.2_模板.json"

# 模版 tag → rule-set 分支相对路径（分功能目录）
TAG_TO_PATH = {
    "YouTube": "geosite/youtube.srs",
    "谷歌美国": "geosite/google.srs",
    "AI服务": "geosite/ai.srs",
    "Meta": "geosite/meta.srs",
    "Apple": "geosite/apple.srs",
    "GitHub": "geosite/github.srs",
    "Microsoft": "geosite/microsoft.srs",
    "Twitter": "geosite/twitter.srs",
    "Binance": "geosite/binance.srs",
    "Bybit": "geosite/bybit.srs",
    "OKX": "geosite/okx.srs",
    "Gate.io": "geosite/gateio.srs",
    "中国大陆域名": "geosite/geolocation-cn.srs",
    "中国大陆IP": "geoip/cn.srs",
}


def main() -> int:
    owner = PUBLISH["github_owner"]
    repo = PUBLISH["github_repo"]
    branch = PUBLISH.get("branch", "rule-set")
    interval = PUBLISH.get("update_interval", "1d")
    if owner.startswith("YOUR_"):
        print(
            "先编辑 ruleset/publish.json，把 github_owner 改成你的 GitHub 用户名",
            file=sys.stderr,
        )
        return 1

    base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
    text = TEMPLATE.read_text(encoding="utf-8")

    for tag, rel in TAG_TO_PATH.items():
        url = f"{base}/{rel}"
        pattern = rf'("tag":\s*"{re.escape(tag)}"[\s\S]*?"url":\s*")[^"]*(")'
        new_text, n = re.subn(pattern, rf"\g<1>{url}\g<2>", text, count=1)
        if n != 1:
            print(f"警告: 未替换到 tag={tag}", file=sys.stderr)
        else:
            text = new_text
            print(f"  {tag} → {url}")

        pattern_iv = (
            rf'("tag":\s*"{re.escape(tag)}"[\s\S]*?"update_interval":\s*")[^"]*(")'
        )
        text, _ = re.subn(pattern_iv, rf"\g<1>{interval}\g<2>", text, count=1)

    TEMPLATE.write_text(text, encoding="utf-8")
    print(f"\n已更新 {TEMPLATE.name}")
    print(f"raw_base = {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
