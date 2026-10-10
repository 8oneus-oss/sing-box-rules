#!/usr/bin/env python3
"""把 dist 产物整理成按功能分目录的发布树。"""

from __future__ import annotations

import datetime
import json
import pathlib
import shutil
from typing import Any, Dict, List


def publish_path(kind: str, output: str) -> str:
    """相对 rule-set 根的路径。"""
    if kind == "geoip":
        # geoip-cn → geoip/cn.srs
        name = output[6:] if output.startswith("geoip-") else output
        return f"geoip/{name}.srs"
    return f"geosite/{output}.srs"


def prepare_publish_tree(dist: pathlib.Path, out: pathlib.Path) -> Dict[str, Any]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    report: List[Dict[str, Any]] = json.loads(
        (dist / "build-report.json").read_text(encoding="utf-8")
    )
    rulesets: List[Dict[str, Any]] = []

    for r in report:
        kind = r.get("kind") or "geosite"
        output = r["output"]
        rel = publish_path(kind, output)
        src = dist / f"{output}.srs"
        if not src.exists():
            raise FileNotFoundError(src)
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

        # 可选附带 source json，便于人工查看（不进客户端）
        src_json = dist / f"{output}.json"
        if src_json.exists():
            shutil.copy2(src_json, dest.with_suffix(".json"))

        entry = {
            "tag": r["tag"],
            "kind": kind,
            "file": rel,
            "url_path": rel,
            "items": r["items"],
            "upstream_items": r.get("upstream_items"),
            "counts": r.get("counts", {}),
            "discover": r.get("discover"),
            "dns_verify": r.get("dns_verify"),
        }
        rulesets.append(entry)

    index = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "layout": {
            "geosite": "geosite/<name>.srs",
            "geoip": "geoip/<name>.srs",
        },
        "rulesets": rulesets,
    }
    (out / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return index


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parent
    idx = prepare_publish_tree(root / "dist", root / "publish-out")
    print(f"prepared {len(idx['rulesets'])} rulesets")
    for r in idx["rulesets"]:
        print(f"  {r['tag']} → {r['file']}")
