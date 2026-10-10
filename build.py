#!/usr/bin/env python3
"""规则集流水线：合并上游 → 自动发现 → 自动验证 → 叠加覆盖 → 过滤 → 生成 → 加载校验。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from coverage import collapse_bucket, covered_by_suffix, normalize_host
from discover import discover_for_output
from verify_dns import summarize, verify_hosts

ROOT = Path(__file__).resolve().parent
CACHE_DIR = ROOT / "cache"
DIST_DIR = ROOT / "dist"
OVERLAY_DIR = ROOT / "overlays"
SING_BOX = ROOT / "tools" / "sing-box"

DOMAIN_KEYS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
IP_KEYS = ("ip_cidr",)
LIST_KEYS = DOMAIN_KEYS + IP_KEYS

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$"
)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]


def empty_bucket() -> Dict[str, Set[str]]:
    return {k: set() for k in LIST_KEYS}


def ingest_rules(rules: Iterable[Dict[str, Any]], bucket: Dict[str, Set[str]]) -> None:
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for key in LIST_KEYS:
            if key in rule:
                for item in ensure_list(rule[key]):
                    bucket[key].add(item)


def fetch_bytes(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ruleset-pipeline/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_upstream(
    url: str,
    fmt: str,
    sing_box: Path,
    cache_dir: Path,
) -> Dict[str, Set[str]]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
    cache_path = cache_dir / safe
    if not cache_path.exists():
        print(f"  fetch {url}")
        data = fetch_bytes(url)
        cache_path.write_bytes(data)
    else:
        print(f"  cache {cache_path.name[:60]}...")

    bucket = empty_bucket()
    if fmt == "source":
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        ingest_rules(payload.get("rules") or [], bucket)
        return bucket

    if fmt == "binary":
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.srs"
            out = Path(td) / "out.json"
            shutil.copyfile(cache_path, src)
            run_sing_box(sing_box, ["rule-set", "decompile", str(src), "-o", str(out)])
            payload = json.loads(out.read_text(encoding="utf-8"))
            ingest_rules(payload.get("rules") or [], bucket)
        return bucket

    raise ValueError(f"未知上游 format: {fmt}")


def run_sing_box(sing_box: Path, args: List[str]) -> subprocess.CompletedProcess:
    if not sing_box.is_file():
        raise FileNotFoundError(f"找不到 sing-box: {sing_box}")
    cmd = [str(sing_box), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"sing-box 失败 ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def merge_buckets(buckets: Iterable[Dict[str, Set[str]]]) -> Dict[str, Set[str]]:
    out = empty_bucket()
    for b in buckets:
        for key in LIST_KEYS:
            out[key] |= b[key]
    return out


def apply_overlay(bucket: Dict[str, Set[str]], overlay: Dict[str, Any]) -> Set[str]:
    """应用 overlay，返回新增的 domain/domain_suffix（供 DNS 验证）。"""
    add = overlay.get("add") or {}
    remove = overlay.get("remove") or {}
    newly: Set[str] = set()
    for key in LIST_KEYS:
        for item in ensure_list(add.get(key)):
            before = item in bucket[key]
            bucket[key].add(item)
            if key in ("domain", "domain_suffix") and not before:
                newly.add(item.strip().lower().rstrip("."))
        for item in ensure_list(remove.get(key)):
            bucket[key].discard(item)
    return newly


def normalize_domain(value: str, strip_dot: bool) -> str:
    v = value.strip().lower()
    if strip_dot:
        v = v.lstrip(".")
    return v


def is_valid_domain_like(value: str, min_len: int) -> bool:
    if len(value) < min_len:
        return False
    if "*" in value or value.startswith("^") or "\\" in value:
        return True
    return bool(DOMAIN_RE.match(value))


def is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def apply_filters(bucket: Dict[str, Set[str]], filters: Dict[str, Any]) -> Dict[str, Set[str]]:
    lower = bool(filters.get("normalize_lower", True))
    strip_dot = bool(filters.get("strip_leading_dot", True))
    drop_empty = bool(filters.get("drop_empty", True))
    min_len = int(filters.get("min_domain_len", 2))

    exclude = {
        "domain": set(),
        "domain_suffix": set(),
        "domain_keyword": set(),
        "domain_regex": set(),
    }
    for key in DOMAIN_KEYS:
        for x in ensure_list(filters.get(f"exclude_{key}")):
            if key in ("domain", "domain_suffix"):
                exclude[key].add(normalize_domain(x, strip_dot) if lower else x.strip())
            else:
                exclude[key].add(x.strip().lower() if lower and key == "domain_keyword" else x.strip())

    out = empty_bucket()
    for raw in bucket["domain"]:
        v = normalize_domain(raw, strip_dot) if lower else raw.strip()
        if drop_empty and not v:
            continue
        if v in exclude["domain"] or not is_valid_domain_like(v, min_len):
            continue
        out["domain"].add(v)

    for raw in bucket["domain_suffix"]:
        v = normalize_domain(raw, strip_dot) if lower else raw.strip()
        if drop_empty and not v:
            continue
        if v in exclude["domain_suffix"] or not is_valid_domain_like(v, min_len):
            continue
        out["domain_suffix"].add(v)

    for raw in bucket["domain_keyword"]:
        v = raw.strip().lower() if lower else raw.strip()
        if drop_empty and not v:
            continue
        if v in exclude["domain_keyword"]:
            continue
        out["domain_keyword"].add(v)

    for raw in bucket["domain_regex"]:
        v = raw.strip()
        if drop_empty and not v:
            continue
        if v in exclude["domain_regex"]:
            continue
        try:
            re.compile(v)
        except re.error:
            print(f"  drop bad domain_regex: {v[:80]}")
            continue
        out["domain_regex"].add(v)

    for raw in bucket["ip_cidr"]:
        v = raw.strip()
        if drop_empty and not v:
            continue
        if not is_valid_cidr(v):
            continue
        out["ip_cidr"].add(v)
    return out


def load_previous_upstream_counts(timeout: int = 20) -> Dict[str, int]:
    """读取上一次已发布的 index.json，返回 {tag: upstream_items}。失败则返回空（不启用降幅保护）。"""
    try:
        pub = load_json(ROOT / "publish.json")
        url = pub["raw_base"].rstrip("/") + "/index.json"
        data = json.loads(fetch_bytes(url, timeout=timeout).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"  (无法读取上次发布的 index.json，跳过降幅保护: {exc})")
        return {}
    out: Dict[str, int] = {}
    for r in data.get("rulesets") or []:
        if isinstance(r.get("upstream_items"), int):
            out[r["tag"]] = r["upstream_items"]
    return out


GUARD_MIN_RATIO = 0.8  # 上游合并后的条目数低于上次的 80% 就视为异常，拒绝发布


def bucket_to_ruleset(bucket: Dict[str, Set[str]], version: int) -> Dict[str, Any]:
    rule: Dict[str, Any] = {}
    for key in LIST_KEYS:
        items = sorted(bucket[key])
        if not items:
            continue
        rule[key] = items if len(items) > 1 else items[0]
    return {"version": version, "rules": [rule] if rule else []}


def count_items(bucket: Dict[str, Set[str]]) -> int:
    return sum(len(bucket[k]) for k in LIST_KEYS)


def write_and_compile(
    payload: Dict[str, Any],
    output_stem: str,
    dist_dir: Path,
    sing_box: Path,
) -> Path:
    dist_dir.mkdir(parents=True, exist_ok=True)
    json_path = dist_dir / f"{output_stem}.json"
    srs_path = dist_dir / f"{output_stem}.srs"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run_sing_box(sing_box, ["rule-set", "compile", str(json_path), "-o", str(srs_path)])
    return srs_path


def verify_load(srs_path: Path, sing_box: Path, kind: str) -> None:
    tag = "test-rs"
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "check.json"
        local_srs = Path(td) / srs_path.name
        shutil.copyfile(srs_path, local_srs)
        cfg = {
            "log": {"level": "error"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "in",
                    "listen": "127.0.0.1",
                    "listen_port": 19850,
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "rules": [{"rule_set": tag, "action": "route", "outbound": "direct"}],
                "rule_set": [
                    {
                        "tag": tag,
                        "type": "local",
                        "format": "binary",
                        "path": str(local_srs),
                    }
                ],
                "final": "direct",
            },
        }
        _ = kind
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        run_sing_box(sing_box, ["check", "-c", str(cfg_path)])
        out = Path(td) / "decompiled.json"
        run_sing_box(sing_box, ["rule-set", "decompile", str(local_srs), "-o", str(out)])
        payload = json.loads(out.read_text(encoding="utf-8"))
        if "rules" not in payload:
            raise RuntimeError(f"decompile 结果异常: {srs_path.name}")


def build_one(
    entry: Dict[str, Any],
    filters: Dict[str, Any],
    rule_set_version: int,
    sing_box: Path,
    cache_dir: Path,
    dist_dir: Path,
    only_source: bool = False,
    refresh_discover: bool = False,
    skip_discover: bool = False,
    skip_dns_verify: bool = False,
    dns_workers: int = 32,
    previous_counts: Optional[Dict[str, int]] = None,
    guard: bool = True,
) -> Dict[str, Any]:
    tag = entry["tag"]
    output = entry["output"]
    kind = entry.get("kind", "geosite")
    print(f"\n== {tag} ({output}) ==")

    # 1) 合并上游
    buckets: List[Dict[str, Set[str]]] = []
    for up in entry.get("upstreams") or []:
        if only_source and up.get("format") != "source":
            print(f"  skip binary {up['url']}")
            continue
        try:
            buckets.append(fetch_upstream(up["url"], up["format"], sing_box, cache_dir))
            print(f"  + upstream items={count_items(buckets[-1])} format={up['format']}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ! upstream 失败，跳过: {up['url']}\n    {exc}")

    configured = entry.get("upstreams") or []
    if configured and not buckets and not only_source:
        # 配了上游却一个都拿不到：宁可这次构建失败（不发布，客户端继续用上次的），也不发布一个残缺的规则集
        raise RuntimeError(f"{tag}: 配置了 {len(configured)} 个上游，但全部下载/解析失败，拒绝发布")
    if not buckets:
        buckets = [empty_bucket()]

    merged = merge_buckets(buckets)
    upstream_items = count_items(merged)
    print(f"  merge items={upstream_items}")

    if guard and previous_counts:
        prev = previous_counts.get(tag)
        if prev and upstream_items < prev * GUARD_MIN_RATIO:
            raise RuntimeError(
                f"{tag}: 上游合并条目数 {upstream_items}，比上次发布时的 {prev} 低于 "
                f"{int(GUARD_MIN_RATIO * 100)}%，疑似上游异常，拒绝发布（确认无误可加 --no-guard 重跑）"
            )

    discover_stats: Dict[str, Any] = {"enabled": False}
    dns_stats: Dict[str, Any] = {"checked": 0, "alive": 0, "dead": 0}
    to_verify: Set[str] = set()

    # 2) 自动发现（geosite + 有 seeds）
    # 只关心：补上游缺失的 seed apex，以及 CT SAN 上的其它相关 apex
    # 不再把「已被 domain_suffix 覆盖的子域」写成 domain 注水
    discovered_suffixes: Set[str] = set()
    if kind == "geosite" and not skip_discover:
        print("  discover ...")
        discovered = discover_for_output(output, refresh=refresh_discover)
        discover_stats = discovered["stats"]
        if discover_stats.get("enabled"):
            print(
                f"  discover seeds={discover_stats['seeds']} "
                f"raw={discover_stats['raw']} "
                f"related_apex={discover_stats.get('related_apex', 0)}"
            )
            before_suffix = set(merged["domain_suffix"])
            for s in discovered["domain_suffix"]:
                s = normalize_host(s)
                if not s:
                    continue
                if covered_by_suffix(s, before_suffix):
                    continue  # 上游已有更宽/同等覆盖
                merged["domain_suffix"].add(s)
                discovered_suffixes.add(s)
                to_verify.add(s)
            print(f"  discover new_suffix={len(discovered_suffixes)}")
        else:
            print("  discover (no seeds)")

    # 3) 叠加覆盖（人工保底）
    overlay_path = OVERLAY_DIR / f"{output}.json"
    overlay_new: Set[str] = set()
    if overlay_path.exists():
        overlay_new = apply_overlay(merged, load_json(overlay_path))
        to_verify |= overlay_new
        print(f"  overlay {overlay_path.name} -> items={count_items(merged)} new={len(overlay_new)}")
    else:
        print("  overlay (none)")

    # 4) DNS 验证：只验证「新 suffix / overlay 新增」
    # domain_suffix 即使 apex 自身无 A 记录也常仍有效，故仅对「发现到的新 apex」在 dead 时剔除；
    # overlay 保底项保留（人工意图优先）。
    if kind == "geosite" and not skip_dns_verify and to_verify:
        print(f"  dns-verify candidates={len(to_verify)} workers={dns_workers}")
        alive, dead = verify_hosts(to_verify, workers=dns_workers)
        dns_stats = summarize(alive, dead)
        print(f"  dns-verify alive={dns_stats['alive']} dead={dns_stats['dead']}")

        for d in dead:
            host = normalize_host(d)
            if host in discovered_suffixes and host not in overlay_new:
                merged["domain_suffix"].discard(host)
                merged["domain"].discard(host)

        if dead:
            dead_path = dist_dir / f"{output}.dead.json"
            dist_dir.mkdir(parents=True, exist_ok=True)
            dead_path.write_text(
                json.dumps(sorted(dead), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    elif skip_dns_verify:
        print("  dns-verify skipped")

    # 5) 覆盖去重：去掉已被 domain_suffix 覆盖的精确 domain / 冗余长 suffix
    merged, collapse_stats = collapse_bucket(merged)
    print(
        f"  collapse domain {collapse_stats['domain_before']}→{collapse_stats['domain_after']} "
        f"(dropped {collapse_stats['domain_dropped']}), "
        f"suffix {collapse_stats['suffix_before']}→{collapse_stats['suffix_after']} "
        f"(dropped {collapse_stats['suffix_dropped']})"
    )

    # 6) 过滤
    filtered = apply_filters(merged, filters)
    print(f"  filter items={count_items(filtered)}")

    # 7) 生成
    payload = bucket_to_ruleset(filtered, rule_set_version)
    srs_path = write_and_compile(payload, output, dist_dir, sing_box)
    print(f"  wrote {srs_path.relative_to(ROOT)} ({srs_path.stat().st_size} bytes)")

    # 8) sing-box 加载校验
    verify_load(srs_path, sing_box, kind)
    print("  load-verify OK (check + decompile)")

    return {
        "tag": tag,
        "output": output,
        "kind": kind,
        "items": count_items(filtered),
        "upstream_items": upstream_items,
        "srs": str(srs_path.relative_to(ROOT)),
        "counts": {k: len(filtered[k]) for k in LIST_KEYS if filtered[k]},
        "discover": discover_stats,
        "dns_verify": dns_stats,
        "collapse": collapse_stats,
        "new_suffix_from_discover": len(discovered_suffixes),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="构建自建 sing-box 规则集（发现+验证+生成）")
    p.add_argument("--only", nargs="*", help="只构建指定 output 名，如 youtube ai")
    p.add_argument("--refresh", action="store_true", help="清空上游 cache 并重新发现")
    p.add_argument("--source-only", action="store_true", help="只拉 JSON 源，跳过 binary 反编译")
    p.add_argument("--skip-discover", action="store_true", help="跳过 CT 自动发现")
    p.add_argument("--skip-dns-verify", action="store_true", help="跳过 DNS 存活验证")
    p.add_argument("--dns-workers", type=int, default=32, help="DNS 验证并发数")
    p.add_argument("--no-guard", action="store_true", help="关闭「上游条目数骤降」保护（确认上游确实缩水时用）")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    catalog = load_json(ROOT / "catalog.json")
    filters = load_json(ROOT / "filters.json")
    defaults = catalog.get("defaults") or {}
    version = int(defaults.get("rule_set_version", 2))

    if not SING_BOX.is_file():
        print(f"缺少 {SING_BOX}，请先下载 sing-box", file=sys.stderr)
        return 1

    if args.refresh and CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
        print("已清空 cache")

    only: Optional[Set[str]] = set(args.only) if args.only else None
    summaries: List[Dict[str, Any]] = []
    previous_counts = {} if args.no_guard else load_previous_upstream_counts()

    for entry in catalog.get("rulesets") or []:
        if only and entry["output"] not in only:
            continue
        summary = build_one(
            entry=entry,
            filters=filters,
            rule_set_version=version,
            sing_box=SING_BOX,
            cache_dir=CACHE_DIR,
            dist_dir=DIST_DIR,
            only_source=args.source_only,
            refresh_discover=args.refresh,
            skip_discover=args.skip_discover,
            skip_dns_verify=args.skip_dns_verify,
            dns_workers=args.dns_workers,
            previous_counts=previous_counts,
            guard=not args.no_guard,
        )
        summaries.append(summary)

    report = DIST_DIR / "build-report.json"
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n完成 {len(summaries)} 个规则集 → {report.relative_to(ROOT)}")
    for s in summaries:
        disc = s.get("discover") or {}
        col = s.get("collapse") or {}
        extra = ""
        if disc.get("enabled"):
            extra = (
                f" | new_suffix={s.get('new_suffix_from_discover', 0)}"
                f" related_apex={disc.get('related_apex', 0)}"
                f" collapse_drop_domain={col.get('domain_dropped', 0)}"
            )
        print(f"  - {s['tag']}: {s['items']} items → {s['srs']}{extra}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as e:
        print(f"网络错误: {e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:  # noqa: BLE001
        print(f"失败: {e}", file=sys.stderr)
        raise SystemExit(1)
