#!/usr/bin/env python3
"""规则集流水线：合并上游 → 自动发现 → 自动验证 → 叠加覆盖 → 过滤 → 生成 → 加载校验。"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from coverage import collapse_bucket, covered_by_suffix, normalize_host
from discover import discover_for_output, load_seed_config
from official_lists import OFFICIAL_SOURCES
from verify import dns_alive, impersonation_screen, verify_candidate
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


# ---- v3.1 验证电池配置（verify.json）。文件缺失时用内置默认，保证旧行为可回退 ----
_VERIFY_DEFAULTS: Dict[str, Any] = {
    "quarantine_days": 7,
    "quarantine_drop_dead_days": 7,
    "quarantine_rescan_days_dead": 3,
    "rescan_daily_sample": 50,
    "rescan_daily_ratio": 0.05,
    "discover_default_max_related": 500,
    "discover_cache_ttl_days": 7,
    "supplement_mode": "verify",
    "upstream_check_mode": "report",
    "dry_run": False,
    "phish_keywords": ["login", "verify", "secure", "account", "wallet", "support",
                       "update", "signin", "auth", "password", "airdrop", "bonus"],
    "typosquat_max_distance": 2,
}


def load_verify_cfg() -> Dict[str, Any]:
    cfg = dict(_VERIFY_DEFAULTS)
    p = ROOT / "verify.json"
    if p.exists():
        try:
            user = load_json(p)
            if isinstance(user, dict):
                cfg.update(user)
        except Exception as exc:  # noqa: BLE001
            print(f"  (verify.json 解析失败，用内置默认: {exc})")
    return cfg


VERIFY_CFG: Dict[str, Any] = load_verify_cfg()


def vcfg(key: str) -> Any:
    return VERIFY_CFG.get(key, _VERIFY_DEFAULTS.get(key))


def make_verify_ctx(entry: Dict[str, Any], official: Set[str], check_dns: bool = True) -> Dict[str, Any]:
    """为某集合构造 verify_candidate 的 ctx：品牌 / 已知 SLD / 已知 TLD / 官方源。"""
    output = entry["output"]
    try:
        cfg = load_seed_config(output) or {}
    except Exception:  # noqa: BLE001
        cfg = {}
    seeds = [normalize_host(s) for s in (cfg.get("seeds") or []) if s]
    brand = seeds[0].split(".")[0] if seeds else ""
    return {
        "brand": brand,
        "sub_brands": tuple(cfg.get("sub_brands") or ()),
        "known_slds": {s.split(".")[0] for s in seeds},
        "known_tlds": {s.rsplit(".", 1)[-1] for s in seeds if "." in s},
        "keywords": tuple(vcfg("phish_keywords") or ()),
        "max_distance": int(vcfg("typosquat_max_distance") or 2),
        "official": set(official or ()),
        "check_dns": check_dns,  # False = 本地调试，DNS 一律视为存活（生产勿用）
    }


def new_quarantine_record(
    apex: str, decision: str, info: Dict[str, Any], source: str, today: str
) -> Dict[str, Any]:
    dead = bool(info.get("dead"))
    return {
        "first_seen": today,
        "pending_review": decision == "pending_review",
        "consecutive_pass": 0 if dead else 1,  # 入场时的那次验证计为第 1 次通过
        "consecutive_dead": 1 if dead else 0,
        "last_check": today,
        "signals": info.get("signals") or [],
        "source": source,
        "reason": info.get("reason") or "",
    }


def merge_quarantine_record(
    old: Dict[str, Any], new: Dict[str, Any]
) -> Dict[str, Any]:
    """合并单条隔离区记录：新发现不重置旧计数。

    保留最早 first_seen、最大 consecutive_pass/consecutive_dead；
    pending_review 一旦置位不因重新发现而清除（fail-safe）；
    其余字段取新记录（当轮证据）。
    """
    old_seen = old.get("first_seen") or new.get("first_seen")
    new_seen = new.get("first_seen") or old.get("first_seen")
    return {
        **new,
        "first_seen": min(old_seen, new_seen) if old_seen and new_seen else (old_seen or new_seen),
        "consecutive_pass": max(int(old.get("consecutive_pass", 0) or 0), int(new.get("consecutive_pass", 0) or 0)),
        "consecutive_dead": max(int(old.get("consecutive_dead", 0) or 0), int(new.get("consecutive_dead", 0) or 0)),
        "pending_review": bool(old.get("pending_review")) or bool(new.get("pending_review")),
    }


def upsert_quarantine_record(
    records: Dict[str, Dict[str, Any]], apex: str, new: Dict[str, Any]
) -> None:
    """向隔离区写入一条记录：已存在则合并保留计数，不存在则全新写入。

    build_one 里 CT 发现/上游新条目/rescan 直接覆盖写曾导致计数重启
    （#64 实测 cloudflaressl.com 4→2；补充上游路径已由
    merge_quarantine_records 管住）；统一走 upsert，语义与合并一致。
    """
    old = records.get(apex)
    records[apex] = merge_quarantine_record(old, new) if old is not None else new


def merge_quarantine_records(
    prev: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """合并上轮隔离区与本轮新发现：新发现不重置旧计数。

    旧写法 {**prev, **new} 是新记录整体覆盖旧记录：某域名被重新发现为
    新候选时，first_seen/consecutive_pass 会重启（如 ai 集两条 4→2），
    只推迟转正、不丢数据，但计数语义是错的。合并时保留最早 first_seen、
    最大 consecutive_pass/consecutive_dead；pending_review 一旦置位不因
    重新发现而清除（fail-safe）；其余字段取新记录（当轮证据）。
    """
    merged = dict(prev or {})
    for apex, rec in (new or {}).items():
        old = merged.get(apex)
        if old is None:
            merged[apex] = rec
        else:
            merged[apex] = merge_quarantine_record(old, rec)
    return merged


def update_quarantine_for_output(
    records: Dict[str, Dict[str, Any]],
    ctx: Dict[str, Any],
    dry_run: bool,
    today: str,
    check_dns: bool = True,
    dns_workers: int = 32,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str], Dict[str, int]]:
    """隔离区每日更新。返回 (保留的记录, 本轮转正的 apex, 统计)。

    - 每轮全量重验（仿冒筛查本地计算 + DNS 批量并发）
    - pending_review 永不自动转正，仅人工 override 可放行
    - consecutive_dead >= drop_days → 丢弃；触发仿冒筛查 → 立即丢弃
    - dry_run 时只累积计数、不执行转正
    """
    qdays = int(vcfg("quarantine_days") or 7)
    drop_dead = int(vcfg("quarantine_drop_dead_days") or 7)
    brand = ctx.get("brand") or ""
    known_slds = ctx.get("known_slds") or set()
    keywords = ctx.get("keywords") or ()
    max_distance = int(ctx.get("max_distance") or 2)
    sub_brands = tuple(ctx.get("sub_brands") or ())

    # 先过本地仿冒筛查（快），再批量 DNS
    candidates = {}
    dropped = 0
    for apex, rec in records.items():
        if impersonation_screen(apex, brand, known_slds, keywords, max_distance, sub_brands):
            dropped += 1
            continue
        candidates[apex] = dict(rec)
    if check_dns and candidates:
        alive, _ = verify_hosts(set(candidates), workers=dns_workers)
    else:
        alive = set(candidates) if not check_dns else set()

    kept: Dict[str, Dict[str, Any]] = {}
    promoted: Set[str] = set()
    stats = {"kept": 0, "promoted": 0, "dropped": dropped, "pending_review": 0}
    for apex, rec in candidates.items():
        rec["last_check"] = today
        if apex in alive:
            rec["consecutive_pass"] = int(rec.get("consecutive_pass", 0)) + 1
            rec["consecutive_dead"] = 0
        else:
            rec["consecutive_dead"] = int(rec.get("consecutive_dead", 0)) + 1
        if int(rec.get("consecutive_dead", 0)) >= drop_dead:
            stats["dropped"] += 1
            continue
        if rec.get("pending_review"):
            stats["pending_review"] += 1
            kept[apex] = rec
            continue
        if int(rec.get("consecutive_pass", 0)) >= qdays and not dry_run:
            promoted.add(apex)
            stats["promoted"] += 1
            continue
        stats["kept"] += 1
        kept[apex] = rec
    return kept, promoted, stats


def load_quarantine(timeout: int = 20) -> Dict[str, Any]:
    """读取上次发布的 state/quarantine.json。失败返回空（本轮不转正、只新增）。"""
    try:
        pub = load_json(ROOT / "publish.json")
        url = pub["raw_base"].rstrip("/") + "/state/quarantine.json"
        data = json.loads(fetch_bytes(url, timeout=timeout).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        print(f"  (无法读取上次的隔离区状态，本轮不转正只新增: {exc})")
        return {}


def load_previous_set_entries(output: str, kind: str, timeout: int = 20) -> Set[str]:
    """读取上次发布的某集合 .json 里的域名条目（用于上游新条目 diff）。失败返回空。"""
    try:
        pub = load_json(ROOT / "publish.json")
        base = pub["raw_base"].rstrip("/")
        if kind == "geoip":
            name = output[6:] if output.startswith("geoip-") else output
            rel = f"geoip/{name}.json"
        else:
            rel = f"geosite/{output}.json"
        data = json.loads(fetch_bytes(f"{base}/{rel}", timeout=timeout).decode("utf-8"))
        out: Set[str] = set()
        for rule in data.get("rules") or []:
            for k in ("domain", "domain_suffix"):
                v = rule.get(k)
                if isinstance(v, str):
                    out.add(normalize_host(v))
                elif isinstance(v, list):
                    out.update(normalize_host(x) for x in v)
        return {x for x in out if x}
    except Exception:  # noqa: BLE001
        return set()


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

    if fmt == "v2fly":
        return parse_v2fly(url, cache_dir)

    if fmt == "clashlist":
        return parse_clashlist(cache_path.read_text(encoding="utf-8", errors="replace"))

    raise ValueError(f"未知上游 format: {fmt}")


def _cached_text(url: str, cache_dir: Path) -> str:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cp = cache_dir / re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
    if not cp.exists():
        cp.write_bytes(fetch_bytes(url))
    return cp.read_text(encoding="utf-8", errors="replace")


def parse_v2fly(url: str, cache_dir: Path, _seen: Optional[Set[str]] = None) -> Dict[str, Set[str]]:
    """解析 v2fly/domain-list-community 的 data 文件（支持 include:，不处理 regexp/keyword，带 @属性 的 include 跳过）。"""
    seen = _seen if _seen is not None else set()
    base, name = url.rsplit("/", 1)
    bucket = empty_bucket()
    if name in seen:
        return bucket
    seen.add(name)
    for line in _cached_text(url, cache_dir).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        tok, has_attr = parts[0], any(p.startswith("@") for p in parts[1:])
        if tok.startswith("include:"):
            if has_attr:
                continue
            sub = parse_v2fly(f"{base}/{tok[8:]}", cache_dir, seen)
            for k in bucket:
                bucket[k] |= sub.get(k, set())
            continue
        if tok.startswith(("regexp:", "keyword:")):
            continue
        if tok.startswith("full:"):
            bucket["domain"].add(tok[5:].lower())
            continue
        bucket["domain_suffix"].add((tok[7:] if tok.startswith("domain:") else tok).lower())
    return bucket


def parse_clashlist(text: str) -> Dict[str, Set[str]]:
    """解析 blackmatrix7 的 Clash .list：只取 DOMAIN-SUFFIX 与 DOMAIN（关键字/IP/进程名一律忽略，避免误伤）。"""
    bucket = empty_bucket()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("DOMAIN-SUFFIX,"):
            bucket["domain_suffix"].add(line.split(",")[1].strip().lower())
        elif line.startswith("DOMAIN,"):
            bucket["domain"].add(line.split(",")[1].strip().lower())
    return bucket


def _label_suffixes(host: str) -> List[str]:
    p = host.split(".")
    return [".".join(p[i:]) for i in range(len(p))]


def _covered(host: str, suffixes: Set[str]) -> bool:
    return any(x in suffixes for x in _label_suffixes(host))


def drop_blacklisted(bucket: Dict[str, Set[str]], apexes: Iterable[str]) -> Dict[str, Set[str]]:
    apex = tuple(apexes)

    def bad(h: str) -> bool:
        return any(h == a or h.endswith("." + a) for a in apex)

    out = {k: set(v) for k, v in bucket.items()}
    out["domain"] = {d for d in bucket["domain"] if not bad(d)}
    out["domain_suffix"] = {x for x in bucket["domain_suffix"] if not bad(x)}
    return out


_FOREIGN: Dict[str, Any] = {}
_PUBLIC_SUFFIX_LIKE = re.compile(r"^(com|co|net|org|gov|edu|ac|or|ne|go|me|mil)\.[a-z]{2}$")
# v3.1 §6.6：compute_supplements 最近一次运行中，被 ≥2 个集合同时要而两边丢弃的第三方域
_AMBIGUOUS: Dict[str, Set[str]] = {}


def conflicts_with_other_sets(tag: str, host: str) -> bool:
    """host 是否与「其它集合」的官方条目重叠（相同、被覆盖、或比它更宽）。"""
    for t, (p, par) in _FOREIGN.items():
        if t == tag:
            continue
        if _covered(host, p["domain_suffix"]) or host in p["domain"] or host in par:
            return True
    return False


def compute_supplements(
    entries: List[Dict[str, Any]], filters: Dict[str, Any], apexes: List[str]
) -> Dict[str, Dict[str, Set[str]]]:
    """补充上游（role=supplement）只能新增「无歧义」的条目：
    1) 先过共享基础设施黑名单；
    2) 已被本集合官方上游覆盖的 → 不算新增；
    3) 与「其它集合」的官方条目有重叠（相同、更宽或更窄）→ 丢弃；
    4) 同时被两个以上集合的补充上游带来、且互相重叠 → 两边都丢弃。
    所以补充上游只会让更多域名被正确归类，绝不改变已有域名的去向。"""
    prim: Dict[str, Dict[str, Set[str]]] = {}
    raw: Dict[str, Dict[str, Set[str]]] = {}
    report: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        if e.get("kind", "geosite") != "geosite":
            continue
        pb, sb = [], []
        for up in e.get("upstreams") or []:
            try:
                b = fetch_upstream(up["url"], up["format"], SING_BOX, CACHE_DIR)
            except Exception as exc:  # noqa: BLE001
                print(f"  ! 上游失败，跳过: {up['url']} ({exc})")
                continue
            (sb if up.get("role") == "supplement" else pb).append(b)
        prim[e["tag"]] = apply_filters(merge_buckets(pb), filters) if pb else empty_bucket()
        if sb:
            raw[e["tag"]] = apply_filters(merge_buckets(sb), filters)

    # 其它集合官方条目的「所有后缀形态」与「被谁覆盖」索引
    all_hosts = {t: (b["domain"] | b["domain_suffix"]) for t, b in prim.items()}
    parents = {t: {x for h in hs for x in _label_suffixes(h)} for t, hs in all_hosts.items()}

    _FOREIGN.clear()
    _FOREIGN.update({t: (prim[t], parents[t]) for t in prim})

    survivors: Dict[str, Dict[str, Set[str]]] = {}
    for tag, sb in raw.items():
        n0 = len(sb["domain"]) + len(sb["domain_suffix"])
        sb = drop_blacklisted(sb, apexes)
        n1 = len(sb["domain"]) + len(sb["domain_suffix"])
        own = prim[tag]
        sb["domain_suffix"] = {x for x in sb["domain_suffix"] if not _covered(x, own["domain_suffix"])}
        sb["domain"] = {d for d in sb["domain"] if d not in own["domain"] and not _covered(d, own["domain_suffix"])}
        n2 = len(sb["domain"]) + len(sb["domain_suffix"])
        others = [t for t in prim if t != tag]

        def clash(h: str) -> bool:
            for t in others:
                if _covered(h, prim[t]["domain_suffix"]) or h in prim[t]["domain"] or h in parents[t]:
                    return True
            return False

        sb["domain_suffix"] = {x for x in sb["domain_suffix"] if not clash(x)}
        sb["domain"] = {d for d in sb["domain"] if not clash(d)}
        n3 = len(sb["domain"]) + len(sb["domain_suffix"])
        survivors[tag] = sb
        report[tag] = {"supplement_raw": n0, "dropped_blacklist": n0 - n1, "already_covered": n1 - n2,
                       "dropped_conflict_with_other_sets": n2 - n3, "kept_before_cross_check": n3}

    # 补充上游之间互相重叠 → 两边都丢
    tags = list(survivors)
    drop: Dict[str, Set[Tuple[str, str]]] = {t: set() for t in tags}
    for i, a in enumerate(tags):
        for b in tags[i + 1:]:
            A, B = survivors[a], survivors[b]
            A_all, B_all = A["domain"] | A["domain_suffix"], B["domain"] | B["domain_suffix"]
            B_par = {x for h in B_all for x in _label_suffixes(h)}
            A_par = {x for h in A_all for x in _label_suffixes(h)}
            for kind_key in ("domain", "domain_suffix"):
                for h in A[kind_key]:
                    if _covered(h, B["domain_suffix"]) or h in B["domain"] or h in B_par:
                        drop[a].add((kind_key, h))
                for h in B[kind_key]:
                    if _covered(h, A["domain_suffix"]) or h in A["domain"] or h in A_par:
                        drop[b].add((kind_key, h))
    out: Dict[str, Dict[str, Set[str]]] = {}
    for t in tags:
        s = {k: set(v) for k, v in survivors[t].items()}
        for kk, h in drop[t]:
            s[kk].discard(h)
        report[t]["dropped_ambiguous_between_supplements"] = len(drop[t])
        report[t]["added"] = len(s["domain"]) + len(s["domain_suffix"])
        report[t]["examples"] = sorted(s["domain_suffix"] | s["domain"])[:8]
        out[t] = s
    global _AMBIGUOUS
    _AMBIGUOUS = {t: {h for _, h in drop[t]} for t in tags}
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    (DIST_DIR / "supplement-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\n补充上游汇总（新增 = 真正会写进规则集的条目数）:")
    for t, r in report.items():
        print(f"  {t}: 新增 {r['added']} | 黑名单丢 {r['dropped_blacklist']} | 已覆盖 {r['already_covered']} | "
              f"与其它集合冲突丢 {r['dropped_conflict_with_other_sets']} | 补充间歧义丢 {r['dropped_ambiguous_between_supplements']}")
    return out


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


STATE_RETENTION_DAYS = 30  # 自动发现的域名，连续这么多天没再被发现才移除


def load_previous_state(timeout: int = 20) -> Dict[str, Dict[str, str]]:
    """读取上次发布的 state/discovered.json：{output: {域名: 最后一次被发现的日期}}。失败返回空（本次不做累积）。"""
    try:
        pub = load_json(ROOT / "publish.json")
        url = pub["raw_base"].rstrip("/") + "/state/discovered.json"
        data = json.loads(fetch_bytes(url, timeout=timeout).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"  (无法读取上次的发现状态，本次不累积: {exc})")
        return {}
    ent = data.get("entries") or {}
    return {k: {h: str(d) for h, d in v.items()} for k, v in ent.items() if isinstance(v, dict)}


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
    supplement: Optional[Dict[str, Set[str]]] = None,
    prev_state: Optional[Dict[str, str]] = None,
    # v3.1 新增
    quarantine_records: Optional[Dict[str, Dict[str, Any]]] = None,
    rescan_dead: Optional[Dict[str, int]] = None,
    official_set: Optional[Set[str]] = None,
    dry_run: bool = False,
    supplement_verify: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    tag = entry["tag"]
    output = entry["output"]
    kind = entry.get("kind", "geosite")
    print(f"\n== {tag} ({output}) ==")
    today = dt.date.today()
    today_str = today.isoformat()
    check_dns = not skip_dns_verify
    ctx = make_verify_ctx(entry, official_set or set(), check_dns=check_dns) if kind == "geosite" else None

    # 1) 合并上游
    buckets: List[Dict[str, Set[str]]] = []
    for up in entry.get("upstreams") or []:
        if up.get("role") == "supplement":
            continue  # 补充上游在 main() 里统一做冲突/黑名单过滤后再合并
        if only_source and up.get("format") != "source":
            print(f"  skip binary {up['url']}")
            continue
        try:
            buckets.append(fetch_upstream(up["url"], up["format"], sing_box, cache_dir))
            print(f"  + upstream items={count_items(buckets[-1])} format={up['format']}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ! upstream 失败，跳过: {up['url']}\n    {exc}")

    configured = [u for u in (entry.get("upstreams") or []) if u.get("role") != "supplement"]
    if configured and not buckets and not only_source:
        # 配了上游却一个都拿不到：宁可这次构建失败（不发布，客户端继续用上次的），也不发布一个残缺的规则集
        raise RuntimeError(f"{tag}: 配置了 {len(configured)} 个上游，但全部下载/解析失败，拒绝发布")
    if not buckets:
        buckets = [empty_bucket()]

    merged = merge_buckets(buckets)
    upstream_items = count_items(merged)
    print(f"  merge items={upstream_items}")
    # v3.1-fix: 记录主上游域名集合，rescan 时主上游命中只报告不删除（官方 0 丢失原则）
    main_upstream_domains = set(merged.get("domain", set())) | set(merged.get("domain_suffix", set()))
    # v3.1-fix: 可信来源快照（主上游 + 官方源 + 种子）：筛查 verdict 不得否决可信来源
    # 的条目；check_samples 用 verification["trusted"] 裁决 supplement/discover bad 名单。
    trusted_domain: Set[str] = set(merged.get("domain", set()))
    trusted_suffix: Set[str] = set(merged.get("domain_suffix", set()))

    if guard and previous_counts:
        prev = previous_counts.get(tag)
        if prev and upstream_items < prev * GUARD_MIN_RATIO:
            raise RuntimeError(
                f"{tag}: 上游合并条目数 {upstream_items}，比上次发布时的 {prev} 低于 "
                f"{int(GUARD_MIN_RATIO * 100)}%，疑似上游异常，拒绝发布（确认无误可加 --no-guard 重跑）"
            )

    # 1.5) 官方源（v3.1 §4）：厂商自己发布的机器可读列表，唯一无条件 admit，仍过 collapse/filter
    official_added = 0
    if kind == "geosite" and official_set:
        off = {normalize_host(x) for x in official_set}
        off = {x for x in off if x and "." in x and not _PUBLIC_SUFFIX_LIKE.match(x)}
        merged["domain_suffix"] |= off
        official_added = len(off)
        trusted_suffix |= off
        print(f"  + 官方源 {official_added} apex（直接并入，仍过后续去重/过滤）")

    if supplement and (supplement["domain"] or supplement["domain_suffix"]):
        merged = merge_buckets([merged, supplement])
        print(f"  + 补充上游新增 {len(supplement['domain']) + len(supplement['domain_suffix'])} 条（已过黑名单与冲突过滤）")

    # 2) 自动发现（v3.1）：seeds 直接并入（人工意图）；related 候选走验证电池
    verification: Dict[str, Any] = {
        "dry_run": dry_run,
        "supplement": supplement_verify or {},
        "discover": {"admit": [], "quarantine": [], "pending_review": [], "reject": []},
        "official_admit": official_added,
    }
    discover_stats: Dict[str, Any] = {"enabled": False}
    discovered_suffixes: Set[str] = set()
    discover_dropped = 0
    seed_set: Set[str] = set()
    records: Dict[str, Dict[str, Any]] = dict(quarantine_records or {})
    if kind == "geosite" and not skip_discover:
        print("  discover ...")
        discovered = discover_for_output(
            output,
            refresh=refresh_discover,
            default_max_related=int(vcfg("discover_default_max_related") or 500),
            ttl_days=float(vcfg("discover_cache_ttl_days") or 7),
        )
        discover_stats = discovered["stats"]
        if discover_stats.get("enabled"):
            print(
                f"  discover seeds={discover_stats['seeds']} "
                f"raw={discover_stats['raw']} "
                f"related_apex={discover_stats.get('related_apex', 0)}"
            )
            seed_set = set(discovered.get("seeds") or [])
            before_suffix = set(merged["domain_suffix"])
            before_exact = set(merged["domain"])
            vd = verification["discover"]
            for s in discovered["domain_suffix"]:
                s = normalize_host(s)
                if not s:
                    continue
                if s in before_exact or covered_by_suffix(s, before_suffix):
                    continue  # 上游/补充/官方已有（精确或更宽覆盖），不是新候选
                if _PUBLIC_SUFFIX_LIKE.match(s) or conflicts_with_other_sets(tag, s):
                    discover_dropped += 1  # 公共后缀样式或属于/重叠其它集合
                    continue
                if s in seed_set:
                    merged["domain_suffix"].add(s)  # seeds：人工意图，直接并入
                    continue
                decision, info = verify_candidate(s, ctx)
                if decision == "reject":
                    vd["reject"].append({"apex": s, "reason": info.get("reason")})
                elif decision == "admit":
                    vd["admit"].append(s)
                    if not dry_run:
                        merged["domain_suffix"].add(s)
                        discovered_suffixes.add(s)
                    # dry_run（Phase 0 report-only）：只记录决策，不并入发布内容
                else:
                    upsert_quarantine_record(records, s, new_quarantine_record(s, decision, info, "ct", today_str))
                    vd["pending_review" if decision == "pending_review" else "quarantine"].append(s)
            print(f"  discover seeds 并入 {len(seed_set & merged['domain_suffix'])}/{len(seed_set)}；"
                  f"related: admit={len(vd['admit'])} quarantine={len(vd['quarantine'])} "
                  f"pending_review={len(vd['pending_review'])} reject={len(vd['reject'])} "
                  f"丢弃(公共后缀/跨集合)={discover_dropped}")
        else:
            print("  discover (no seeds)")

    # 可信来源快照收尾：种子是人工意图，同样高于筛查 verdict（种子未并入时不影响检查，
    # 因为检查只测产物命中；并入的种子若被筛查否决，check_samples 据此放行）。
    trusted_suffix |= seed_set
    verification["trusted"] = {
        "domain": sorted(trusted_domain),
        "domain_suffix": sorted(trusted_suffix),
    }

    # 2.5) 上游新条目检查（v3.1 §6.3）：与上次发布 diff，新增条目过仿冒筛查 + DNS
    prev_published: Set[str] = set()
    upstream_new_report: Dict[str, Any] = {"new": 0, "suspicious": []}
    if kind == "geosite":
        prev_published = load_previous_set_entries(output, kind)
    if kind == "geosite" and prev_published and ctx is not None:
        cur_hosts = {h for h in (merged["domain"] | merged["domain_suffix"]) if h}
        new_hosts = {h for h in cur_hosts - prev_published
                     if not covered_by_suffix(h, merged["domain_suffix"] - {h})}
        upstream_new_report["new"] = len(new_hosts)
        mode_up = str(vcfg("upstream_check_mode") or "report")
        if new_hosts and check_dns:
            up_alive, _ = verify_hosts(new_hosts, workers=dns_workers)
        else:
            up_alive = set(new_hosts) if not check_dns else set()
        for h in sorted(new_hosts):
            rej = impersonation_screen(h, ctx["brand"], ctx["known_slds"], ctx["keywords"], ctx["max_distance"], tuple(ctx.get("sub_brands") or ()))
            alive = h in up_alive
            if rej or not alive:
                upstream_new_report["suspicious"].append({"apex": h, "reason": rej or "dns_dead"})
                if mode_up == "quarantine":
                    merged["domain"].discard(h)
                    merged["domain_suffix"].discard(h)
                    upsert_quarantine_record(
                        records, h, new_quarantine_record(
                            h, "pending_review" if (rej and ctx["brand"] and ctx["brand"] in h) else "quarantine",
                            {"reason": rej or "dns_dead", "dead": not alive, "signals": []},
                            "upstream", today_str))
        if upstream_new_report["suspicious"]:
            print(f"  上游新条目：新增 {len(new_hosts)}，可疑 {len(upstream_new_report['suspicious'])}（模式={mode_up}）")
    verification["upstream_new"] = upstream_new_report

    # 2.6) 迁移（v3.1 切换不断档）：上次发布中有、本轮上游/种子/官方都没有的条目
    #      （即历史发现项），以"已验证"身份进隔离区；dry_run 下只累积不转正
    if kind == "geosite" and prev_published:
        cur_hosts = {h for h in (merged["domain"] | merged["domain_suffix"]) if h}
        cur_hosts |= seed_set | {normalize_host(x) for x in (official_set or set()) if normalize_host(x)}
        qdays = int(vcfg("quarantine_days") or 7)
        migrated = 0
        for h in sorted(prev_published - cur_hosts):
            if h in records:
                continue
            records[h] = {
                "first_seen": today_str, "pending_review": False,
                "consecutive_pass": qdays, "consecutive_dead": 0,
                "last_check": today_str, "signals": ["migrated"],
                "source": "migration", "reason": "v3.1 切换：上次发布中的历史发现项",
            }
            migrated += 1
        if migrated:
            print(f"  迁移 {migrated} 条历史发现项进隔离区（已验证身份）")

    # 2.7) 隔离区更新（v3.1 §5.2）：全量重验 → 转正 / 保留 / 丢弃
    #      先剔除已在可信来源（上游/seeds/官方/已放行补充）中的记录：它们不需要隔离
    if kind == "geosite":
        trusted_now = set(merged["domain"]) | set(merged["domain_suffix"])
        for h in [h for h in records
                  if h in trusted_now or covered_by_suffix(h, merged["domain_suffix"])]:
            del records[h]
        # 报告对齐：被可信来源覆盖的候选不再算隔离/待审（避免样本检查误报）
        vd_rep = verification["discover"]
        for sec in ("quarantine", "pending_review"):
            vd_rep[sec] = [h for h in vd_rep[sec] if h in records]
    qstats: Dict[str, int] = {"kept": 0, "promoted": 0, "dropped": 0, "pending_review": 0}
    if kind == "geosite" and ctx is not None:
        kept, promoted, qstats = update_quarantine_for_output(
            records, ctx, dry_run, today_str, check_dns=check_dns, dns_workers=dns_workers)
        records = kept
        if promoted:
            merged["domain_suffix"] |= promoted
            print(f"  隔离区转正 {len(promoted)} 条并入")
            # v3.1-fix: 转正域名写入 dist/promoted-{output}.json，供构建后同步样本脚本使用
            # （不在构建主流程里改 samples.json，避免时序问题）
            try:
                _promoted_path = dist_dir / f"promoted-{output}.json"
                _promoted_path.write_text(json.dumps(sorted(promoted), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            except Exception:
                pass
        print(f"  隔离区：保留 {qstats['kept']} / 待审 {qstats['pending_review']} / "
              f"转正 {qstats['promoted']} / 丢弃 {qstats['dropped']}")
    verification["quarantine"] = qstats

    # 3) 叠加覆盖（人工保底，最高优先级不变）
    overlay_path = OVERLAY_DIR / f"{output}.json"
    overlay_new: Set[str] = set()
    if overlay_path.exists():
        overlay_new = apply_overlay(merged, load_json(overlay_path))
        print(f"  overlay {overlay_path.name} -> items={count_items(merged)} new={len(overlay_new)}")
    else:
        print("  overlay (none)")
    # 注：v3.1 里旧的「发现项 DNS 验证剔除」已由验证电池替代；overlay 保底项保留（人工意图优先）。

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

    # 6.2) 仿冒店铺黑名单：剔除已确认的 counterfeit_shops（2026-10-22 从 Apple 集合清理）
    # 6.3) 已撤销白名单：剔除 revoked_allowlist（2026-10-23，ownership 未确认而移除的域名，永久不信任）
    try:
        _bl = load_json(ROOT / "blacklist.json") or {}
        _cf = (_bl.get("counterfeit_shops") or []) + (_bl.get("revoked_allowlist") or [])
        if _cf:
            before = count_items(filtered)
            filtered = drop_blacklisted(filtered, _cf)
            after = count_items(filtered)
            if before != after:
                print(f"  counterfeit_shops+revoked_allowlist 剔除 {before - after} 条")
    except Exception:  # noqa: BLE001
        pass

    # 6.5) 存量抽查复验（v3.1 §5.3）：每天随机抽查 min(50, 5%) 个已发布条目
    #      seeds / 官方源是人工/厂商意图，不在抽查池里
    #      v3.1-fix: 主上游命中仿冒筛查只报告不删除（官方 0 丢失原则）
    rescan_stats: Dict[str, Any] = {"sampled": 0, "impersonation_hit": [], "dns_dead_moved": [], "main_upstream_hit": []}
    rescan_dead_out = dict(rescan_dead or {})
    if kind == "geosite" and ctx is not None:
        trusted = set(seed_set) | {normalize_host(x) for x in (official_set or set()) if normalize_host(x)}
        pool = sorted((filtered["domain"] | filtered["domain_suffix"]) - trusted)
        n = min(int(vcfg("rescan_daily_sample") or 50),
                int(len(pool) * float(vcfg("rescan_daily_ratio") or 0.05)))
        if n > 0 and pool:
            rng = random.Random(f"{today_str}:{output}")  # 当天确定性抽样，可复现
            sample = rng.sample(pool, min(n, len(pool)))
            rescan_stats["sampled"] = len(sample)
            rescan_drop_dead = int(vcfg("quarantine_rescan_days_dead") or 3)
            clean: List[str] = []
            for h in sample:
                rej = impersonation_screen(h, ctx["brand"], ctx["known_slds"], ctx["keywords"], ctx["max_distance"], tuple(ctx.get("sub_brands") or ()))
                if rej:
                    if h in main_upstream_domains:
                        # 主上游：只报告，不删除（官方 0 丢失原则）
                        rescan_stats["main_upstream_hit"].append({"domain": h, "reason": rej})
                    else:
                        # 补充上游/CT：删除+隔离（原有行为）
                        filtered["domain"].discard(h)
                        filtered["domain_suffix"].discard(h)
                        upsert_quarantine_record(
                            records, h, new_quarantine_record(
                                h, "quarantine", {"reason": f"rescan:{rej}", "signals": []}, "rescan", today_str))
                        rescan_stats["impersonation_hit"].append(h)
                    rescan_dead_out.pop(h, None)
                else:
                    clean.append(h)
            if clean:
                if check_dns:
                    _, rescan_dead_hosts = verify_hosts(set(clean), workers=dns_workers)
                else:
                    rescan_dead_hosts = set()
                for h in clean:
                    if h in rescan_dead_hosts:
                        d = int(rescan_dead_out.get(h, 0)) + 1
                        if d >= rescan_drop_dead:
                            filtered["domain"].discard(h)
                            filtered["domain_suffix"].discard(h)
                            upsert_quarantine_record(
                                records, h, new_quarantine_record(
                                    h, "quarantine", {"reason": "rescan:dns_dead", "dead": True, "signals": []},
                                    "rescan", today_str))
                            rescan_stats["dns_dead_moved"].append(h)
                            rescan_dead_out.pop(h, None)
                        else:
                            rescan_dead_out[h] = d
                    else:
                        rescan_dead_out.pop(h, None)
            if rescan_stats["impersonation_hit"] or rescan_stats["dns_dead_moved"] or rescan_stats["main_upstream_hit"]:
                print(f"  存量抽查：仿冒命中 {len(rescan_stats['impersonation_hit'])} / "
                      f"DNS 死亡打回 {len(rescan_stats['dns_dead_moved'])} / "
                      f"主上游告警 {len(rescan_stats['main_upstream_hit'])}（仅报告未删除）")
    verification["rescan"] = rescan_stats

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
        "state": {},  # v3.1：相关域名改由 state/quarantine.json 持久化，此处留空
        "srs": str(srs_path.relative_to(ROOT)),
        "counts": {k: len(filtered[k]) for k in LIST_KEYS if filtered[k]},
        "discover": discover_stats,
        "dns_verify": {"checked": 0, "alive": 0, "dead": 0, "note": "v3.1 起由验证电池替代"},
        "collapse": collapse_stats,
        "new_suffix_from_discover": len(discovered_suffixes),
        "verification": verification,
        "quarantine_records": records,
        "rescan_dead_out": rescan_dead_out,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="构建自建 sing-box 规则集（发现+验证+生成）")
    p.add_argument("--only", nargs="*", help="只构建指定 output 名，如 youtube ai")
    p.add_argument("--refresh", action="store_true", help="清空上游 cache 并重新发现")
    p.add_argument("--source-only", action="store_true", help="只拉 JSON 源，跳过 binary 反编译")
    p.add_argument("--skip-discover", action="store_true", help="跳过 CT 自动发现")
    p.add_argument("--skip-dns-verify", action="store_true",
                   help="跳过 DNS 存活验证（仅本地调试用：验证电池/隔离区/抽查中的 DNS 一律视为存活，生产勿用）")
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

    # v3.1-fix: 转正文件是单轮产物，旧文件残留会让 check_samples 误排除；
    # 构建开始即清理，保证本轮检查只认本轮转正。
    for stale in DIST_DIR.glob("promoted-*.json"):
        try:
            stale.unlink()
        except OSError:
            pass

    if args.refresh and CACHE_DIR.exists():
        # v3.1：--refresh 只清空上游缓存，保留 cache/discover（独立 7 天 TTL，见 verify.json）
        disc = CACHE_DIR / "discover"
        tmp = None
        if disc.exists():
            tmp = Path(tempfile.mkdtemp()) / "discover"
            shutil.move(str(disc), str(tmp))
        shutil.rmtree(CACHE_DIR)
        if tmp is not None:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp), str(disc))
        print("已清空上游 cache（discover 缓存保留，按 TTL 失效）")

    dry_run = bool(vcfg("dry_run"))
    if dry_run:
        print("\n!! verify.json dry_run=true：验证决策只记录进报告，不改变发布内容（Phase 0 report-only）")

    # v3.1 §4 官方源：厂商自己发布的机器可读列表，唯一无条件 admit
    print("\n== 官方源 ==")
    official: Dict[str, Set[str]] = {}
    for output, fetcher in OFFICIAL_SOURCES.items():
        try:
            official[output] = set(fetcher())
            print(f"  {output}: {len(official[output])} apex")
        except Exception as exc:  # noqa: BLE001
            print(f"  ! 官方源 {output} 失败，本轮跳过（不阻断）: {exc}")
            official[output] = set()

    # v3.1 §5.1 隔离区状态：上次发布的 state/quarantine.json
    prev_quarantine_all = load_quarantine()
    prev_quarantine = prev_quarantine_all.get("entries") or {}
    prev_rescan_dead = prev_quarantine_all.get("rescan_dead") or {}

    only: Optional[Set[str]] = set(args.only) if args.only else None
    summaries: List[Dict[str, Any]] = []
    previous_counts = {} if args.no_guard else load_previous_upstream_counts()
    # v3.1：旧的 discovered-state 累积机制已由隔离区替代，不再读取
    bl_data = load_json(ROOT / "blacklist.json") if (ROOT / "blacklist.json").exists() else {}
    blacklist = (
        list(bl_data.get("shared_infrastructure_apex") or [])
        + list(bl_data.get("auto_blacklisted_apex") or [])
        + list(bl_data.get("counterfeit_shops") or [])
        + list(bl_data.get("revoked_allowlist") or [])
    )
    print("\n== 计算补充上游（黑名单 + 冲突过滤）==")
    supplements_raw = compute_supplements(catalog.get("rulesets") or [], filters, blacklist or [])

    # v3.1 §6.6 自动黑名单：被 ≥2 个集合的补充上游同时要的第三方域，记入 auto 段
    auto_bl = set()
    for hosts in _AMBIGUOUS.values():
        auto_bl |= hosts
    if auto_bl:
        bl_data["auto_blacklisted_apex"] = sorted(set(bl_data.get("auto_blacklisted_apex") or []) | auto_bl)
        (ROOT / "blacklist.json").write_text(json.dumps(bl_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"  自动黑名单 +{len(auto_bl)} 条（累计 {len(bl_data['auto_blacklisted_apex'])}，已写入 blacklist.json 的 auto 段）")

    mode = str(vcfg("supplement_mode") or "verify")
    allow_all = load_json(ROOT / "supplement_allow.json") if (ROOT / "supplement_allow.json").exists() else {}
    supplements: Dict[str, Dict[str, Set[str]]] = {}
    supplement_report: Dict[str, Dict[str, List[str]]] = {}
    quarantine_new: Dict[str, Dict[str, Dict[str, Any]]] = {}  # output -> {apex: record}
    today_str = dt.date.today().isoformat()
    if mode == "allowlist":
        for e in catalog.get("rulesets") or []:
            t = e["tag"]
            if t not in supplements_raw:
                continue
            bkt = empty_bucket()
            ok = set(allow_all.get(e["output"]) or [])
            for kk in ("domain", "domain_suffix"):
                bkt[kk] = {x for x in supplements_raw[t][kk] if x in ok}
            supplements[t] = bkt
            print(f"  [{t}] 白名单模式：并入 {len(bkt['domain']) + len(bkt['domain_suffix'])} 条")
    elif mode == "verify":
        print("  补充上游为 verify 模式：候选过验证电池（supplement_allow.json 降级为手工 override）")
        for e in catalog.get("rulesets") or []:
            t, out = e["tag"], e["output"]
            if t not in supplements_raw:
                continue
            ctx = make_verify_ctx(e, official.get(out, set()), check_dns=not args.skip_dns_verify)
            bkt = empty_bucket()
            rep: Dict[str, List[str]] = {"admit": [], "quarantine": [], "pending_review": [], "reject": []}
            allow_ok = set(allow_all.get(out) or [])
            for kk in ("domain", "domain_suffix"):
                for h in sorted(supplements_raw[t][kk]):
                    # 人工 override 优先级最高（写死）：allowlist 里的直接放行，不走验证电池
                    if not dry_run and h in allow_ok:
                        bkt[kk].add(h)
                        rep["admit"].append(h)
                        continue
                    decision, info = verify_candidate(h, ctx)
                    rep[decision].append(h)
                    if decision == "reject":
                        continue
                    if dry_run:
                        # report-only：实际并入仍走旧白名单，验证决策只记录
                        if h in allow_ok:
                            bkt[kk].add(h)
                    elif decision == "admit":
                        bkt[kk].add(h)
                    else:  # quarantine / pending_review → 进隔离区，本轮不并入
                        quarantine_new.setdefault(out, {})[h] = new_quarantine_record(
                            h, decision, info, "supplement", today_str)
            supplements[t] = bkt
            supplement_report[t] = rep
            print(f"  [{t}] verify: admit={len(rep['admit'])} quarantine={len(rep['quarantine'])} "
                  f"pending_review={len(rep['pending_review'])} reject={len(rep['reject'])}"
                  + ("（dry_run：实际并入走旧白名单）" if dry_run else ""))
    else:
        supplements = supplements_raw
        print("  补充上游为 auto 模式：并入全部通过黑名单与冲突过滤的条目")

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
            supplement=supplements.get(entry["tag"]),
            prev_state=None,  # v3.1：旧累积机制已由隔离区替代
            # v3.1 新增
            quarantine_records=merge_quarantine_records(
                prev_quarantine.get(entry["output"]),
                quarantine_new.get(entry["output"])),
            rescan_dead=dict(prev_rescan_dead.get(entry["output"]) or {}),
            official_set=official.get(entry["output"], set()),
            dry_run=dry_run,
            supplement_verify=supplement_report.get(entry["tag"]),
        )
        summaries.append(summary)

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    (DIST_DIR / "discovered-state.json").write_text(
        json.dumps({"version": 1,
                    "note": "v3.1 起相关域名改由 state/quarantine.json 持久化，此文件仅保留占位",
                    "updated": dt.date.today().isoformat(), "entries": {}},
                   ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    # v3.1 §5.1：隔离区状态发布（state/quarantine.json），下次构建读回
    quarantine_out: Dict[str, Dict[str, Any]] = {}
    rescan_dead_out: Dict[str, Dict[str, int]] = {}
    for x in summaries:
        q = x.get("quarantine_records")
        if isinstance(q, dict):
            quarantine_out[x["output"]] = q
        rd = x.get("rescan_dead_out")
        if isinstance(rd, dict):
            rescan_dead_out[x["output"]] = rd
    for o, v in (prev_quarantine or {}).items():  # 本次没处理的集合原样保留
        quarantine_out.setdefault(o, v)
    for o, v in (prev_rescan_dead or {}).items():
        rescan_dead_out.setdefault(o, v)
    (DIST_DIR / "quarantine-state.json").write_text(
        json.dumps({"version": 1, "updated": dt.date.today().isoformat(),
                    "entries": quarantine_out, "rescan_dead": rescan_dead_out},
                   ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for x in summaries:
        x.pop("state", None)  # build-report 里不放状态，避免膨胀
        x.pop("quarantine_records", None)
        x.pop("rescan_dead_out", None)
    report = DIST_DIR / "build-report.json"
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n完成 {len(summaries)} 个规则集 → {report.relative_to(ROOT)}")
    for s in summaries:
        disc = s.get("discover") or {}
        col = s.get("collapse") or {}
        ver = s.get("verification") or {}
        extra = ""
        if disc.get("enabled"):
            extra = (
                f" | new_suffix={s.get('new_suffix_from_discover', 0)}"
                f" related_apex={disc.get('related_apex', 0)}"
                f" collapse_drop_domain={col.get('domain_dropped', 0)}"
            )
        if ver:
            q = ver.get("quarantine") or {}
            extra += (f" | 隔离:转正{q.get('promoted', 0)}"
                      f"/待审{q.get('pending_review', 0)}/保留{q.get('kept', 0)}")
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
