#!/usr/bin/env python3
"""自动发现：基于 seeds，从证书透明度(crt.sh)拉取相关域名。"""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ROOT = Path(__file__).resolve().parent
SEEDS_DIR = ROOT / "seeds"
CACHE_DIR = ROOT / "cache" / "discover"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

DEFAULT_EXCLUDE = (
    "internal",
    "intranet",
    "staging",
    "stg-",
    "dev-",
    "test-",
    "testing",
    "localhost",
    "local.",
    "debug",
    "sandbox",
    "corp.",
    "vpn.",
)


def load_seed_config(output: str) -> Optional[Dict[str, Any]]:
    path = SEEDS_DIR / f"{output}.json"
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _http_get(url: str, timeout: int = 90) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box-ruleset-discover/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        chunks: List[bytes] = []
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def fetch_certspotter(seed: str, cache_dir: Path, refresh: bool = False, max_pages: int = 10) -> List[str]:
    """certspotter 公共 CT API（crt.sh 失败时的兜底）。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"certspotter_{seed.replace('.', '_')}.json"
    if cache_path.exists() and not refresh:
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    names: Set[str] = set()
    after = ""
    try:
        for _ in range(max_pages):
            q = urllib.parse.urlencode(
                {
                    "domain": seed,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                    **({"after": after} if after else {}),
                }
            )
            url = f"https://api.certspotter.com/v1/issuances?{q}"
            raw = _http_get(url, timeout=60)
            rows = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(rows, list) or not rows:
                break
            for row in rows:
                for part in row.get("dns_names") or []:
                    part = str(part).strip().lower().rstrip(".")
                    if part:
                        names.add(part)
            after = str(rows[-1].get("id") or "")
            if len(rows) < 100 or not after:
                break
            time.sleep(0.4)
    except Exception as exc:  # noqa: BLE001
        print(f"    ! certspotter 失败 {seed}: {exc}")
        return []

    result = sorted(names)
    if result:
        cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def fetch_crtsh(seed: str, cache_dir: Path, refresh: bool = False, retries: int = 3) -> List[str]:
    """从 crt.sh 拉 %.seed 的证书名。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"crtsh_{seed.replace('.', '_')}.json"
    if cache_path.exists() and not refresh:
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    q = urllib.parse.quote(f"%.{seed}")
    url = f"https://crt.sh/?q={q}&output=json"
    names: Set[str] = set()
    def ingest_raw(raw: bytes) -> bool:
        if not raw or not raw.strip().startswith(b"["):
            return False
        # 截断响应时尽量截到最后一个完整对象
        text = raw.decode("utf-8", errors="replace").strip()
        if not text.endswith("]"):
            cut = text.rfind("},")
            if cut != -1:
                text = text[: cut + 1] + "]"
            else:
                return False
        rows = json.loads(text)
        for row in rows:
            nv = row.get("name_value") or ""
            for part in str(nv).split("\n"):
                part = part.strip().lower().rstrip(".")
                if part:
                    names.add(part)
        return True

    last_err: Optional[BaseException] = None
    for attempt in range(1, retries + 1):
        try:
            raw = _http_get(url)
            if ingest_raw(raw):
                last_err = None
                break
            print(f"    ! crt.sh 非 JSON，跳过 {seed}")
            return []
        except http.client.IncompleteRead as exc:
            last_err = exc
            partial = getattr(exc, "partial", b"") or b""
            if ingest_raw(partial):
                print(f"    ~ crt.sh 使用部分响应 {seed}: {len(names)} names")
                last_err = None
                break
            print(f"    ! crt.sh 重试 {attempt}/{retries} {seed}: {exc}")
            time.sleep(2 * attempt)
        except Exception as exc:  # noqa: BLE001 - 网络抖动不阻断整条流水线
            last_err = exc
            print(f"    ! crt.sh 重试 {attempt}/{retries} {seed}: {exc}")
            time.sleep(2 * attempt)

    if last_err is not None and not names:
        print(f"    ! crt.sh 放弃 {seed}: {last_err}")
        return []

    result = sorted(names)
    if result:
        cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def normalize_name(name: str, seed: str) -> Optional[str]:
    n = name.strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    if not n or n == seed:
        return seed
    if not n.endswith("." + seed) and n != seed:
        return None
    if not DOMAIN_RE.match(n):
        return None
    return n


def should_exclude(name: str, extra: Iterable[str]) -> bool:
    low = name.lower()
    for kw in list(DEFAULT_EXCLUDE) + list(extra):
        if kw.lower() in low:
            return True
    return False


def discover_for_output(
    output: str,
    refresh: bool = False,
    sleep_between: float = 1.0,
) -> Dict[str, Any]:
    """
    返回 {
      domain_suffix: set(seed apexes),
      domain: set(discovered hosts),
      stats: {...}
    }
    """
    cfg = load_seed_config(output)
    if not cfg:
        return {
            "domain_suffix": set(),
            "domain": set(),
            "stats": {"enabled": False, "seeds": 0, "raw": 0, "kept": 0},
        }

    seeds = [s.strip().lower().rstrip(".") for s in (cfg.get("seeds") or []) if s]
    max_per_seed = int(cfg.get("max_per_seed", 400))
    exclude_extra = cfg.get("exclude_keywords") or []
    sources = cfg.get("sources") or ["crtsh"]

    domain_suffix: Set[str] = set(seeds)
    domain: Set[str] = set()
    raw_total = 0
    kept_total = 0

    for i, seed in enumerate(seeds):
        raw_names: List[str] = []
        got = False
        if "crtsh" in sources:
            print(f"    discover crt.sh %.{seed}")
            crt = fetch_crtsh(seed, CACHE_DIR, refresh=refresh)
            raw_names.extend(crt)
            got = bool(crt)
        if (not got and "certspotter" in sources) or ("certspotter" in sources and "crtsh" not in sources):
            print(f"    discover certspotter {seed}")
            raw_names.extend(fetch_certspotter(seed, CACHE_DIR, refresh=refresh))
        elif not got and "certspotter" not in sources:
            # crt.sh 失败时自动兜底一次
            print(f"    discover certspotter (fallback) {seed}")
            raw_names.extend(fetch_certspotter(seed, CACHE_DIR, refresh=refresh))
        if i + 1 < len(seeds) and sleep_between > 0:
            time.sleep(sleep_between)

        raw_total += len(raw_names)
        kept: List[str] = []
        for name in raw_names:
            n = normalize_name(name, seed)
            if not n:
                continue
            if should_exclude(n, exclude_extra):
                continue
            kept.append(n)

        # 去重后截断：优先短域名（更接近 apex）
        uniq = sorted(set(kept), key=lambda x: (x.count("."), len(x), x))
        if len(uniq) > max_per_seed:
            uniq = uniq[:max_per_seed]
        kept_total += len(uniq)
        for h in uniq:
            if h == seed:
                domain_suffix.add(h)
            else:
                domain.add(h)

    return {
        "domain_suffix": domain_suffix,
        "domain": domain,
        "stats": {
            "enabled": True,
            "seeds": len(seeds),
            "raw": raw_total,
            "kept": kept_total,
            "domain": len(domain),
            "domain_suffix": len(domain_suffix),
        },
    }
