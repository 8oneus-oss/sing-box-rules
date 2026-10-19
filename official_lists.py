#!/usr/bin/env python3
"""厂商官方机器可读域名列表（实现方案 v3.1 §4）。

目前：Microsoft 365 endpoints API。这是唯一"无条件 admit"的来源，
接入新源需人工确认一次（一次性，非日常维护）。
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from typing import Set

_UA = {"User-Agent": "sing-box-ruleset/1.0"}


def _get_json(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def m365_version(timeout: int = 30):
    """取官方版本号，用于缓存失效判断。失败返回 None（不阻断）。"""
    try:
        return _get_json(
            f"https://endpoints.office.com/version/worldwide"
            f"?clientrequestid={uuid.uuid4()}",
            timeout=timeout,
        )
    except Exception:
        return None


def fetch_m365(timeout: int = 60) -> Set[str]:
    """返回 Microsoft 365 官方 endpoint 的 apex 集合（去通配符，作为 domain_suffix 用）。"""
    rows = _get_json(
        f"https://endpoints.office.com/endpoints/worldwide?clientrequestid={uuid.uuid4()}",
        timeout=timeout,
    )
    out: Set[str] = set()
    for row in rows:
        if row.get("category") not in ("Optimize", "Allow", "Default"):
            continue
        for u in row.get("urls") or []:
            u = str(u).strip().lower().lstrip("*").lstrip(".").rstrip(".")
            if u and "." in u:
                out.add(u)
    return out


OFFICIAL_SOURCES = {
    "microsoft": fetch_m365,
}
