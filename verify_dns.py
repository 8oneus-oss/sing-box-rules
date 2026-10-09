#!/usr/bin/env python3
"""自动验证：DNS 解析存活检查（并发）。"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Set, Tuple


def resolves(host: str, timeout: float = 3.0) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
    finally:
        socket.setdefaulttimeout(old)


def verify_hosts(
    hosts: Iterable[str],
    workers: int = 32,
    timeout: float = 3.0,
) -> Tuple[Set[str], Set[str]]:
    """返回 (alive, dead)。"""
    uniq = sorted({h.strip().lower().rstrip(".") for h in hosts if h and h.strip()})
    alive: Set[str] = set()
    dead: Set[str] = set()
    if not uniq:
        return alive, dead

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(resolves, h, timeout): h for h in uniq}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                ok = fut.result()
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                alive.add(h)
            else:
                dead.add(h)
    return alive, dead


def summarize(alive: Set[str], dead: Set[str]) -> Dict[str, int]:
    return {"checked": len(alive) + len(dead), "alive": len(alive), "dead": len(dead)}
