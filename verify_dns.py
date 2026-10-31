#!/usr/bin/env python3
"""自动验证：DNS 解析存活检查（并发）。"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Set, Tuple


def resolves(host: str, timeout: float = 3.0) -> bool:
    del timeout  # getaddrinfo 超时由系统解析器控制，避免修改全局 socket 默认超时引发多线程竞态
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


def verify_hosts(
    hosts: Iterable[str],
    workers: int = 32,
    timeout: float = 3.0,
) -> Tuple[Set[str], Set[str]]:
    alive: Set[str] = set()
    dead: Set[str] = set()

    clean = [h.strip().lower().rstrip(".") for h in hosts if h and h.strip()]
    if not clean:
        return alive, dead

    with ThreadPoolExecutor(max_workers=workers) as ex:
        f2h = {ex.submit(resolves, h, timeout): h for h in clean}
        for f in as_completed(f2h):
            h = f2h[f]
            try:
                if f.result():
                    alive.add(h)
                else:
                    dead.add(h)
            except Exception:
                dead.add(h)

    return alive, dead