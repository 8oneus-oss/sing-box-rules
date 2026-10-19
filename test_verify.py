#!/usr/bin/env python3
"""verify.py 单元测试：仿冒筛查 / 待审判定 / verify_candidate 决策。

运行：python3 test_verify.py
DNS 相关用 check_dns=False 跳过（纯逻辑测试）。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify import impersonation_screen, needs_human_review, verify_candidate

KW = ("login", "verify", "secure", "account", "wallet", "support",
      "update", "signin", "auth", "password", "airdrop", "bonus")
BINANCE_SLD = {"binance", "bnb"}
BINANCE_TLD = {"com", "me", "us", "uk"}

FAILURES = []


def check(name, got, want):
    ok = got == want
    if not ok:
        FAILURES.append(f"{name}: got={got!r} want={want!r}")
    print(("PASS " if ok else "FAIL ") + name)


def scr(apex):
    return impersonation_screen(apex, "binance", BINANCE_SLD, KW, 2)


# --- 仿冒筛查：应拒绝 ---
for d in ["binance-login.com", "www--binance.com", "secure-binance.net",
          "bnance.com",  # typosquat（编辑距离 1）
          "xn--binance.com", "binance--secure.com",
          "login-binance.com",
          ]:
    check(f"reject {d}", scr(d) is not None, True)

# 已知局限：品牌+关键词连写无分隔符（如 binancewallet.com）筛查不到，
# 这类靠隔离期 + 待审的人工 glance 兜底
check("limitation binancewallet.com", scr("binancewallet.com"), None)

# --- 仿冒筛查：应放行（无问题返回 None） ---
for d in ["binance.com", "binance.bh", "safu.im", "api.binance.com",
          "bnbstatic.com", "binancefuture.com"]:
    check(f"pass-screen {d}", scr(d), None)

# --- 待审判定 ---
check("review binance-bh.com", needs_human_review("binance-bh.com", "binance", BINANCE_SLD, BINANCE_TLD), True)
check("review binance.cm", needs_human_review("binance.cm", "binance", BINANCE_SLD, BINANCE_TLD), True)
check("review mybinance.com", needs_human_review("mybinance.com", "binance", BINANCE_SLD, BINANCE_TLD), True)
check("no-review safu.im", needs_human_review("safu.im", "binance", BINANCE_SLD, BINANCE_TLD), False)
check("no-review binance.com", needs_human_review("binance.com", "binance", BINANCE_SLD, BINANCE_TLD), False)


def ctx(**kw):
    base = {"brand": "binance", "known_slds": BINANCE_SLD, "known_tlds": BINANCE_TLD,
            "keywords": KW, "max_distance": 2, "official": set(), "check_dns": False}
    base.update(kw)
    return base


# --- verify_candidate 决策（DNS 跳过） ---
d, _ = verify_candidate("binance-login.com", ctx())
check("candidate reject", d, "reject")

d, _ = verify_candidate("office.com", ctx(official={"office.com"}))
check("candidate official admit", d, "admit")

d, _ = verify_candidate("binance-bh.com", ctx())
check("candidate pending_review", d, "pending_review")

d, _ = verify_candidate("safu.im", ctx())
check("candidate quarantine", d, "quarantine")

print()
if FAILURES:
    print(f"{len(FAILURES)} 失败：")
    for f in FAILURES:
        print("  ✗", f)
    sys.exit(1)
print("全部通过。")
