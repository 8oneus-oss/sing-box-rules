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

# --- check_samples：转正竞态与可信来源裁决 ---
import json as _json
import tempfile as _tempfile

from check_samples import covered_by_suffix, promoted_apex, report_bad_entries

check("suffix exact", covered_by_suffix("a.com", {"a.com"}), True)
check("suffix covered", covered_by_suffix("x.a.com", {"a.com"}), True)
check("suffix no partial-label", covered_by_suffix("onmicrosoft.com", {"microsoft.com"}), False)
check("suffix empty", covered_by_suffix("a.com", set()), False)


def _ver(discover=None, supplement=None, trusted=None, dry_run=False):
    return {"dry_run": dry_run,
            "discover": discover or {"reject": [], "quarantine": [], "pending_review": []},
            "supplement": supplement or {"reject": [], "quarantine": [], "pending_review": []},
            "trusted": trusted or {"domain": [], "domain_suffix": []}}


# 转正竞态：discover-quarantine + 本轮转正 → 排除；discover-reject + 转正 → 保留（真冲突必报）
check("race discover-quarantine promoted excluded",
      report_bad_entries(_ver(discover={"reject": [], "quarantine": ["promoted.com"], "pending_review": []}),
                         set(), {"promoted.com"}), [])
check("race discover-reject promoted kept",
      report_bad_entries(_ver(discover={"reject": ["promoted.com"], "quarantine": [], "pending_review": []}),
                         set(), {"promoted.com"}), [("reject", "promoted.com")])
check("race supplement-quarantine promoted excluded",
      report_bad_entries(_ver(supplement={"reject": [], "quarantine": ["promoted.com"], "pending_review": []}),
                         set(), {"promoted.com"}), [])
# 可信来源：supplement-reject 被 trusted 精确覆盖 → 排除；supplement-quarantine 被后缀覆盖 → 排除
check("trusted exact covers supplement-reject",
      report_bad_entries(_ver(supplement={"reject": ["t.com"], "quarantine": [], "pending_review": []},
                              trusted={"domain": ["t.com"], "domain_suffix": []}),
                         set(), set()), [])
check("trusted suffix covers supplement-quarantine",
      report_bad_entries(_ver(supplement={"reject": [], "quarantine": ["x.trusted.com"], "pending_review": []},
                              trusted={"domain": [], "domain_suffix": ["trusted.com"]}),
                         set(), set()), [])
# 旧行为保留：普通 bad 保留、human_added 排除、dry_run 跳过 supplement
check("plain bad kept",
      report_bad_entries(_ver(discover={"reject": ["bad.com"], "quarantine": [], "pending_review": []}),
                         set(), set()), [("reject", "bad.com")])
check("human_added excluded",
      report_bad_entries(_ver(discover={"reject": ["bad.com"], "quarantine": [], "pending_review": []}),
                         {"bad.com"}, set()), [])
check("dry_run skips supplement",
      report_bad_entries(_ver(supplement={"reject": ["s.com"], "quarantine": [], "pending_review": []},
                              dry_run=True),
                         set(), set()), [])
# promoted_apex：读文件 + 归一化；缺失为空集
with _tempfile.TemporaryDirectory() as td:
    _p = Path(td) / "promoted-x.json"
    _p.write_text(_json.dumps(["  Foo.COM.", "bar.com"]), encoding="utf-8")
    check("promoted_apex normalizes", promoted_apex(Path(td), "x"), {"foo.com", "bar.com"})
    check("promoted_apex missing empty", promoted_apex(Path(td), "y"), set())

# rescan 抽查池豁免 overlay（squarecloudservices.com 案）：人工意图不进池
from build import rescan_pool
_f = {"domain": {"a.com"}, "domain_suffix": {"squarecloudservices.com", "other.org"}}
check("rescan pool excludes overlay suffix", rescan_pool(_f, set(), set(), {"squarecloudservices.com"}), ["a.com", "other.org"])
check("rescan pool excludes overlay domain", rescan_pool({"domain": {"x.com"}, "domain_suffix": set()}, set(), set(), {"x.com"}), [])
check("rescan pool keeps non-overlay", rescan_pool(_f, set(), set(), set()), ["a.com", "other.org", "squarecloudservices.com"])
check("rescan pool keeps seeds/official exclusion", rescan_pool(_f, {"a.com"}, {"other.org"}, set()), ["squarecloudservices.com"])
check("rescan pool normalizes overlay add", rescan_pool(_f, set(), set(), {"  SquareCloudServices.COM."}), ["a.com", "other.org"])

print()
if FAILURES:
    print(f"{len(FAILURES)} 失败：")
    for f in FAILURES:
        print("  ✗", f)
    sys.exit(1)
print("全部通过。")
