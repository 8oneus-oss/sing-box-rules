# sing-box-rules

面向 [sing-box](https://sing-box.sagernet.org/) 的自建分流规则集流水线：每天在 GitHub Actions 上合并多个上游、过滤、去重、校验、编译 `.srs`，并按功能分目录发布。

> 仓库：https://github.com/8oneus-oss/sing-box-rules  
> 产物分支：[`rule-set`](https://github.com/8oneus-oss/sing-box-rules/tree/rule-set)  
> 清单：https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json

---

## 目标

官方 sing-geosite 更新慢、覆盖不全，导致有的域名没走到该走的出口。本仓库在**不丢失官方任何条目**的前提下，补上官方没收录的域名，并保证每一条新增都有来历。

## 流水线

```text
合并主上游 → 补充上游（验证电池）→ 官方源（M365）→ 种子 → CT 自动发现（验证电池）
  → 隔离区（quarantine/pending_review）→ overlays → 覆盖去重
  → 上游缩水保护 → 上游新条目检查 → 存量抽查复验 → 编译 → 加载校验 → 发布前样本检查 → 发布
```

| 阶段 | 作用 |
|------|------|
| 主上游 | MetaCubeX ∪ SagerNet（`catalog.json`），取并集，**官方 0 丢失** |
| 补充上游 | v2fly、blackmatrix7、SukkaW/Surge（`role: supplement`），**走验证电池**：仿冒筛查硬拒绝；通过的进隔离区观察；品牌相关但无法验证的进待审（永不自动放行）。先过 `blacklist.json`（共享 CDN/通用第三方），再丢弃与其它集合重叠的条目 |
| 官方源 | Microsoft 365 endpoints API（`official_lists.py`），唯一无条件放行的第三方来源 |
| 种子 | `seeds/<name>.json` 里的主域名一律作为 `domain_suffix` 直接并入（人工意图，不走验证）；上游没有的种子会做 DNS 存活检查 |
| CT 自动发现 | 默认开启（上限 500/集合，`verify.json: discover_default_max_related`）：证书透明度里与种子同证书的其它 apex，全部走验证电池；`youtube`/`microsoft` 显式关闭（`max_related_apex: 0`，CT 噪音太大） |
| 隔离区 | `state/quarantine.json`：连续 7 天通过验证 → 自动转正；连续 7 天 DNS 死亡或触发仿冒 → 丢弃；`pending_review` 永不自动转正 |
| overlays | 人工强制增删，**最高优先级**（高于验证电池），在隔离区之后应用 |
| 覆盖去重 | 删掉已被 `domain_suffix` 覆盖的精确 `domain` 和冗余长 suffix，匹配结果不变 |
| 上游缩水保护 | 配置的上游全部失败，或合并后的条目数比上次发布低于 80%，本次构建失败，**不发布** |
| 上游新条目检查 | 与上次发布 diff，新增条目过仿冒筛查 + DNS（默认只报告，`upstream_check_mode`） |
| 存量抽查复验 | 每天抽查已发布条目（5%/50 个），DNS 死亡的进隔离区 |
| 加载校验 | 每个 `.srs` 用 `sing-box check` + `decompile` 校验 |
| 样本检查 | `check_samples.py` 按 `samples.json` 检查"该命中的命中、不该命中的不命中"，外加"验证隔离/待审/拒绝的条目不得出现在产物中"（人工 overlay 豁免）+"人工 overlay 的每一条必须出现在产物中"（`overlay_must_hit`，防手写清单被误删）；任何一条不符就停止发布 |

`verify.json` 的 `dry_run: true` 时为观察模式：验证决策只记录进 `build-report.json`，不改变发布内容。

每天北京时间约 07:00 自动构建；构建超过 90 分钟会被终止且**不发布**，客户端继续用上一次的版本。同一时间只允许一个构建。

## 重要说明

1. **条目数多 ≠ 覆盖广。** 已有 `domain_suffix: openai.com` 时，再加一千个 `*.openai.com` 子域不增加覆盖，本仓库不做这种注水。
2. **「相关域名」自动发现默认开启**（上限 500/集合）：证书透明度里与种子同证书的其它 apex 会被抓出来，但**全部走验证电池**——仿冒的直接拒绝，可疑的进隔离区观察 7 天，品牌相关但无法验证的永久待审。精度由验证层保证，不再靠"默认关闭"来保。`youtube`/`microsoft` 显式关闭（CT 噪音太大）。发现缓存 7 天 TTL，不会每次构建都打 CT API。
3. **补充上游走验证，不再是纯白名单。** v2fly、blackmatrix7、SukkaW/Surge 的新增条目先过仿冒筛查 + DNS，通过的进隔离区观察。`supplement_allow.json` 已降级为**人工 override**（最高优先级，写进去的直接放行）。
4. **中国大陆域名 / IP** 体量大，以合并上游为主，不做补充。
5. 累积状态：`state/discovered.json`（发现历史）；`state/quarantine.json`（隔离区：候选、连续通过天数、待审），随产物一起发布到 `rule-set` 分支的 `state/` 目录。
6. **验证的取舍**：验证电池是"宁可错杀不可放过"（精确率优先），合法新域名可能被隔离几天；`pending_review` 里的是机器拿不准的，需要人看一眼。阈值都在 `verify.json` 里，不用改代码。

## 客户端 URL

前缀：

```text
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/
```

| 功能 | 路径 |
|------|------|
| YouTube | `geosite/youtube.srs` |
| 谷歌美国 | `geosite/google.srs` |
| AI服务 | `geosite/ai.srs` |
| Meta / Apple / GitHub / Microsoft / Twitter | `geosite/<name>.srs` |
| Binance / Bybit / OKX / Gate.io | `geosite/<name>.srs` |
| 中国大陆域名 | `geosite/geolocation-cn.srs` |
| 中国大陆IP | `geoip/cn.srs` |
| 美国域名（人工） | `geosite/us-domains.srs` |
| 新加坡域名（人工） | `geosite/sg-domains.srs` |
| 美国大流量CDN（人工） | `geosite/us-cdn.srs` |
| 苹果微软下载直连（人工） | `geosite/dl-direct.srs` |

> 人工清单（us-domains/sg-domains/us-cdn/dl-direct）只允许人工维护，不做自动发现；其中 us-cdn 与 Meta/Twitter、dl-direct 与 Apple/Microsoft/大陆域名有少量重叠，走向靠你 sing-box 模板里的规则顺序决定。

```json
{
  "tag": "AI服务",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geosite/ai.srs",
  "update_interval": "1d"
}
```

## 仓库结构

```text
catalog.json            构建哪些规则集、上游地址（role: supplement 为补充上游）
verify.json             验证电池阈值（隔离天数、dry_run 开关等），改阈值不用改代码
seeds/                  种子主域名（直接并入，人工意图）
overlays/               人工增删（add / remove），最高优先级；us-domains/sg-domains/us-cdn/dl-direct 四个纯人工清单也在此目录（详见 overlays/README.md）
blacklist.json          补充上游的共享基础设施黑名单
supplement_allow.json   人工 override（直接放行，最高优先级）
samples.json            发布前样本清单（must_hit / must_not_hit）
filters.json            全局过滤
build.py                主构建；coverage.py 覆盖去重；discover.py 种子/相关域名发现
verify.py               验证电池（仿冒筛查/待审判定）；verify_dns.py DNS 存活检查
official_lists.py       官方源（M365 endpoints）
check_samples.py        样本检查；publish_layout.py 发布目录
test_verify.py          验证电池单元测试
.github/workflows/publish.yml
```

产物在 `rule-set` 分支，不在 `main`。

## 如何扩展

| 想做的事 | 改哪里 |
|---|---|
| 上游缺某个厂商根域 | `seeds/<name>.json` 的 `seeds` |
| 强制加入 / 删除某个域名 | `overlays/<name>.json` 的 `add` / `remove` |
| 改四个纯人工清单（美/新/CDN/下载直连） | 直接编辑 `overlays/us-domains.json` 等的 `add.domain_suffix`（详见 `overlays/README.md`），金融类宁缺毋滥 |
| 放行某个被隔离/待审的条目 | `supplement_allow.json`（人工 override，直接放行） |
| 调验证严格程度 | `verify.json` 的阈值（隔离天数、仿冒距离等） |
| 关掉观察模式正式启用 | `verify.json` 的 `dry_run` 改 `false` |
| 某个域名走错出口 | 往 `samples.json` 加一行，防止以后回归 |

改 `seeds/`、`overlays/`、`blacklist.json`、`supplement_allow.json`、`catalog.json`、`verify.json` 等会自动触发构建。

## 本地调试

把 `sing-box` 放到 `tools/sing-box` 后：

```bash
python3 build.py --skip-dns-verify
python3 build.py --only ai
python3 check_samples.py
```

## 已知局限

- 官方更新是否滞后，没有长期数据证明；目前能确认的是：官方条目 0 丢失，另有一批官方没有的域名被接住。
- 验证电池是精确率优先：合法新域名可能被隔离几天才转正；`pending_review` 需要人工看。自动验证回答"像不像这家厂商"，回答不了"该不该走这个出口"——那是你的 sing-box 配置（规则顺序）决定的，本仓库不提供配置。
- 发布分支每次整体覆盖，没有历史版本可回滚（回滚方案待定）。
- 上游（MetaCubeX/SagerNet/v2fly/blackmatrix7/SukkaW）和证书透明度 API 的质量、稳定性不在本仓库控制内。
