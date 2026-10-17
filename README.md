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
合并主上游 → 补充上游（过滤后按白名单并入）→ 种子 → overlays → 覆盖去重
  → 上游缩水保护 → 编译 → 加载校验 → 发布前样本检查 → 发布
```

| 阶段 | 作用 |
|------|------|
| 主上游 | MetaCubeX ∪ SagerNet（`catalog.json`），取并集 |
| 补充上游 | v2fly 原始域名表、blackmatrix7（`role: supplement`），**默认只并入 `supplement_allow.json` 白名单里的条目**。先过 `blacklist.json`（共享 CDN/通用第三方），再丢弃与其它集合重叠的条目，补充来源之间互相重叠的两边都丢 |
| 种子 | `seeds/<name>.json` 里的主域名一律作为 `domain_suffix`（上游缺这些根域，才是有效增量）；上游没有的种子会做 DNS 存活检查 |
| overlays | 人工强制增删，最高优先级，在自动发现之后应用 |
| 覆盖去重 | 删掉已被 `domain_suffix` 覆盖的精确 `domain` 和冗余长 suffix，匹配结果不变 |
| 上游缩水保护 | 配置的上游全部失败，或合并后的条目数比上次发布低于 80%，本次构建失败，**不发布** |
| 加载校验 | 每个 `.srs` 用 `sing-box check` + `decompile` 校验 |
| 样本检查 | `check_samples.py` 按 `samples.json` 检查"该命中的命中、不该命中的不命中"，任何一条不符就停止发布 |

每天北京时间约 07:00 自动构建；构建超过 90 分钟会被终止且**不发布**，客户端继续用上一次的版本。同一时间只允许一个构建。

## 重要说明

1. **条目数多 ≠ 覆盖广。** 已有 `domain_suffix: openai.com` 时，再加一千个 `*.openai.com` 子域不增加覆盖，本仓库不做这种注水。
2. **「相关域名」自动发现默认关闭。** 证书透明度里「和种子出现在同一张证书上」不代表是同一家，曾经混进大量仿冒域名（如 `porno--x.com`、`www--binance.com`）。需要给某个集合开启时，在它的种子文件里显式写 `"max_related_apex": 正整数`；开启时会过滤双连字符和国际化域名，并丢弃与其它集合重叠的条目。关闭时构建**不会联网查证书**。
3. **补充上游噪音大。** blackmatrix7 会把厂商网站依赖的第三方服务（如 Stripe、Sentry、Auth0）一并列入，所以只并入白名单。要放开某条，加进 `supplement_allow.json`；`catalog.json` 里 `supplement_mode` 改成 `auto` 则全量并入（不建议）。
4. **中国大陆域名 / IP** 体量大，以合并上游为主，不做补充。
5. 累积状态 `state/discovered.json`：仅在某集合开启了相关域名发现时才使用（近 30 天发现过的域名在证书查询偶尔失败时保留）；全部关闭时为空。

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
catalog.json            构建哪些规则集、上游地址、supplement_mode
seeds/                  种子主域名（有效增量主要靠这里）
overlays/               人工增删（add / remove）
blacklist.json          补充上游的共享基础设施黑名单
supplement_allow.json   补充上游白名单
samples.json            发布前样本清单（must_hit / must_not_hit）
filters.json            全局过滤
build.py                主构建；coverage.py 覆盖去重；discover.py 种子/相关域名发现
verify_dns.py           DNS 存活检查；check_samples.py 样本检查；publish_layout.py 发布目录
.github/workflows/publish.yml
```

产物在 `rule-set` 分支，不在 `main`。

## 如何扩展

| 想做的事 | 改哪里 |
|---|---|
| 上游缺某个厂商根域 | `seeds/<name>.json` 的 `seeds` |
| 强制加入 / 删除某个域名 | `overlays/<name>.json` 的 `add` / `remove` |
| 放开某个补充来源的条目 | `supplement_allow.json` |
| 某个域名走错出口 | 往 `samples.json` 加一行，防止以后回归 |

改 `seeds/`、`overlays/`、`blacklist.json`、`supplement_allow.json`、`catalog.json` 等会自动触发构建。

## 本地调试

把 `sing-box` 放到 `tools/sing-box` 后：

```bash
python3 build.py --skip-dns-verify
python3 build.py --only ai
python3 check_samples.py
```

## 已知局限

- 官方更新是否滞后，没有长期数据证明；目前能确认的是：官方条目 0 丢失，另有一批官方没有的域名被接住。
- 自动发现新域名的能力有限：精度优先，宁可漏收也不错收。
- 发布分支每次整体覆盖，没有历史版本可回滚。
