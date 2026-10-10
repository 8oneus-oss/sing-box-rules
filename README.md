# sing-box-rules

面向 [sing-box](https://sing-box.sagernet.org/) 的**自建分流规则集**：在 GitHub Actions 上自动合并上游、发现新域名、DNS 验证、编译 `.srs`，并按功能分目录发布，供客户端远程引用。

> 仓库：https://github.com/8oneus-oss/sing-box-rules  
> 产物分支：[`rule-set`](https://github.com/8oneus-oss/sing-box-rules/tree/rule-set)  
> 清单：https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json

---

## 解决什么问题

官方 / 社区 geosite、geoip 更新常滞后，单一上游覆盖不全。本项目把「收集 → 验证 → 生成 → 发布」做成云端流水线：

- **不依赖你的电脑**：每天由 GitHub Actions 云端执行
- **每个功能独立 URL**：YouTube、AI、GitHub、交易所等各自一个 `.srs`
- **比纯上游更全**：上游并集 + 证书透明度(CT)发现 + 人工 overlay 保底
- **有质量门槛**：新发现域名先做 DNS 存活检查，再写入规则集

---

## 架构（一眼看懂）

```text
┌─────────────────────────────────────────────────────────┐
│  GitHub Actions（每天北京时间 ≈ 07:00，也可手动/push 触发） │
└─────────────────────────────────────────────────────────┘
        │
        ▼
 1. 合并上游          MetaCubeX JSON  ∪  SagerNet .srs
 2. 自动发现          seeds/*.json → crt.sh / certspotter（CT）
 3. 自动验证          对新发现域名做 DNS 解析存活检查
 4. 人工保底          overlays/*.json 增删
 5. 过滤整理          规范化、去噪、丢弃非法 regex
 6. 编译              sing-box rule-set compile → .srs
 7. 发布              推送到 rule-set 分支（geosite/ + geoip/）
        │
        ▼
 客户端 remote rule_set（update_interval ≈ 1d）按需拉取
```

| 角色 | 做什么 | 是否需要开电脑 |
|------|--------|----------------|
| GitHub Actions | 发现 / 验证 / 生成 / 发布 | 否 |
| sing-box 客户端 | 按 `update_interval` 下载已发布的 `.srs` | 仅使用客户端时 |

---

## 已发布规则集 URL

基础前缀：

```text
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/
```

| 功能 | 路径 | 条目数（近期） |
|------|------|----------------|
| YouTube | `geosite/youtube.srs` | ~184 |
| 谷歌美国 | `geosite/google.srs` | ~1208 |
| AI服务 | `geosite/ai.srs` | ~835 |
| Meta | `geosite/meta.srs` | ~988 |
| Apple | `geosite/apple.srs` | ~2321 |
| GitHub | `geosite/github.srs` | ~430 |
| Microsoft | `geosite/microsoft.srs` | ~2075 |
| Twitter | `geosite/twitter.srs` | ~76 |
| Binance | `geosite/binance.srs` | ~90 |
| Bybit | `geosite/bybit.srs` | ~38 |
| OKX | `geosite/okx.srs` | ~68 |
| Gate.io | `geosite/gateio.srs` | ~24 |
| 中国大陆域名 | `geosite/geolocation-cn.srs` | ~9309 |
| 中国大陆IP | `geoip/cn.srs` | ~10712 |

完整列表与每次构建统计见 [`index.json`](https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json)。

### 在 sing-box 配置里引用（示例）

```json
{
  "tag": "AI服务",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geosite/ai.srs",
  "update_interval": "1d"
}
```

---

## 仓库结构

```text
sing-box-rules/
├── catalog.json          # 要构建哪些规则集、上游地址
├── seeds/                # 自动发现用的 apex 种子域名
├── overlays/             # 人工增删（保底补全）
├── filters.json          # 全局过滤规则
├── build.py              # 主流水线：合并→发现→验证→生成
├── discover.py           # CT 发现（crt.sh / certspotter）
├── verify_dns.py         # DNS 存活验证
├── publish_layout.py     # 按 geosite/ geoip/ 整理发布树
├── patch-template.py     # 可选：批量改本地模版 URL
└── .github/workflows/
    └── publish.yml       # 定时构建并推送到 rule-set 分支
```

产物在 **`rule-set` 分支**（不在 `main`），避免源码与二进制混在一起。

---

## 定时与触发

| 触发 | 时机 |
|------|------|
| `schedule` | 每天 **北京时间约 07:00**（UTC 23:00） |
| `push` | 改动 `seeds/`、`overlays/`、`build.py` 等后推送到 `main` |
| `workflow_dispatch` | Actions 页面手动 Run workflow |

查看运行记录：https://github.com/8oneus-oss/sing-box-rules/actions

---

## 和「纯上游」有何不同

生成结果 **不是** 上游文件原样拷贝，而是：

```text
上游并集 + CT 新发现（经 DNS 验证）+ overlays − 过滤丢弃项
```

例如 AI 类规则集，上游约两百条量级，发布后可达八百+（随每日发现波动）。

说明与局限：

- CT 源（crt.sh 等）偶发 502/限流时，当天发现会变少，结果更接近上游
- DNS 验证主要针对**新发现**域名；上游条目默认保留
- `geolocation-cn` / `geoip` 体量过大，当前以合并上游为主，不做全量 CT
- GitHub schedule 偶有延迟；仓库长期无活动时，定时任务可能被平台暂停

---

## 本地构建（开发 / 调试）

需要本机有与线上一致主版本的 `sing-box`，放到 `tools/sing-box`：

```bash
git clone https://github.com/8oneus-oss/sing-box-rules.git
cd sing-box-rules

# 下载 sing-box 到 tools/ 后：
python3 build.py                  # 完整流水线
python3 build.py --only ai github # 只构建指定集
python3 build.py --refresh        # 清空 cache 重拉
python3 publish_layout.py         # 预览分目录发布树
```

---

## 如何扩展覆盖

1. **加发现范围**：编辑 `seeds/<name>.json`，增加 apex 域名后 push  
2. **强制保底**：编辑 `overlays/<name>.json` 的 `add` / `remove`  
3. **新规则集**：在 `catalog.json` 增加条目，并补对应 `seeds/`（可选）

---

## License / 使用注意

- 上游数据来自 MetaCubeX、SagerNet 等公开规则源，以及公共 CT / DNS
- 规则集按「尽力覆盖」维护，不保证绝对完整或实时
- 可直接在自有 sing-box 配置中引用上述 raw URL；Fork 后请改 `publish.json` 与 Actions 目标仓库
