# sing-box-rules

面向 [sing-box](https://sing-box.sagernet.org/) 的自建分流规则集流水线：在 GitHub Actions 上自动合并上游、发现候选域名、DNS 验证、去重、编译 `.srs`，并按功能分目录发布。

> 仓库：https://github.com/8oneus-oss/sing-box-rules  
> 产物分支：[`rule-set`](https://github.com/8oneus-oss/sing-box-rules/tree/rule-set)  
> 清单：https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json

---

## 这套流水线实际在做什么

```text
合并上游 → CT 发现候选 → DNS 验证新增 → overlays 保底 → 覆盖去重 → 编译发布
```

| 阶段 | 作用 |
|------|------|
| 合并上游 | MetaCubeX ∪ SagerNet，减少单源缺漏 |
| CT 发现 | 用 `seeds/` 查证书透明度；**只保留上游还没有的 apex**（相关域名），不把子域再写成精确 `domain` |
| DNS 验证 | 对新发现的 apex 做解析存活检查 |
| overlays | 人工强制增删（保底） |
| 覆盖去重 | 删掉已被 `domain_suffix` 覆盖的精确 `domain`，以及被更宽 suffix 覆盖的长 suffix |
| 发布 | `geosite/<name>.srs`、`geoip/cn.srs` → `rule-set` 分支 |

**每天北京时间约 07:00** 由 GitHub Actions 云端执行，不需要开着电脑。

---

## 重要说明（避免误解）

1. **条目数变多 ≠ 覆盖变广**  
   若上游已有 `domain_suffix: openai.com`，再收集一千个 `*.openai.com` 子域写进规则集，对 sing-box 分流**几乎没有新增覆盖**。旧版流水线曾把这类子域算进条目数，造成「比官方全很多」的假象；现已去掉这种注水。

2. **真实增量主要来自**  
   - 上游互相补缺（两边并集）  
   - `seeds/` / `overlays/` 里上游还没有的 **apex**（例如某些 AI 相关根域）  
   - CT SAN 上偶尔出现的、且尚未被现有 suffix 覆盖的 **相关根域**

3. **中国大陆域名 / IP**  
   体量过大，当前以合并上游为主，不做全量 CT。

4. **CT / DNS 源不稳定**  
   crt.sh、certspotter 可能 502/限流；当天发现变少时，结果会更接近上游并集。

---

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

完整列表与每次构建统计见 [`index.json`](https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json)。

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
catalog.json           # 构建哪些规则集、上游地址
seeds/                 # 发现用的 apex 种子（有效增量主要靠这里补上游没有的根域）
overlays/              # 人工增删
filters.json           # 全局过滤
coverage.py            # 覆盖去重
discover.py / verify_dns.py / build.py / publish_layout.py
.github/workflows/publish.yml
```

产物在 **`rule-set` 分支**，不在 `main`。

---

## 本地调试

将 `sing-box` 放到 `tools/sing-box` 后：

```bash
python3 build.py
python3 build.py --only ai
python3 build.py --refresh
```

构建日志里关注：

- `discover new_suffix=`：相对上游真正新增的 suffix 数量  
- `collapse ... dropped`：去掉了多少无效重复条目  

---

## 如何扩展

1. 上游缺某个根域：写入 `seeds/<name>.json` 或 `overlays/<name>.json`  
2. 不要指望靠「堆子域条目数」提升覆盖；优先补 **apex / domain_suffix**
