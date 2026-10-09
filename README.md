# sing-box-rules

自建 sing-box 规则集流水线：

**合并上游 → 自动发现(CT) → 自动验证(DNS) → overlays → 过滤 → 生成 → 按功能分目录发布**

## 客户端 URL（每个功能一个独立地址）

仓库只有一个，但发布在 `rule-set` 分支时按功能分目录：

```text
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geosite/youtube.srs
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geosite/ai.srs
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geosite/github.srs
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/geoip/cn.srs
...
```

清单：[rule-set/index.json](https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/index.json)

| 目录 | 内容 |
|---|---|
| `geosite/` | YouTube / AI / Google / Meta / Apple / GitHub / Microsoft / Twitter / 交易所 / 中国大陆域名 |
| `geoip/` | 中国大陆 IP（`cn.srs`） |

## 流水线

| 阶段 | 做什么 |
|---|---|
| 合并上游 | MetaCubeX ∪ SagerNet |
| 自动发现 | `seeds/*.json` → crt.sh / certspotter |
| 自动验证 | 新发现域名 DNS 存活检查 |
| 叠加覆盖 | `overlays/*.json` |
| 生成发布 | 编译 `.srs`，按 `geosite/` `geoip/` 推到 `rule-set` |

每天北京时间约 07:00（UTC 23:00）自动跑；改 `seeds/` / `overlays/` 后 push 也会触发。

## 本地

```bash
python3 build.py
python3 publish_layout.py   # 查看分目录发布树
python3 patch-template.py   # 更新上级模版 URL
```
