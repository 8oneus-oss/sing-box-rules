# sing-box-rules

自建 sing-box 规则集流水线：

**合并上游 → 自动发现(CT) → 自动验证(DNS) → 叠加 overlays → 过滤 → 生成 `.srs` → 发布 `rule-set` 分支**

客户端 URL：

```
https://raw.githubusercontent.com/8oneus-oss/sing-box-rules/rule-set/<name>.srs
```

## 流水线说明

| 阶段 | 做什么 |
|---|---|
| 合并上游 | MetaCubeX JSON ∪ SagerNet `.srs` |
| 自动发现 | 读 `seeds/*.json`，向 crt.sh 查 `%.seed`，发现子域/相关域名 |
| 自动验证 | 对「新发现 + overlay 新增」做 DNS 存活检查，死域名丢弃 |
| 叠加覆盖 | `overlays/*.json` 人工保底补全/剔除 |
| 过滤 | 规范化、去噪、丢弃非法 regex |
| 生成 | `sing-box rule-set compile` → `.srs` |
| 发布 | GitHub Actions 推到 `rule-set` 分支（每天定时） |

`geolocation-cn` / `geoip-cn` 无 seeds（体量过大），仍走上游合并。

## 本地构建

```bash
# 需 tools/sing-box
python3 build.py                  # 完整：发现+验证+生成
python3 build.py --only ai youtube
python3 build.py --refresh        # 清空 cache，重新拉上游与 CT
python3 build.py --skip-discover  # 仅上游+overlay（调试用）
```

## 维护

- 扩覆盖：改 `seeds/<name>.json` 增加 apex，push 后 Actions 自动发现
- 强行保底：改 `overlays/<name>.json`
- 立刻发布：Actions → Build and publish rule-set → Run workflow
