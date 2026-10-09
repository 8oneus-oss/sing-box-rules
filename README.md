# sing-box-rules

自建 sing-box 规则集

## 本地构建

```bash
# 需先准备 tools/sing-box（与客户端同主版本）
python3 build.py
python3 build.py --only youtube ai
python3 build.py --refresh
```
`publish.json` 填入用户名，在上级目录跑：

```bash
python3 patch-template.py
```

模版里的远程规则集 URL 会改成你的 GitHub raw 地址。
