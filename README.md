# sing-box-rules

自建 sing-box 规则集：合并 MetaCubeX + SagerNet → 叠加 overlays → 过滤 → 编译 `.srs` → 发布到 `rule-set` 分支。

## 客户端 URL

```
https://raw.githubusercontent.com/<你的用户名>/sing-box-rules/rule-set/<name>.srs
```

例如：`youtube.srs`、`ai.srs`、`geolocation-cn.srs`、`geoip-cn.srs`。清单见同分支 `index.json`。

## 本地构建

```bash
# 需先准备 tools/sing-box（与客户端同主版本）
python3 build.py
python3 build.py --only youtube ai
python3 build.py --refresh
```

## 发布到 GitHub

1. 在 GitHub 新建**公开**仓库 `sing-box-rules`（raw 拉取需要 public）
2. 把本目录推上去：

```bash
cd ruleset
git init -b main
git add .
git commit -m "feat: ruleset pipeline"
git remote add origin git@github.com:<你的用户名>/sing-box-rules.git
git push -u origin main
```

3. 打开 Actions，手动跑一次 **Build and publish rule-set**，或等定时任务
4. 编辑 `publish.json` 填入用户名，在上级目录跑：

```bash
python3 patch-template.py
```

模版里的远程规则集 URL 会改成你的 GitHub raw 地址。
