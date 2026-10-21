# 手写域名清单（人工维护）

这些清单原先写在 sing-box 模板的内联规则里，现在统一放在本目录的 overlay 文件中，由构建流水线编译成规则集发布。
改清单：直接编辑对应的 `<输出名>.json` 的 `add.domain_suffix`，提交后下一次构建自动发布，客户端按更新周期自动拉取，不需要改模板、不需要重新导入。

> 这几个清单**只允许人工维护，不做自动发现**（没有对应的 `seeds/` 文件）。金融类域名宁缺毋滥。

| 文件 | 规则集 tag | 模板里对应的出口 |
|---|---|---|
| `us-domains.json` | 美国域名 | 🇺🇸 美国 ISP |
| `sg-domains.json` | 新加坡域名 | 🇸🇬 新加坡 ISP |
| `us-cdn.json` | 美国大流量CDN | US（普通美国节点，不走 ISP） |
| `dl-direct.json` | 苹果微软下载直连 | CN（直连） |

规则的先后顺序仍由模板里的 `route.rules` 决定，**不要在模板里调整这些规则的顺序**：美国大流量CDN 与 Meta、YouTube、Google、Twitter 有少量重叠，下载直连与 Apple、Microsoft、大陆域名有少量重叠，走向靠顺序决定。

## 原模板里的分类注释（迁移时保留）

### 美国域名（us-domains）

| 分类 | 域名 |
|---|---|
| Ally 银行 | `ally.com`, `allybank.com` |
| 运通卡 | `aexp-static.com`, `americanexpress.com` |
| 美国银行 | `bankofamerica.com`, `merrilledge.com`, `ml.com` |
| Braintree | `braintree-api.com`, `braintreegateway.com`, `braintreepayments.com` |
| Capital One | `capitalone.com`, `capitalone360.com` |
| Cash App / Square | `cash.app`, `squarecdn.com`, `squareup.com`, `issquareup.com`, `cash.me`, `squarecloudservices.com`, `square.site` |
| Chase 银行 | `chase.com` |
| 花旗银行 | `citi.com`, `citibank.com` |
| Discover 卡 | `discover.com` |
| 富达投资 | `fidelity.com` |
| IBKR 券商 | `ibkr.com`, `interactivebrokers.com` |
| 美国身份校验 | `id.me` |
| 美国国税局 | `irs.gov` |
| Stripe / Link | `link.co`, `link.com`, `stripe.com`, `stripe.network`, `stripeassets.com`, `stripecdn.com` |
| PayPal | `paypal-corp.com`, `paypal.com`, `paypal.me`, `paypalobjects.com`, `py.pl`, `venmo.com`, `venmopayments.com` |
| Plaid | `plaid.com`, `plaidcdn.com` |
| PNC 银行 | `pnc.com` |
| 嘉信理财 | `schwab.com` |
| Talkatone | `talkatone.com`, `tktn.at`, `tktn.be`, `tktn.us` |
| 合众银行 | `usbank.com` |
| 富国银行 | `wellsfargo.com`, `wellsfargoadvisors.com` |
| Zelle 支付 | `earlywarning.com`, `zelle.com`, `zellepay.com` |

### 新加坡域名（sg-domains）

| 分类 | 域名 |
|---|---|
| 星展银行 | `dbs.com`, `dbs.com.sg`, `posb.com.sg` |
| iFAST / FSMOne | `fsmone.com`, `fsmone.com.sg`, `ifastgb.com`, `ifastgm.com.sg` |
| 老虎证券 | `itiger.com`, `tigerbrokers.com.sg` |
| 富途牛牛 | `moomoo.com`, `moomoo.sg` |
| 华侨银行 | `ocbc.com`, `ocbc.com.sg` |
| Wise | `transferwise.com`, `wise.com` |
| 大华银行 | `uob.com`, `uob.com.sg` |
| 盈立证券 | `usmart.com`, `usmart.sg` |

