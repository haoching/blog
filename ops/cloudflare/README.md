# Cloudflare 上線清單

這份 runbook 是給 `chang929.site` 正式上線使用。所有指令都應在確認帳戶、zone 與資源 ID 後執行；不要把 API token、Tunnel token 或 R2 secret 寫入 Git。

## 1. 部落格 Worker

在 `haoching/blog` 建立兩個 Worker：

- `blog-preview`：`v2` 分支驗收用，使用 `wrangler.jsonc` 的 Workers Static Assets。
- `blog`：`master` 分支正式環境，綁定 `chang929.site` 的 custom domain。

GitHub Actions 只需要一個限制為該帳戶 Workers 部署權限的 API token，以及 `CLOUDFLARE_ACCOUNT_ID`。先手動保存舊 Worker 的設定與 deployment/tag，再讓 workflow 部署。

## 2. DNS 與圖片

確認 zone `chang929.site` 在同一個 Cloudflare account，然後：

1. 建立 R2 bucket `blog-media`。
2. 建立只允許該 bucket 的 R2 S3 access key，填入 `R2_ENDPOINT`、`R2_ACCESS_KEY_ID`、`R2_SECRET_ACCESS_KEY`。
3. 將 R2 custom domain 接到 `media.chang929.site`，設定 Cache Rule／Smart Tiered Cache。
4. 關閉 `r2.dev` public development URL；正式 Markdown 只能使用 `https://media.chang929.site/...`。
5. 確認 `chang929.site` 的 Worker custom domain 已建立；不要用未經驗證的 wildcard route 取代它。

R2 custom domain 與 `r2.dev` 是不同的公開入口；custom domain 才能使用 Cloudflare cache 與 WAF。參考：[R2 public buckets](https://developers.cloudflare.com/r2/buckets/public-buckets/)、[R2 cache](https://developers.cloudflare.com/cache/interaction-cloudflare-products/r2/)。

## 3. 編輯站 Tunnel 與 Access

建立一條 remotely-managed Tunnel，public hostname 指向 `http://reverse_proxy:8080`：

- hostname：`edit.chang929.site`
- origin service：`http://reverse_proxy:8080`
- origin port 不對 WAN 開放，只允許 LXC 本機的 `127.0.0.1:8080`
- 將 Tunnel token 放入 `ops/hedgedoc/.env` 的 `CLOUDFLARE_TUNNEL_TOKEN`

建立 Access application `edit.chang929.site`，Allow policy 只列出指定協作者 Email 或 GitHub identity。Rocket Loader 在此 hostname 停用，避免 HedgeDoc editor／WebSocket 被改寫。Publisher 仍會驗證 `Cf-Access-Jwt-Assertion`，所以 origin 不可直接繞過 Access。

Tunnel 是由 LXC 對外建立 outbound-only 連線，不需要路由器入站 port。參考：[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)、[Tunnel token run](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/)、[Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)。

## 4. 驗收

```bash
curl -fsS https://chang929.site/robots.txt
curl -fsS https://chang929.site/sitemap.xml
curl -I https://media.chang929.site/posts/ais3-2025-writeup/<sha256>.png
curl -fsS https://edit.chang929.site/        # 未通過 Access 時應為 403/登入頁
```

確認 `r2.dev` 不可用、編輯站未列入白名單時拒絕、正式文章與圖片在 LXC 關機後仍可讀取。
