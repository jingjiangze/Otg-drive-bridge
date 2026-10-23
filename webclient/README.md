# webclient — OTG Drive Bridge 的 Web 实例站

部署在 `otg.jiangjiangze.icu`（Cloudflare Pages，纯静态，无 Functions/Worker）。

它是什么：一个**浏览器里的 WebDAV 文件管理客户端**，面向本项目的手机端服务器
（`http://<手机IP>:8080`，HTTP Digest + RFC 4918），功能：列目录 / 下载 / 上传 /
新建文件夹 / 删除。另带一个**演示模式**（内存虚拟文件系统），无需任何服务器即可
展示全部交互。

边界（有意为之的不完整）：

- 浏览器 → 手机是**跨域**请求，手机端 Ktor server 目前不发 CORS 头，所以真实连接
  需要 phone 侧放行 CORS（后续工作）；跨域下浏览器对 `fetch()` 的 401 不会弹原生
  凭据框，因此本页在 JS 里实现了 Digest（MD5，RFC 2617 qop=auth），凭据只存本页内存。
- 手机上的**同源文件页**（浏览器直接打开 `http://<手机IP>:8080/`，由
  `app/src/main/kotlin/com/jingjiangze/otgdrivebridge/server/HtmlIndex.kt` 渲染）
  不受 CORS 限制，是日常使用的正路；本站是「任何浏览器、任何设备」的兜底入口与演示面。

## 部署（本工作区已验证配方，同公告后台/下载站）

```bash
# 0) 凭据：CLOUDFLARE_API_TOKEN=~/.cf_agent_token，CLOUDFLARE_ACCOUNT_ID=8641802a2d46497f1cc4e7a4cba365d2
# 1) staging 干净目录（不要把本 README/wrangler 烤进去——wrangler pages deploy 会整目录上传）
DST=../_tmp/otg-web-deploy   # 相对工作区；拷 index.html app.js style.css _headers
# 2) 建项目（一次性）
npx --yes wrangler pages project create otg-drive-bridge --production-branch=main
# 3) 上线
npx --yes wrangler pages deploy "$DST" --project-name=otg-drive-bridge --branch=main --commit-dirty=true
# 4) 自定义域（API，不会自动建 DNS）
#    POST /accounts/<acct>/pages/projects/otg-drive-bridge/domains  {"name":"otg.jiangjiangze.icu"}
#    POST /zones/6f824f1706dc9a64073560400840d73a/dns_records
#         {"type":"CNAME","name":"otg","content":"otg-drive-bridge.pages.dev","proxied":true,"ttl":1}
# 5) 新子域 NXDOMAIN 可能被本地 DNS 缓存：curl --resolve otg.jiangjiangze.icu:443:<CF边缘IP> 验证
```

`_headers` 惯例（superbig 实测教训）：`/*` 只放安全头不放 Cache-Control（多规则命中会
逗号拼接、no-store 会赢）；HTML 的缓存规则写在 `/` 与 `/index.html`（`/x.html` 会 308 到
`/x`，规则写在去扩展名路径上才命中）。
