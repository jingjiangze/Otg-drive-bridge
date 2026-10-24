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

## 交付形态：单文件（2026-10-24 第二轮提速）

第一轮的 jsDelivr 镜像链已**撤下**：二轮实测发现它的致命模式——用户浏览器挂着
Clash 系统代理时，当前节点对 CF 与 jsDelivr 的 TLS 全部黑洞（curl 35），四级
`onerror` 链会**串行等待每级 TCP 超时**，比不用镜像更慢。同时 CF 自定义域直连也有
约 50% 的 15s 挂起率（边缘抖动）。

现行方案（`build.mjs` → `dist/`）：

- **整站内联为 `dist/index.html` 一个文件**（CSS+JS 全内联，首屏恰好 1 个请求，
  无瀑布、无镜像链黑洞风险）；
- `_headers` 给 HTML `Cache-Control: max-age=86400, stale-while-revalidate=604800`
  ——浏览器当天内重复打开**秒开**，后台自动刷新；
- 部署即 `wrangler pages deploy webclient/dist`（配方见下）。

**已知边界**：首次访问（或缓存过期后）仍依赖 CF 边缘健康度；若访问环境走代理，
建议对 `jiangjiangze.icu` 加直连规则（当前代理节点对 CF 是 TLS 黑洞）。
真正的大陆快源需要能吐 `text/html` 的国内托管——实测 ModelScope dataset resolve
对 `.html` 返回 `attachment` 下载头（不可当入口，仅素材镜像可用），备选是
阿里云 OSS 静态托管 / ModelScope 创空间 / 腾讯 EdgeOne Pages（均需账号侧操作）。

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
