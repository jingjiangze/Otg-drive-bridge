# OTG Drive Bridge

把 Android 手机 OTG 口上的 U 盘 / SD 卡，导出成一个 **WebDAV 服务**；电脑（Windows / macOS / Linux）把对应地址**映射成网络驱动器**，直接读写 U 盘里的**原始文件**——不是同步副本。

```
┌──────────────┐   WebDAV (Digest Auth)   ┌─────────────────────────┐
│  电脑客户端   │ ◄──────────────────────► │  手机 · OTG Drive Bridge │
│  Win 映射盘   │   http://<lan-ip>:8080   │                         │
└──────────────┘                          │  Ktor CIO (0.0.0.0:8080) │
                                          │        │                │
┌──────────────┐  虚拟 LAN / 公网隧道      │        ▼                │
│  任意位置电脑 │ ◄──────────────────────► │  DavStorage 抽象层       │
└──────────────┘  https://…  (443 + 证书)  │   ├─ SAF tree URI       │
                                          │   └─ MANAGE_EXTERNAL_…   │
                                          │        │                │
                                          │        ▼                │
                                          │   OTG U盘 / SD 卡原文件  │
                                          └─────────────────────────┘
```

## 特性

- **三条通路共用同一个 WebDAV 内核**（按优先级探测，局域网优先）：
  1. **局域网直连** — 同 Wi-Fi 下 `http://<phone-ip>:8080`，零额外配置、零公网暴露；
  2. **虚拟 LAN** — NetBird 组网（复用成熟基础设施，`netbird expose` 提供 443 + 有效证书）；
  3. **公网隧道** — Cloudflare named tunnel（可选，默认关闭）。
- **双轨存储访问**：
  - **SAF 树授权**（`ACTION_OPEN_DOCUMENT_TREE` + `takePersistableUriPermission`）——最小权限路径，Android 11+ 也能用；
  - **`MANAGE_EXTERNAL_STORAGE`**（all-files access）——官方文档明确覆盖「OTG 盘与 SD 卡根目录」，可直接按路径操作。
- **HTTP Digest 认证**（RFC 2617）——不用 Basic，因此不受 Windows `BasicAuthLevel` 限制、也不受 Office 365 弃用 Basic Auth 的影响。
- **原子写**——`AtomicWriteHandle` 契约：先写暂存区，`commit()` 时才发布。`FileSystemDavStorage` 用同分区 `.otgpart` + rename；`SafDavStorage` 受 SAF 限制（无 rename 动词），改为 App `cacheDir` 暂存后经 `openOutputStream("wt")` 拷入目标，**中断时目标是截断态**——这一点的真机行为列在手动验收清单里。
- **RFC 4918 锁**——`opaquelocktoken:` + `If:` 头，LOCK/UNLOCK 冲突返回 423。
- **路径穿越防护**——`..` / `.` / 反斜杠 / NUL / Windows 保留名在**解码后**判定，编码绕过（`%2e%2e`、`..%2f`）同样拦截。
- **前台服务保活**——`dataSync` 类型 + `PARTIAL_WAKE_LOCK` + 通知渠道；授权失效时自动停服而不是裸奔。

## 架构

代码分成两层，**分层的目的就是让协议层可以在没有 Android 设备的 CI 里被完整测试**：

| 层 | 位置 | 依赖 | 可测性 |
|---|---|---|---|
| 纯 JVM 协议层 | `security/` `webdav/` `server/` | 只用 Ktor + Kotlin 标准库 | **ubuntu runner 直接跑单元测试** |
| Android 层 | `storage/` `network/` `service/`，以及根包的 `MainActivity`（Compose UI） | SAF / ConnectivityManager / Compose | 需真机，走手动验收清单 |

关键接口 `DavStorage`（`webdav/DavStorage.kt`）隔离了「WebDAV 语义」与「文件系统后端」：

```kotlin
interface DavStorage {
    fun isRootAvailable(): Boolean
    fun node(segments: List<String>): DavNode?
    fun parentOf(segments: List<String>): Pair<DavNode, String>?
    fun createFile(parent: DavNode, name: String): DavNode?
    fun createDirectory(parent: DavNode, name: String): DavNode?
    fun delete(node: DavNode): Boolean
    fun move(node: DavNode, destination: DavNode, newName: String = node.name): Boolean
    fun copy(node: DavNode, destination: DavNode, newName: String = node.name): Boolean
    fun openRead(node: DavNode): InputStream?
    fun openWrite(node: DavNode, overwrite: Boolean): AtomicWriteHandle?
    fun mimeTypeOf(name: String): String
}
```

两个实现：

- `webdav/FileSystemDavStorage.kt` — 本地目录，**供 CI 单元测试与端到端测试使用**；
- `storage/SafDavStorage.kt` — `DocumentFile` 之上的实现，覆盖 SAF tree URI 与直路径两种根。

`AtomicWriteHandle` 把「先写完再发布」变成契约：`output` 写、`commit()` 发布、`abort()` 丢弃；未 commit 就关闭 = 丢弃。测试 `FileSystemDavStorageTest` 有一条专门断言**中断的写入不会破坏原文件**。

## 构建与测试

构建和测试**全部在 GitHub Actions 上跑**，本地不做长跑构建。

```bash
# 本地只做只读检查
git status / git diff / ls

# 推上去让 CI 跑
git push
```

CI（`.github/workflows/ci.yml`）三个 job：

| Job | 命令 | 产物 |
|---|---|---|
| `test` | `:app:testDebugUnitTest` | `app/build/reports/tests/`（测试报告） |
| `lint` | `:app:lintDebug` | lint HTML 报告 |
| `build` | `:app:assembleDebug`（依赖 test + lint 通过） | debug APK + `SHA256SUMS.txt` |

单元测试（6 个文件、10 个测试类）：

- `WebDavPathsTest`（`webdav/WebDavPathsTest.kt`）— 路径穿越、`%2e%2e`、`..%2f`、反斜杠、NUL、Windows 保留名、UTF-8 往返、`+` 不解码成空格；
- `DigestAuthenticatorTest`、`CredentialGeneratorTest`（同文件 `security/DigestAuthenticatorTest.kt`）— challenge 格式、对/错口令、错 method、重放 nc、未知 nonce、畸形头、转义引号、熵；
- `FileSystemDavStorageTest`、`LockManagerTest`（同文件 `webdav/FileSystemDavStorageTest.kt`）— CRUD、**中断写不毁原文件**、关闭未提交即丢弃、`overwrite=false` 拒绝、move/copy/递归删除、锁与 423、`If:` token 放行、过期清理；
- `WebDavXmlTest`（`webdav/WebDavXmlTest.kt`）— `D:` 命名空间、`iscollection`、仅文件有 `content-length`、集合 href 尾斜杠、XML 转义、`lockdiscovery`、Allow 头方法集完整；
- `TransportProbeUseCaseTest`、`NetBirdExposureTest`、`PublicEndpointTest`（同文件 `network/TransportProbeUseCaseTest.kt`）— 局域网优先、离线空列表、未开启互联网不探测、排序 LAN < VIRTUAL_LAN < TUNNEL、工具缺失不产卡片、隧道卡片带 100 MB 提示、URL 解析；
- `WebDavEndToEndTest`（`server/WebDavEndToEndTest.kt`）— **真起 Ktor 服务器**（`127.0.0.1:18080`）跑完整 Digest 握手：OPTIONS 免认证 + `DAV`/`Allow` 头、401 challenge、PROPFIND multistatus、PUT/GET 往返、PUT 覆盖 204、MKCOL、父目录缺失 409、穿越 400、MOVE/DELETE/COPY、LOCK→423→UNLOCK→PUT、`If:` token 放行、错口令 401、未知方法 405、HEAD Content-Length、UTF-8 文件名。

## 手动验收清单（真机）

协议层能自动化，以下必须真机：

- [ ] Windows「映射网络驱动器」输入 `http://<phone-ip>:8080`，能列出 U 盘根目录（需 MRxDAV 显式 `D:` 前缀，已实现）；
- [ ] 资源管理器里双击打开 / 编辑 / 保存一个 U 盘上的原文件，改动落到 U 盘本身；
- [ ] 拖拽上传大文件，中断后 U 盘上不出现半个文件；
- [ ] 非 80 端口下的 Windows 原生映射（**PENDING**，已知 MRxDAV 限制，备选 RaiDrive / rclone + WinFSP）；
- [ ] SAF 选根（OTG U 盘）后杀进程重进，授权仍在；
- [ ] `MANAGE_EXTERNAL_STORAGE` 路径能直接看到 OTG 盘根；
- [ ] 拔掉 U 盘后服务不停、不崩、给出可读状态；
- [ ] Doze 下保持可达（前台服务 + 白名单）；
- [ ] NetBird `netbird expose` 拿到 `https://*.proxy.<domain>`，异地电脑可映射；
- [ ] Cloudflare 隧道（可选开启）上传 ≤ 100 MB 正常，超限有明确错误而非静默截断。

## 路线图

- [x] T0 仓库 + Gradle wrapper + CI 三 job
- [x] T1 WebDAV 协议层（12 方法 + Digest + 锁 + 原子写 + 穿越防护）
- [x] T2 `DavStorage` 抽象 + 文件系统实现（可测）
- [ ] T3 SAF 树授权全流程真机验收
- [ ] T4 `MANAGE_EXTERNAL_STORAGE` 直路径轨道真机验收
- [ ] T5 三条通路探测 UI（已完成大部分，待真机）
- [ ] T6 Windows 原生映射盘端到端
- [ ] T7 互联网暴露安全基线（默认关、显式开启、可见告警）
- [ ] T8 发布：签名 + Release

## 异地接入（openp2p，可选）

手机作为被访问方只需登录 openp2p 网络（不需要任何转发命令）；异地电脑跑 openp2p 拨到手机的
**实际节点名**（登录时服务器可能改写配置名，UI 显示的是 `getAndroidNodeName()` 的真值），
把 WebDAV 指向 `http://127.0.0.1:<映射端口>/` 即可走既有的鉴权。

- 节点命名空间：本项目一律 `otg-<8hex>`；`ecs-*`（既有平台房间）与 `aliyun-*`（ECS 服务节点）
  在 `windows/internal/openp2p` 的校验里直接拒绝——与现有部署零重叠是用户硬约束。
- `-sharebandwidth 0`：私有 P2P，不中继他人流量；打不穿时不自动走公共中继。
- AAR 不入库：`.github/workflows/openp2p-aar.yml`（手动触发）构建出 15 MiB 产物；
  APK 构建经 `.github/actions/inject-openp2p-aar` 拉取最近一次成功产物注入 `app/libs/`。
  没有 AAR 时 APK 照常构建，UI 明示「本构建无引擎」。

## 安全边界

- 互联网暴露**默认关闭**，需要用户在 UI 里显式打开；开启后界面常驻警示。
- 口令由 `CredentialGenerator` 生成（默认 24 字符，约 138 bit），不含 shell 特殊字符，可安全复制粘贴。
- `allowBackup="false"`；凭据只存应用私有 SharedPreferences。
- 非 80 端口的局域网通路在 UI 上标注「未加密」。
- 仓库、日志、README 中不得出现任何真实口令或 token。

## 许可与致谢

- 本项目代码以 **MIT** 发布（见 `LICENSE`）。
- 协议层设计参考了以下 **Apache-2.0** 项目：`anujkumarprasad/webdav-server-apk`（Ktor/CIO + DocumentFile 引擎）、`messense/dav-server-rs`（方法集与 XML 形状）。
- WebDAV 规范：[RFC 4918](https://www.rfc-editor.org/rfc/rfc4918)；Digest 认证：[RFC 2617 §3.2.2](https://www.rfc-editor.org/rfc/rfc2617#section-3.2.2)。
- 未采用 `miltonio/milton2`（AGPL，许可不兼容）与 `gregko/Mini-WebDAV-server-for-Android`（无 LICENSE 文件）。
