# SongsterX ↔ Surge 按状态详细功能清单

本文把 `docs/feature-mapping-review.md` 中的每个功能 ID 按状态重新展开。审查时可以从上到下逐条确认，不需要在不同配置区段之间来回查找。

状态含义：

- `M0 已实现`：当前最小链路已有配置、启动逻辑或静态验证，可以进行 M0 验收。
- `M0 受限`：有对应 primitive，但只覆盖子集，或与 Surge 存在明确语义差异。
- `契约/待实现`：已经定义接口、字段和失败策略，但真实组件尚未交付。
- `已下载未激活`：本体和依赖已下载、哈希锁定，但没有执行引擎。
- `部分接入`：静态规则、HTTP 处理和本地 JavaScript 已运行，但仍有 Surge 全局策略和事件语义差异。
- `未实现`：当前没有可运行的对应实现。
- `设计/不纳入`：只有架构设计，或不属于本 macOS 网关 M0 范围。

## 一、M0 已实现

| ID | 功能 | 当前对应实现 | 仍需审查 |
|---|---|---|---|
| G-08 | TUN 排除网段 `223.86.225.0/24` | sing-box TUN `route_exclude_address` | 检查启动后该网段没有被 TUN 再次接管 |
| G-09 | 指定 DNS server | `218.6.200.139`、`61.139.2.69`、`223.5.5.5`，最终使用 `dns-cn-1` | 实测传统 DNS、系统 resolver 和应用私有 DNS 是否旁路 |
| G-15 | 不启动 DHCP/RA | `[Gateway]` 中 DHCP、IPv6/RA 均关闭；Bridged helper 不传不存在的 `--no-dhcp` 参数 | 客户端必须手工填写网关、DNS；仍需在真实网卡抓包确认没有 DHCP/RA |
| P-02 | Trojan WebSocket TLS 代理 | sing-box `trojan` outbound `tunnel` | 检查 WS path、Host、SNI、TLS 和实际出口连通性 |
| P-05 | 代理密码和 PSK 的秘密注入 | Trojan 从环境变量进入 jq；Snell 使用 `--psk-env` | 检查仓库、日志、argv 均没有真实秘密 |
| PG-05 | `Final` selector | sing-box `selector`，候选为 `smart/tunnel/snell-bridge/ad/direct` | 当前没有 Dashboard/API 手动切换能力 |
| R-01 | TCP/8000 拒绝 | `network=tcp`、`port=[8000]`、`action=reject` | 必须位于 `ip_is_private → direct` 前，测试私网目标 `:8000` |
| R-02 | `linux.do → Final` | `domain=linux.do` route 到 `Final` | 测试域名命中和最终出口 |
| R-03 | `*.v2ex.com → Final` | `domain_suffix=v2ex.com` route 到 `Final` | 测试根域名和子域名边界 |
| R-04 | `*.openai.com → Final` | `domain_suffix=openai.com` route 到 `Final` | 测试域名 sniff 后是否命中 |
| R-05 | `*.chatgpt.com → Final` | `domain_suffix=chatgpt.com` route 到 `Final` | 测试 HTTPS SNI/域名识别 |
| R-06 | `*.googleapis.cn → Final` | `domain_suffix=googleapis.cn` route 到 `Final` | 测试 DNS 未返回域名时的行为 |
| R-07 | `*.nodeseek.com → Final` | `domain_suffix=nodeseek.com` route 到 `Final` | 测试根域名及子域名 |
| R-08 | `*.steamserver.net → DIRECT` | `domain_suffix=steamserver.net` route 到 `direct` | 测试与 Final 规则的优先级 |
| R-10 | `iosapps.itunes.apple.com → DIRECT` | sing-box domain rule 到 `direct` | 仅验证路由；Host 静态解析仍未迁移 |
| R-12 | Snell server `/32` 直连防回环 | `172.64.229.216/32 → direct` | Snell bridge 启动后抓包确认不回到自身代理链 |
| M-01 | `api.day.app` MITM | 用户通过统一入口 `127.0.0.1:2080`；命中后内部转 `mitm:127.0.0.1:8080` | 安装 M0 CA 后测试 HTTPS MITM；只允许该 hostname |
| L-11 | `pre-matching` 的端口优先级 | TCP/8000 reject 已前置 | 测试规则命中后不能被后续 private direct 覆盖 |

## 二、M0 受限

| ID | 功能 | 当前对应实现 | 限制/不能声称的内容 |
|---|---|---|---|
| G-04 | IPv6 开关 | M0 `[Gateway]` 固定 `ipv6=false` | 这是关闭 IPv6，不是 IPv6 已兼容 |
| G-10 | `skip-proxy` | private、Apple、Steam 等部分 direct 规则 | 没有完整 Surge wildcard、resolver 和 bypass 语义 |
| G-11 | HTTP 监听 | 只有本机 `127.0.0.1:2081` 后置 bridge | 不是对 LAN 用户开放的 Surge HTTP proxy listener |
| P-01 | 本地广告 HTTP proxy `127.0.0.1:3128` | sing-box 定义 `ad` outbound | 只定义出站，不启动或实现 3128 上游服务 |
| P-03 | `skip-cert-verify` | sing-box TLS `insecure=true` | 与源配置对应，但证书校验被关闭，存在安全风险 |
| P-04 | Snell v4/HTTP obfs/reuse | 外部 Snell bridge → `127.0.0.1:2082` → sing-box SOCKS | sing-box 1.13.14 没有原生 Snell；bridge 仍是外部依赖 |
| PG-03 | `include-all-proxies` | selector/urltest 手工列出固定 outbounds | 不是动态包含全部代理的 Surge 语义 |
| PG-04 | `evaluate-before-use` | 通过 Snell 先启动和 2082 health-check 降低竞态 | 仍不是完整 Surge `evaluate-before-use` 实现 |
| PG-06 | `smart` | sing-box `urltest`，测试 URL 为 `generate_204` | 只能称 URLTest approximation，不是 Surge Smart |
| R-09 | `extended-matching` | 普通 `domain` 规则对应 `gateway.icloud.com` | 扩展匹配语义没有实现 |
| R-11 | 源 LAN CIDR/no-resolve | 源值是 `192.168.88.1/16`；M0 `[Gateway]` 使用 `192.168.88.0/24` 和 `ip_is_private` | 源 CIDR 与 M0 LAN CIDR 不同；`no-resolve` 未由 RuleCompiler 实现 |
| R-13 | `FINAL,Final,dns-failed` | sing-box `route.final=Final` | `dns-failed` 的 Surge 特殊失败行为没有单独复刻 |
| M-02 | MITM HTTP/2 | 使用 mitmproxy 的基础能力 | 没有完整 HTTP/2 E2E conformance |
| M-04 | MITM CA keystore | M0 使用持久 `SONGSTERX_MITMPROXY_CONFDIR` | macOS Keychain 迁移仍是后续目标 |
| M-06 | HTTP request/response hook | Module Engine 处理 URL-REGEX、Map Local、Header Rewrite 和 MITM hostname | 没有 Surge JS 参数、完整 body、context relay 和策略恢复 |
| M-07 | P12/base64/Keystore | 真实 P12 不入库；M0 使用私有 mitmproxy confdir | 客户端需要安装 M0 CA；生产 Keychain 尚未接入 |
| M-08 | MITM 保持 Final/Smart 策略 | `api.day.app` 进入 MITM 后固定 direct | 明确是 `forced_direct_m0_semantic_deviation` |
| L-03 | HTTP/HTTPS 协议 `OR` | sing-box sniff 有基础协议识别 | 没有把它和 source IP、domain keyword 组合成 Surge AND 规则 |
| L-13 | first-match/terminal action | sing-box route 按顺序选终止动作 | 仅 M0 基础路由已验证，完整 RuleCompiler 优先级仍未完成 |

## 三、契约/待实现

| ID | 功能 | 已定义的契约 | 缺少的实际实现 |
|---|---|---|---|
| G-13 | `proxy-restricted-to-lan` | LAN 内转发路径已实现；客户端 MAC/IP allowlist 尚未接入 Linux guest，配置会拒绝启动 | `client-policy = all`；allowlist 暂不支持 |
| G-14 | macOS Gateway Mode | vfkit/vmnet guest 路线已有双 virtio-net supervisor、guest-agent authenticated status、runtime readiness 和 LAN/`tun0` 计数器验收 | 计数器验收仍需实体客户端现场触发，且不代替 ARP/TCP/UDP/DNS/MITM 协议级验证 |
| L-02 | 多个 source IP 的 `OR` | 结构化为 `OR(192.168.88.242,.240,.246,.243)` | guest Gateway/FlowContext 尚未把 LAN source identity 提供给规则引擎 |
| M-03 | `client-source-address` | `[Gateway]` 可选 static client MAC/IP allowlist；默认使用 LAN 学习 | 真实 MAC 校验和 MITM client connection 绑定尚未完成 |

## 四、模块运行时（本地 Script 已启用）

| ID | 模块/资源 | 已下载内容 | 未激活原因 |
|---|---|---|---|
| MOD-01 | zheye | 静态 Rule、URL-REGEX、Map Local、MITM、response Script 已接入 | 依赖真实知乎响应回放验收；策略恢复未等价 |
| MOD-02 | wloc | MITM hostname、参数注入和 request/response Script 已接入 | 依赖真实 Apple 响应回放验收 |
| MOD-03 | jd_price2 | MITM hostname、参数注入和 request/response Script 已接入 | 外部慢慢买接口可用性取决于网络和脚本自身 |
| MOD-04 | YouTube.Enhance | MITM hostname、参数、binary body 和 request/response Script 已接入 | 依赖真实 YouTube 响应回放验收 |
| MOD-05 | tieba | 静态 RULE-SET、MITM hostname、JSON/protobuf body Script 已接入 | 依赖真实 protobuf 响应回放验收 |
| MOD-06 | BiliHD | MITM hostname、response body Script 已接入 | 依赖真实 BiliBili 响应回放验收 |
| MOD-07 | spotify | MITM hostname、Header Rewrite、JSON/protobuf body Script 已接入 | 依赖真实 Spotify 响应回放验收 |
| MOD-08 | BiliBili.Enhanced | MITM hostname、参数和 response body Script 已接入 | 依赖真实 WebView 响应回放验收 |
| MOD-09 | BiliBili.ADBlock | 静态 URL Rewrite、Map Local、Body Rewrite、MITM、binary body Script 已接入 | 依赖真实 Bilibili protobuf 响应回放验收 |
| L-08 | `RULE-SET` | Tieba ruleset 已校验并展开为静态 sing-box 规则 | 只支持本地已校验 source 子集，不支持通用远程更新 |
| L-09 | `URL-REGEX` | 已进入 Module Engine 的 HTTP request 匹配器 | URL 级行为已接入；完整 Surge 版本和跨阶段策略语义仍需 conformance |

共同状态：9 个模块、45 条 Script、1 条 Body Rewrite、2 个数据/ruleset 共 16 个唯一运行时引用均已 SHA-256 锁定；脚本只从本地哈希资源加载并在内置 QuickJS 上下文执行，`execute_remote_code=false` 表示运行时不下载远程代码。

## 五、未实现

| ID | 功能 | 目前缺少什么 | 后续组件 |
|---|---|---|---|
| G-01 | `external-controller-access` | 6155 Controller API | Control API |
| G-02 | `http-api` | 6200 HTTP API 兼容层 | Control API |
| G-03 | Dashboard/Logbook | Web UI、CSRF、权限和流量日志 | Dashboard/Control API |
| G-05 | `ipv6-vif=auto` | IPv6 VIF、NDP、RA、IPv6 gateway | Linux guest Gateway |
| G-06 | `always-raw-tcp-keywords` | Surge raw TCP 关键字匹配器 | RuleCompiler/Flow Runtime |
| G-07 | `always-real-ip` | 强制真实 IP 解析和 DNS 策略 | DNS/PolicyEngine |
| G-12 | 对外 SOCKS5 listener | 用户代理入口；当前 2082 只是 Snell 内部 bridge | Native Layer/sing-box inbound |
| PG-01 | `policy-path` | 远程策略下载、签名/hash、更新和回滚 | PolicyEngine |
| PG-02 | `update-interval` | 外部策略更新生命周期 | PolicyEngine |
| PG-07 | `fallback` | 按健康状态和超时选第一个可用策略 | PolicyEngine |
| PG-08 | `load-balance` | persistent hostname、per-flow/per-request 选择 | PolicyEngine |
| PG-09 | `subnet`/SSID/BSSID/ROUTER/TYPE | 网络环境变量和 Requirement 求值 | Native Layer/PolicyEngine |
| R-14 | `PROCESS-NAME` 远程规则 | 从远程 LAN 流量获得进程路径 | Device/Flow Context |
| H-01 | `iosapps.itunes.apple.com` Host | sing-box hosts/rule-set 编译 | Host Compiler |
| H-02 | `hanime1.me` Host | 同上 | Host Compiler |
| H-03 | `cm.cdn.bgp.yt` Host | 同上 | Host Compiler |
| H-04 | `*.acgrip.com` Host | wildcard Host 匹配语义 | Host Compiler |
| H-05 | `18comic.vip` Host | 同上 | Host Compiler |
| H-06 | `jm18*` Host | 非标准 wildcard 语义 | Host Compiler |
| H-07 | `missav.ws` Host | 同上 | Host Compiler |
| H-08 | `www.wenku8.net` Host | 同上 | Host Compiler |
| M-05 | `EmbyRefresh` Surge JS | JavaScriptCore/WKWebView、`$request/$response/$done` 等桥接 | Surge JS Runtime |
| L-01 | 广告复合 `AND` 规则 | AND/OR/NOT、四个 source IP、HTTP/HTTPS、关键词排除和 `ad` 动作的统一求值 | RuleCompiler + FlowContext |
| L-04 | `NOT(OR(DOMAIN-KEYWORD...))` | extended-matching 的 domain keyword 否定 | RuleCompiler |
| L-05 | qBittorrent `PROCESS-NAME` | 本机进程身份采集和规则匹配 | Native Layer |
| L-06 | Emby 复合规则 | source CIDR + domain + `SCRIPT(EmbyRefresh)` 三条件求值 | RuleCompiler + Surge JS |
| L-07 | `GEOIP,CN,DIRECT` | 固定版本 GeoIP 数据库、更新和回滚 | GeoIP Service |
| L-10 | `IP-CIDR,no-resolve` | 命中 IP 条件时阻止额外域名解析 | DNS/RuleCompiler |
| L-12 | `extended-matching` | Surge 扩展域名/关键词匹配 | RuleCompiler |

## 六、设计或不纳入

| 状态 | 功能 | 说明 |
|---|---|---|
| 设计 | Flow/Traffic/Metrics/Diagnostics | 已在架构文档定义 FlowContext、Flow Store、Control API 方向，但没有完整运行时数据库和 UI |
| 设计 | UDP Fast Path | 需要 FakeIP 排除、端口豁免、阈值、设备开关、统计和回退原因 |
| 不纳入 | Ponte | 独立协议/产品能力，不属于当前 macOS Gateway M0 |
| 不纳入 | MTProto Server | 独立服务端能力，不是客户端代理链路 |
| 不纳入 | Snell Server | 当前只计划外部 Snell client bridge，不实现 Snell 服务端 |
| 不纳入 | iOS/tvOS | 当前目标是 macOS 静态 LAN 网关 |

## 七、最终审查结论模板

你可以按以下方式审查：

1. `M0 已实现`：检查是否真的能运行和通过对应测试。
2. `M0 受限`：确认限制是否能接受，不能直接标记为完整兼容。
3. `契约/待实现`：检查接口是否足够明确，但不要当成已交付。
4. `已下载未激活`：只检查文件、来源和 hash，不检查“功能已生效”。
5. `未实现`：决定是否进入下一里程碑。
6. `设计/不纳入`：确认边界，不纳入当前通过条件。

当前整体结论仍应写成：

> 脱敏、无 DHCP、依赖明确且可验证的 macOS 静态 LAN 网关最小方案；不是完整 Surge 替代品。
