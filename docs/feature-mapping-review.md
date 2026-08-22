# SongsterX ↔ Surge 一一对应审查清单

本文用于逐项审查，不把“sing-box/mitmproxy 有类似 primitive”误写成“SongsterX 已经完成 Surge 兼容”。每一行都是一个可以单独判定的功能点。

## 状态定义

| 状态 | 含义 | 审查规则 |
|---|---|---|
| `M0 已实现` | 当前最小链路已有实际配置、启动逻辑或静态验证 | 可以进入 M0 验收，但仍要看验收条件 |
| `M0 受限` | 有对应能力，但只覆盖当前网关方案的子集或有明确语义偏差 | 不能当作完整 Surge 等价 |
| `契约/待实现` | 已定义接口、字段和 fail-closed 行为，但实际组件尚未交付 | 不能宣称运行时已支持 |
| `已下载未激活` | 文件和依赖已下载并哈希锁定，但没有执行引擎 | 不能宣称模块功能已生效 |
| `部分接入` | 静态规则、HTTP 处理和本地 JavaScript 已运行，但仍有 Surge 全局策略和事件语义差异 | 只能宣称对应运行时已生效 |
| `未实现` | 当前仓库没有可执行实现 | 只能列入后续里程碑 |
| `不纳入` | Surge 的其他平台或独立服务能力 | 不作为本 macOS 网关 M0 的交付范围 |

## 按状态分类总览

下面是审查入口；同一 ID 的详细源配置、对应文件和验收条件仍以本文后面的逐项表为准。

### 1. `M0 已实现`

| 范围 | 功能 ID |
|---|---|
| General | `G-08`、`G-09`、`G-15` |
| Proxy | `P-02`、`P-05` |
| Proxy Group | `PG-05` |
| Rule | `R-01`～`R-08`、`R-10`、`R-12` |
| MITM/Script/Keystore | `M-01` |
| 逻辑规则基础 | `L-11` |

这些项目可以进入 M0 实际验收，但仍要按逐项表中的命令、端口或 E2E 条件测试。

### 2. `M0 受限`

| 范围 | 功能 ID |
|---|---|
| General | `G-04`、`G-10`、`G-11` |
| Proxy | `P-01`、`P-03`、`P-04` |
| Proxy Group | `PG-03`、`PG-04`、`PG-06` |
| Rule | `R-09`、`R-11`、`R-13` |
| MITM/Script/Keystore | `M-02`、`M-04`、`M-06`、`M-07`、`M-08` |
| 逻辑规则基础 | `L-03`、`L-13` |

这些项目有基础对应物，但存在子集、版本、策略或安全语义差异，不能勾选为“完整 Surge 等价”。

### 3. `契约/待实现`

| 范围 | 功能 ID |
|---|---|
| LAN 接管 | `G-13`、`G-14` |
| 逻辑 source context | `L-02` |
| MITM 客户端来源校验 | `M-03` |

这些项目已经有 profile 字段、启动 gate 或接口约束，但缺少真实 guest Gateway、DeviceRegistry 或 source context runtime。

### 4. `部分接入`

| 范围 | 功能 ID |
|---|---|
| 9 个模块 | `MOD-01`～`MOD-09` |
| 模块逻辑资源 | `L-08`、`L-09` |

模块本体、14 个脚本和 2 个数据/ruleset 已下载并哈希锁定；静态 Rule、MITM、URL Rewrite、Map Local、Header Rewrite 已接入，脚本和 Body Rewrite 仍禁用。

### 5. `未实现`

| 范围 | 功能 ID |
|---|---|
| General | `G-01`～`G-03`、`G-05`～`G-07`、`G-12` |
| Proxy Group | `PG-01`、`PG-02`、`PG-07`～`PG-09` |
| Rule/Host | `R-14`、`H-01`～`H-08` |
| MITM/Script/Keystore | `M-05` |
| 逻辑规则 | `L-01`、`L-04`～`L-07`、`L-10`、`L-12` |

这些项目当前没有可运行的等价实现，只能进入后续 RuleCompiler、Surge JS、GeoIP、Host Compiler、Control API 或 guest Gateway 里程碑。

### 6. `设计`或`不纳入`

| 分类 | 功能 |
|---|---|
| 设计 | Flow/Traffic/Metrics/Diagnostics 统一数据面 |
| 不纳入 | Ponte、MTProto Server、Snell Server、iOS/tvOS 等独立或其他平台能力 |

### 当前数量概览

| 状态 | 数量口径 |
|---|---:|
| `M0 已实现` | 18 个编号项 |
| `M0 受限` | 19 个编号项 |
| `契约/待实现` | 4 个编号项 |
| `部分接入` | 11 个编号项（9 模块 + 2 逻辑资源） |
| `未实现` | 29 个编号项 |

数量只用于审查导航，不代表功能权重；具体结论以每一项的限制和验收条件为准。

## A. `Default.conf` 的逐项对应

### A1. `[General]`

| ID | Surge 功能/字段 | SongsterX 对应 | 状态 | 审查证据/验收 |
|---|---|---|---|---|
| G-01 | `external-controller-access` | Control API 的设计目标；当前没有 6155 服务 | `未实现` | `docs/surge-like-proxy.md` §10；启动后不能声称 API 可用 |
| G-02 | `http-api` | SongsterX Control API 规划；当前没有 6200 服务 | `未实现` | 不能用 sing-box Clash API 代替完整 Surge API |
| G-03 | `http-api-web-dashboard` | Dashboard/Logbook/UI 未实现 | `未实现` | README 与开发文档明确列为路线项 |
| G-04 | `ipv6=false` | `SongsterX.conf [Gateway]` 固定 `ipv6=false` | `M0 受限` | 这是主动关闭 IPv6，不是 IPv6 已支持 |
| G-05 | `ipv6-vif=auto` | 没有 IPv6 VIF/RA/NDP 实现 | `未实现` | guest Gateway/IPv6/RA 尚未交付 |
| G-06 | `always-raw-tcp-keywords` | 没有 Surge raw TCP 关键字识别 | `未实现` | 不得把 sing-box sniff 当成等价功能 |
| G-07 | `always-real-ip` | 没有 Surge 强制真实 IP 解析策略 | `未实现` | 当前仅有 sing-box DNS 与 route 基础能力 |
| G-08 | `tun-excluded-routes=223.86.225.0/24` | TUN `route_exclude_address` | `M0 已实现` | sing-box JSON；validator 强制检查该网段 |
| G-09 | `dns-server=218.6.200.139,61.139.2.69,223.5.5.5` | sing-box 三个 UDP DNS server，`final=dns-cn-1` | `M0 已实现` | sing-box 1.13.14 `check/format`；仍需实机 DNS 泄漏测试 |
| G-10 | `skip-proxy` | `ip_is_private`、Apple/Steam 等 direct 规则的子集 | `M0 受限` | 没有完整迁移所有 Surge wildcard 语义 |
| G-11 | `http-listen` | 当前只有本机 `mixed-in-direct:2081` 后置 bridge | `M0 受限` | 不是对 LAN 开放的 Surge HTTP 代理监听 |
| G-12 | `socks5-listen` | 当前没有对外 SOCKS5；2082 是 Snell 内部 bridge | `未实现/内部专用` | 不能把 `127.0.0.1:2082` 当用户 SOCKS5 服务 |
| G-13 | `proxy-restricted-to-lan` | Linux guest LAN 转发已实现；static client allowlist 尚未接入 guest | `未实现` | Gateway 当前拒绝 `client-policy = allowlist`，避免 fail-open |
| G-14 | Gateway Mode | vfkit、vmnet bridged 和 Linux guest supervisor 已接通，含 guest-agent authenticated status/runtime readiness 及 LAN/`tun0` 计数器观察 | `部分实现` | 计数器不阻塞启动；仍需实体客户端做 ARP/TCP/UDP/DNS/MITM 协议级验收 |
| G-15 | 不启动 DHCP | `dhcp=false`、`ipv6=false`；Bridged helper 不启动 SongsterX DHCP 服务 | `M0 已实现` | `[Gateway]`/interface gate；客户端手工配置网关/DNS |

### A2. `[Proxy]`

| ID | Surge 功能/字段 | SongsterX 对应 | 状态 | 审查证据/验收 |
|---|---|---|---|---|
| P-01 | `ad=http,127.0.0.1,3128` | sing-box `http` outbound `ad` | `M0 受限` | 只定义出站，不负责启动 3128 上游服务 |
| P-02 | Trojan + WS + TLS | sing-box `trojan` outbound `tunnel` | `M0 已实现` | server/port/WS path/Host/SNI 在脱敏 JSON；密码环境注入 |
| P-03 | `skip-cert-verify=true` | sing-box TLS `insecure=true` | `M0 受限` | 与源配置对应，但降低证书校验安全性 |
| P-04 | Snell v4 + HTTP obfs + reuse | 外部 Snell bridge → `127.0.0.1:2082` → sing-box SOCKS | `M0 受限` | 1.13.14 没有原生 Snell；bridge 使用 `--psk-env` |
| P-05 | proxy secret/PSK | `SONGSTERX_TROJAN_PASSWORD`、`SONGSTERX_SNELL_PSK` | `M0 已实现` | 不写仓库；不进入进程 argv |

### A3. `[Proxy Group]`

| ID | Surge 功能/字段 | SongsterX 对应 | 状态 | 审查证据/验收 |
|---|---|---|---|---|
| PG-01 | `ikuu=smart,policy-path=...` | 未拉取源 policy URL；无 external policy loader | `未实现` | token 已从仓库和审核材料移除 |
| PG-02 | `update-interval=0` | 没有 policy-path 更新器 | `未实现` | 需要 PolicyEngine 远程策略生命周期 |
| PG-03 | `include-all-proxies` | selector/urltest 固定列出代理 | `M0 受限` | 不是动态包含所有代理的 Surge 语义 |
| PG-04 | `evaluate-before-use=1` | urltest 首次探测 + Snell 启动顺序 | `M0 受限` | 不是 Surge 完整语义 |
| PG-05 | `Final=select,...` | sing-box `selector` tag=`Final` | `M0 已实现` | 候选和默认值在 JSON；没有 Dashboard 切换 API |
| PG-06 | `smart=smart,tunnel,sn` | sing-box `urltest` tag=`smart` | `M0 受限` | 仅 local subset + URLTest approximation |
| PG-07 | Surge `fallback` | 未配置独立 fallback group | `未实现` | 不能把 selector/urltest 说成 fallback |
| PG-08 | Surge `load-balance` | 未实现 persistent/per-flow load balance | `未实现` | 需要 PolicyEngine/conformance |
| PG-09 | `subnet`/`SSID`/`BSSID`/`ROUTER`/`TYPE` | Native network context 规划 | `未实现` | 远程 LAN 客户端不能伪造本机 context |

### A4. `[Rule]`

| ID | Surge 规则 | SongsterX 对应 | 状态 | 审查证据/验收 |
|---|---|---|---|---|
| R-01 | `DEST-PORT,8000,REJECT,pre-matching` | `network=tcp, port=[8000], action=reject` | `M0 已实现` | 已放在 `ip_is_private → direct` 前 |
| R-02 | `DOMAIN,linux.do,Final` | `domain=linux.do → Final` | `M0 已实现` | sing-box route rule |
| R-03 | `DOMAIN-SUFFIX,v2ex.com,Final` | `domain_suffix=v2ex.com → Final` | `M0 已实现` | sing-box route rule |
| R-04 | `DOMAIN-SUFFIX,openai.com,Final` | `domain_suffix=openai.com → Final` | `M0 已实现` | sing-box route rule |
| R-05 | `DOMAIN-SUFFIX,chatgpt.com,Final` | `domain_suffix=chatgpt.com → Final` | `M0 已实现` | sing-box route rule |
| R-06 | `DOMAIN-SUFFIX,googleapis.cn,Final` | `domain_suffix=googleapis.cn → Final` | `M0 已实现` | sing-box route rule |
| R-07 | `DOMAIN-SUFFIX,nodeseek.com,Final` | `domain_suffix=nodeseek.com → Final` | `M0 已实现` | sing-box route rule |
| R-08 | `DOMAIN-SUFFIX,steamserver.net,DIRECT` | `domain_suffix=steamserver.net → direct` | `M0 已实现` | sing-box route rule |
| R-09 | `DOMAIN,gateway.icloud.com,DIRECT,extended-matching` | `domain=gateway.icloud.com → direct` | `M0 受限` | extended-matching 完整语义未实现 |
| R-10 | `DOMAIN,iosapps.itunes.apple.com,DIRECT` | `domain=iosapps.itunes.apple.com → direct` | `M0 已实现` | sing-box route rule |
| R-11 | `IP-CIDR,192.168.88.1/16,DIRECT,no-resolve`（源值） | M0 使用 `192.168.88.0/24` 静态 LAN `[Gateway]` + `ip_is_private → direct` | `M0 受限` | 源 CIDR 与 M0 LAN CIDR 不同，需单独确认是否保留源 `/16` |
| R-12 | `IP-CIDR,172.64.229.216/32,DIRECT` | `ip_cidr=172.64.229.216/32 → direct` | `M0 已实现` | Snell bridge anti-loop；validator 检查 |
| R-13 | `FINAL,Final,dns-failed` | route `final=Final` | `M0 受限` | `dns-failed` 特殊失败行为未单独复刻 |
| R-14 | `PROCESS-NAME` 类规则 | Native 层规划；远程客户端不猜测 | `未实现/边界` | M0 改用静态 source IP/MAC 契约 |

### A4.1. 逻辑组合规则与修饰符

上一版漏掉了源配置中真正重要的逻辑规则。它们不是普通的单条件 `DOMAIN → POLICY`，而是 RuleCompiler 必须保留的布尔表达式：

| ID | 源逻辑规则 | 逻辑结构 | 当前对应 | 状态 |
|---|---|---|---|---|
| L-01 | 广告出站 `AND(...) → ad` | `hostname_type=domain AND (source_ip 为四个地址之一) AND (protocol 为 HTTP/HTTPS) AND NOT(domain_keyword 为 byte/icloud/apple/tiktok/douyin)` | `config/surge-logic-rules.redacted.json` `source-ad-filter` | `未实现` |
| L-02 | 四个 `SRC-IP` 的 `OR` | `OR(192.168.88.242, .240, .246, .243)` | guest Gateway/static source context 尚未接入 sing-box route | `契约/待实现` |
| L-03 | HTTP/HTTPS 的 `OR` | `OR(PROTOCOL,HTTPS; PROTOCOL,HTTP)` | sing-box sniff 只能提供基础协议判断，不提供源规则等价编译 | `M0 受限` |
| L-04 | 关键词 `NOT(OR(...))` | 排除 byte、icloud、apple、tiktok、douyin 的 extended matching | 没有 Domain Keyword + extended-matching 的组合编译 | `未实现` |
| L-05 | qBittorrent 进程规则 | `PROCESS-NAME → DIRECT` | 只对本机 Native 层有意义，远程 LAN 客户端没有进程身份 | `未实现/边界` |
| L-06 | Emby 规则 | `SRC-IP-CIDR AND DOMAIN(api.day.app) AND SCRIPT(EmbyRefresh) → DIRECT` | `api.day.app` M0 MITM 存在，但 EmbyRefresh/Script matcher 不存在 | `未实现` |
| L-07 | `GEOIP,CN,DIRECT` | `geoip_country=CN → DIRECT` | 当前没有锁定 GeoIP 数据库和更新/回滚策略 | `未实现` |
| L-08 | `RULE-SET` | 本地已校验规则集展开为静态规则插入主规则序列 | 只支持模块清单内的本地 source 子集，不支持通用远程更新 | `部分接入` |
| L-09 | `URL-REGEX` | URL 正则叶子条件，进入 HTTP request pipeline | 由本地 Module Engine 处理请求拦截/替换安全子集 | `部分接入` |
| L-10 | `IP-CIDR,no-resolve` | IP 条件命中时禁止触发域名解析 | 模块和源配置中均有声明，尚无 RuleCompiler 语义 | `未实现` |
| L-11 | `pre-matching` | 在最终连接路由前优先匹配端口规则 | M0 已把 TCP/8000 reject 放在 private direct 前 | `M0 已实现` |
| L-12 | `extended-matching` | 扩展域名/关键词匹配 | sing-box 当前只用了普通 domain/domain_suffix | `未实现` |
| L-13 | first-match / terminal action | 规则按顺序选择一个终止动作；后续规则不再覆盖 | sing-box route 顺序已用于 8000 reject 优先级 | `M0 受限` |

这些规则的脱敏保留和结构化表示见 `config/surge-logic-rules.redacted.json`。当前 M0 没有把它们偷偷塞进 sing-box 配置，因为那会把未实现的 source context、Surge JS、GEOIP 和 AND/OR/NOT 语义伪装成已完成。

### A5. `[Host]`

| ID | Surge Host 条目 | SongsterX 对应 | 状态 |
|---|---|---|---|
| H-01 | `iosapps.itunes.apple.com → 17.253.85.142` | 未转入 sing-box hosts | `未实现` |
| H-02 | `hanime1.me → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-03 | `cm.cdn.bgp.yt → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-04 | `*.acgrip.com → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-05 | `18comic.vip → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-06 | `jm18* → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-07 | `missav.ws → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |
| H-08 | `www.wenku8.net → 172.64.229.216` | 未转入 sing-box hosts | `未实现` |

### A6. `[MITM]`、`[Script]`、`[Keystore]`

| ID | Surge 功能/字段 | SongsterX 对应 | 状态 | 审查证据/验收 |
|---|---|---|---|---|
| M-01 | `hostname=api.day.app` | 用户统一使用 `127.0.0.1:2080`；命中后内部转 `mitmdump:8080` | `M0 已实现` | `mitm_minimal_addon.py` 只处理该 hostname；CA 用持久 confdir |
| M-02 | `h2=true` | mitmproxy 基础 HTTP/2 能力 | `M0 受限` | 没有完整 HTTP/2 E2E conformance |
| M-03 | `client-source-address=MAC1,MAC2` | guest Gateway 动态 LAN 学习 + 可选 `static_clients` + MITM allowlist | `契约/待实现` | `[Gateway]` gate 可选字段；真实 MAC 校验由 guest Gateway 完成 |
| M-04 | `ca-keystore-name=MITM` | M0 `SONGSTERX_MITMPROXY_CONFDIR`；Keychain 后迁移 | `M0 受限` | profile 的 `ca_reference`/`secrets.mitm_ca` 已统一 |
| M-05 | `EmbyRefresh` Surge JS | 无 Surge JS runtime；M0 不执行 | `未实现` | Python addon 不等价 JS |
| M-06 | Surge `type=rule/http-request/http-response` | mitmproxy Python hook 仅做 M0 header 标记和 bounded inspection | `M0 受限` | 没有参数、body rewrite、完整 context relay |
| M-07 | `[Keystore]` P12/base64/password | 不写入仓库；运行时私有 CA confdir | `M0 受限` | 原始私钥材料不提交；客户端需安装 M0 CA |
| M-08 | MITM 保持 Final/Smart 策略 | 当前 `api.day.app` 强制 direct | `M0 受限` | 明确标为 `forced_direct_m0_semantic_deviation` |

## B. 9 个模块逐项对应

| ID | 模块 | 本地模块文件 | 远程脚本/资源 | 状态 |
|---|---|---|---|---|
| MOD-01 | zheye | `modules/zheye.sgmodule` | `zheye.min.js`、`zhihu-blank_dict.json` | `静态/HTTP 部分接入；脚本禁用` |
| MOD-02 | wloc | `modules/wloc.sgmodule` | `wloc.js`、`wloc-settings.js` | `MITM 接入；脚本禁用` |
| MOD-03 | jd_price2 | `modules/jd_price2.sgmodule` | `jd_price.js` | `MITM 接入；脚本禁用` |
| MOD-04 | YouTube.Enhance | `modules/YouTube.Enhance.sgmodule` | `youtube.response.js`、`youtube.request.js` | `MITM 接入；脚本禁用` |
| MOD-05 | tieba | `modules/tieba.sgmodule` | `tieba-json.js`、`tieba-proto.js`、`tieba-ad.list` | `静态/HTTP 部分接入；脚本禁用` |
| MOD-06 | BiliHD | `modules/BiliHD.sgmodule` | `bilibili_json.js` | `MITM 接入；脚本禁用` |
| MOD-07 | spotify | `modules/spotify.module` | `spotify-json.js`、`spotify-proto.js` | `Header Rewrite/MITM 接入；脚本禁用` |
| MOD-08 | BiliBili.Enhanced | `modules/BiliBili.Enhanced.sgmodule` | `response.bundle.js` | `MITM 接入；脚本禁用` |
| MOD-09 | BiliBili.ADBlock | `modules/BiliBili.ADBlock.sgmodule` | `request.bundle.js`、`response.bundle.js` | `静态/HTTP 部分接入；脚本禁用` |

模块审查结论：9 个模块本体、14 个脚本、2 个数据/ruleset 共 16 个唯一运行时引用已下载并哈希锁定。当前 Module Engine 只接入静态 Rule、MITM hostname、URL Rewrite、Map Local、Header Rewrite 和本地 ruleset 展开；`execute_remote_code=false`，因此 `%APPEND%` 之外的模块合并语义、override、Arguments、Requirement、脚本沙箱、body 解码/重编码、`binary-body-mode`、`requires-body` 和失败回滚仍不能勾选为“完整生效”。

## C. Surge 通用功能与组件对应

| Surge 能力 | 目标组件 | 当前状态 | 审查结论 |
|---|---|---|---|
| System Proxy / HTTP / SOCKS | Native macOS Layer + sing-box mixed inbound | `M0 受限` | 当前重点是 TUN/网关，不是完整代理 UI |
| Enhanced Mode / TUN | Linux guest sing-box `tun0` | `Gateway guest 配置与 runtime readiness 已实现；当前会话 packet path 计数仅作观察` | macOS host 不创建 TUN；实际转发仍由 guest 防火墙和路由负责 |
| TCP 代理 | sing-box outbound | `M0 已实现` | Trojan/HTTP/SOCKS 路径已有配置 |
| UDP 代理 | sing-box 基础能力 | `M0 受限` | UDP Fast Path 和全量 E2E 未完成 |
| DNS 分流 | sing-box DNS/route | `M0 受限` | 有基础配置，不承诺绝对无泄漏 |
| DoH/DoH3/DoT/DoQ/FakeIP | sing-box DNS runtime | `未完成验证` | 当前最小配置只使用 UDP DNS |
| DIRECT / REJECT | sing-box direct + route reject | `M0 已实现` | 8000 优先级已锁定 |
| Selector | sing-box selector | `M0 已实现` | 没有 Dashboard/API 手动控制 |
| URLTest | sing-box urltest | `M0 受限` | 只能称 URLTest approximation |
| Fallback / Load Balance / Smart | PolicyEngine | `未实现` | 不能用 urltest 冒充三者 |
| URL/Header/Body Rewrite | HTTPProcessingRuntime | `部分接入` | URL/Header/Body Rewrite 已接入；复杂 jq/完整 Surge 版本语义仍需 conformance |
| Map Local | HTTPProcessingRuntime | `部分接入` | 只允许内联数据或已哈希锁定的本地资源 |
| MITM | mitmproxy | `M0 受限` | 模块主机从统一入口 `127.0.0.1:2080` 内部转发到 `127.0.0.1:8080`；策略保持仍是 forced direct |
| HTTP/1、HTTP/2、WebSocket、gRPC | mitmproxy backend | `基础能力/未完成验收` | 需要逐协议 conformance |
| Surge JS | JavaScriptCore/WKWebView runtime | `未实现` | 不以 Python 替代 |
| Module Engine | Profile IR/Module Parser/Merger | `部分接入` | 已生成哈希校验后的本地运行计划；脚本、Body Rewrite、Arguments/Requirement 仍禁用 |
| Process/Device/MAC rules | Native Layer + guest DeviceRegistry | `契约/待实现` | M0 已支持 LAN 动态 IP/MAC 学习；精细设备规则仍待实现 |
| DHCP | Linux guest Gateway | `明确不启用` | 本方案不包括 DHCP |
| IPv6/NDP/RA | Linux guest Gateway | `明确不启用` | M0 `ipv6=false` |
| TCP Port Forwarding | Network Service | `未实现` | 不由 sing-box route 自动推导 |
| UDP Fast Path | Linux guest Gateway | `未实现` | 需要 FakeIP 排除、阈值和统计 |
| Dashboard/Logbook/Controller API | Control API/UI | `未实现` | 当前只提供静态校验和启动脚本 |
| Flow/Traffic/Metrics/Diagnostics | Flow Store/Control API | `设计` | 没有可运行统一流量数据库 |
| Ponte / MTProto Server / Snell Server | 独立项目 | `不纳入` | 不属于 macOS Gateway M0 |

## D. 审查顺序

1. 审 A1：没有 guest Gateway 时 `--lan` 是否必定退出，且没有 DHCP/RA。
2. 审 A2/A3：Trojan、Snell bridge、Final、smart 的标签是否和 JSON/启动脚本一致。
3. 审 A4：重点测试私网地址的 TCP/8000，确认 reject 先于 private direct。
4. 审 A5：确认 Host 当前只是保留稿，没有被误报成 sing-box 已生效。
5. 审 A6：确认 `api.day.app` MITM、持久 CA、client allowlist 和 forced-direct 偏差都已写明。
6. 审 B：静态 Rule、MITM、URL Rewrite、Map Local、Header Rewrite 可按本地 Module Engine 计划验收；模块脚本、Surge JS、Body Rewrite、binary body 不能勾选。

## E. 当前可接受结论

当前项目可以称为：

> 脱敏、无 DHCP、依赖明确且可验证的 macOS 静态 LAN 网关最小方案。

不能称为：

> 已完成的完整 Surge 替代品。

`契约/待实现`、`部分接入`、`已下载未激活`、`M0 受限` 和 `未实现` 都是故意保留的审查边界。
