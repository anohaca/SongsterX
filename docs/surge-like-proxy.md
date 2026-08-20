# SongsterX Surge-like Proxy 开发文档

版本：0.2.2-design
更新日期：2026-08-15
已验证核心版本：sing-box 1.13.14
适配策略：sing-box 1.13.x 起按版本能力矩阵渲染；mitmproxy stable
平台目标：macOS 优先，Linux/OpenWrt 网关随后；iOS/tvOS 需要独立原生客户端

## 1. 文档结论

技术路线：

```
sing-box + mitmproxy + Surge Runtime + Tauri/Rust Control Plane + vfkit Linux guest
```

sing-box 和 mitmproxy 只是数据面基础，不能直接串起来宣称 Surge 兼容。必须自行实现：

- Profile IR：Profile、Module、Arguments、Requirement 合并后的中间表示。
- PolicyEngine：Selector、URLTest、Fallback、Load Balance、Smart、Subnet 的真实语义。
- FlowContext：贯穿规则、进程、设备、选定策略和 HTTP 处理。
- HTTPProcessingRuntime：确定性执行 Header/URL/Body Rewrite、Map Local 和 Script。
- Surge JS Runtime：JavaScriptCore/WKWebView 兼容层，Python addon 不能冒充。
- Linux guest Gateway：基于两张 virtio-net 的 L3 Gateway、ARP/IPv4、设备注册和后续 UDP Fast Path。

当前仓库包含可运行的 Mixed/Module Engine 最小实现和 vfkit Gateway supervisor 启动路径。Gateway 的进程、guest-agent、最终 authenticated status 和配置控制面已接通；应用会在启动后持续读取 guest LAN 与 `tun0` 计数器，并在真实客户端产生两侧新增流量后标记当前会话的 packet path 已验收，但这不等于 ARP、TCP、UDP、DNS 和 MITM 的协议级完整验收。完整 Controller、PolicyEngine、IPv6/RA、DHCP、UDP Fast Path 和 Surge JS Runtime 仍是 planned/partial。未实现能力必须显示为 planned/partial；启动计划或 runtime readiness 就绪不等于这些未覆盖能力已经可用。

## 2. 产品边界

### 2.1 目标

- 系统代理、TUN/Enhanced Mode 和 Gateway Mode。
- TCP、UDP、DNS、IPv4、IPv6 接管。
- 域名、IP、端口、进程、来源设备、网络状态规则。
- DIRECT、REJECT、代理节点和真实策略组。
- DNS 分流、Hosts、FakeIP、DoH/DoH3/DoT/DoQ。
- 指定域名 HTTPS MITM、HTTP/1、HTTP/2、WebSocket、gRPC。
- URL/Header/Body Rewrite、Map Local、HTTP Script。
- Surge Module、Profile、Arguments/Requirement 表达式。
- Surge JS 请求/响应脚本和事件脚本兼容层。
- Gateway VM、DHCP、Device Manager、设备规则、独立 TCP Port Forwarding、UDP Fast Path。
- 统一 Flow、Dashboard、Control API、CLI、日志、统计、诊断。

### 2.2 非目标或独立项目

- iOS/tvOS Network Extension/VPN 原生客户端。
- Surge Ponte 协议级兼容。
- MTProto Server、Snell Server 服务端兼容。
- 对第三方 App Certificate Pinning 的绕过。
- 无限制执行任意用户脚本或任意远程 Module。

## 3. Surge 能力覆盖矩阵

状态：✅ 上游 primitive 可用（不等于 SongsterX conformance 已通过）；◐ 需要自研组件；△ 当前仅有设计；❌ 不承诺。SongsterX 的实际支持状态必须同时看实现状态、版本矩阵和 §12.6 的 fixture/expected/failure evidence；本表的 ✅ 不能单独作为“产品已支持”证据。

| 能力 | 状态 | 实现/限制 |
|---|---:|---|
| System Proxy、SOCKS5/HTTP、TUN | ✅ | Native macOS Layer + sing-box |
| TCP/UDP/DNS 接管 | ✅ | sing-box |
| IPv4/IPv6 双栈 | ◐ | sing-box + Linux guest Gateway NDP/RA |
| Process Name/Path | ◐ | 平台权限和进程元数据 |
| Network Type/SSID/Expensive | ◐ | Native 层注入 FlowContext |
| macOS Gateway VM | ◐ | `vmnet-helper`/vfkit/Linux guest supervisor、guest-agent runtime readiness 和 LAN/`tun0` 计数器验收已接通；仍需实体客户端和协议级现场验收 |
| Linux/OpenWrt Gateway | ◐ | nftables/TPROXY 或自有数据面 |
| DIRECT/REJECT | ✅ | direct；route action reject |
| HTTP/HTTPS/SOCKS、主流代理协议 | ✅/◐ | sing-box，按版本矩阵适配 |
| WireGuard | ◐ | 1.13+ 生成 WireGuard Endpoint |
| Selector/URLTest | ✅ | sing-box + PolicyEngine |
| Fallback | ◐ | 按声明顺序选第一个可用策略 |
| Load Balance | ◐ | per-request/per-flow PolicyEngine，不能用 URLTest 冒充 |
| Smart/Subnet/Requirement | ◐ | 自有策略、原生网络状态和显式兼容边界；未完成 Surge 全语义 |
| DOMAIN/IP/PORT/PROCESS 规则 | ✅/◐ | sing-box + 平台权限 |
| SRC-IP/MAC-ADDRESS/DEVICE-NAME | ◐ | Linux guest Gateway DeviceRegistry |
| UDP/TCP DNS、DoH/DoH3/DoT/DoQ、FakeIP | ✅/◐ | sing-box，逐版本测试 |
| DNS “绝对无泄漏” | ❌ | 只能按明确测试定义验收 |
| HTTPS MITM、HTTP/1、HTTP/2、WebSocket | ✅/◐ | MitmproxyBackend，逐站点验证 |
| Header/URL/Body Rewrite、Map Local | ◐ | HTTPProcessingRuntime |
| HTTP Python Hook | ✅ | mitmproxy addon |
| Surge JS Script | ◐ | 内置 QuickJS HTTP Script bridge；cron/event/dns 和完整 JSC/WKWebView 差异待 conformance |
| Module、APPEND、Arguments、Requirement | ◐ | 已有哈希校验、本地 Script、Body/HTTP 运行时和默认 Arguments；Requirement/完整合并语义待实现 |
| Dashboard、Logbook、CLI、产品 API | △ | Control API/统一 UI 待实现 |
| Device Manager、DHCP、TCP Port Forwarding | △ | Linux guest Gateway/Network Service 待实现 |
| UDP Fast Path | △ | Linux guest Gateway 数据面待实现 |
| Ponte、MTProto/Snell Server、iOS/tvOS | ❌ | 独立项目 |

必须区分传统 53、系统 resolver、应用自有 DoH/DoH3/DoQ、bootstrap、代理节点域名解析和 IPv6 DNS。

## 4. 统一架构

### 4.1 数据面

```
                         Native macOS Layer
                    ┌──────┼────────┬─────────┐
                    │      │        │         │
                 Keychain  CA   System Proxy  Network State
                    └──────┴────────┴────┬────┘
                                         │
┌──────────────┐   ┌─────────────────────▼─────────────────────┐
│ Profile/     │   │ Controller / Surge Runtime                │
│ Module       │──▶│ Profile IR · RuleCompiler · PolicyEngine  │
└──────────────┘   │ ScriptManager · Control API · Flow Store  │
                   └─────────────┬──────────────┬───────────────┘
                                 │              │
                       ┌─────────▼──────┐ ┌────▼───────────────┐
                       │ sing-box       │ │ HTTPBackend        │
                       │ TUN/DNS/Route  │ │ MitmproxyBackend   │
                       │ TCP/UDP/Proxy  │ │ future RustBackend │
                       └─────────┬──────┘ └────┬───────────────┘
                                 │             │
LAN ──▶ vmnet-helper + vfkit ───┘              │
       Linux guest Gateway / tun0              │
       DeviceRegistry, ARP/IPv4                │
       DHCP/IPv6/fast path planned              │
                                               │
                                         原 resolved_policy
```

### 4.2 FlowContext

第一次接管时创建，并贯穿 sing-box、HTTPBackend、Controller 和 Linux guest Gateway：

```
FlowContext
├── id / ingress
├── source_process / source_pid
├── source_ip / source_mac
├── device_id / device_name
├── interface / ssid / network_type
├── destination / domain / port / protocol
├── selected_rule / selected_policy_ref / resolved_policy
├── policy_resolution_generation
├── backend_ingress_id / proxy_correlation_token（transport-only，one-time）
├── http_processing_required / http_flow_id
├── bytes_up / bytes_down / timing
└── terminal_state
```

#### FlowContext Producer / sing-box Integration Point（P0）

SongsterX 选择方案 A：维护一个锁定在 sing-box 1.13.14 版本矩阵上的 `songsterx-singbox` fork/embedded runtime，并在新 flow 被 TUN/packet inbound 接受、但尚未执行最终 route action 时插入同步 `FlowTap` hook。这里不假定 stock sing-box 存在未公开的 `onNewTunFlow` API。

```
TUN/Packet inbound accepted
  → FlowTapPre（生成 flow_id，捕获 5-tuple/process/device，写入 pending FlowRegistry）
  → protocol sniff（HTTP/TLS/QUIC/DNS）
  → FlowTapRoute（补 domain，执行 PolicyEngine 最终匹配）
  → return existing flow_id + resolved FlowContext
     {selected_rule, selected_policy_ref,
            resolved_policy, policy_resolution_generation,
            http_processing_required, config_generation_id}
  → IngressAdapter validates it, updates FlowRegistry,
    creates relay_ticket, and applies the route/relay decision
  → songsterx-singbox applies the returned route/relay decision
```

`FlowTapPre` 在 `FlowAccepted` 后立即生成 flow_id，并把 source/destination/协议、process/device 和 generation 写成 pending context；需要域名规则时由 fork 内的 sniff stage 得到可用的 domain；`FlowTapRoute` 再执行最终规则匹配并写入 `selected_policy_ref`（例如 `Final`）、`resolved_policy`（例如 `HK`）和当前 selector 状态版本 `policy_resolution_generation`。在 Route 阶段返回前，不允许数据连接进入 selected outbound、ContextRelay 或 policy bridge。后续 selector 变化只影响新 flow，已建立 flow 固定其 `resolved_policy`。IngressAdapter RPC 有 deadline，超时按配置 fail closed。任何无法可靠解析的字段保留为 unknown，不能靠事后日志、destination+时间戳或 API 轮询猜回去。

`FlowTapPre` 是整个数据面的唯一 `flow_id` 生成点；`FlowTapRoute` 只更新同一条 pending FlowRegistry 记录并返回已解析的 FlowContext。Transport/IngressAdapter 不得重新生成 flow_id，也不得再次调用 PolicyEngine；它只能校验、持久化和转运 FlowTap 已经产生的上下文。

因此 M1/M2 的完整数据面必须使用 `songsterx-singbox` fork/embedded runtime 或等价的自定义 inbound/outbound adapter；普通 stock sing-box 二进制没有这个 producer hook，只能用于本仓库的 M0 配置结构和单策略 DIRECT 静态校验，不得据此宣称 process/device/multi-policy correlation 已实现。

#### FlowContext Transport / Correlation（P0）

标准 sing-box `http` outbound 不会把 SongsterX 的内部 metadata 自动带到 mitmproxy；`flow.metadata` 也不是 CONNECT 协议字段。因此“在 addon 中读取 metadata”本身不是传输方案。SongsterX 采用明确的 A 方案：**每个 resolved_policy 使用独立的 backend bridge，并由 Context Relay 提供显式上下文传输**。

一次连接的协议闭环如下：

```
IngressAdapter（消费 FlowTapPre/FlowTapRoute 已生成的 resolved FlowContext；不重新生成 flow_id，也不重新运行 PolicyEngine）
  1. 接收并校验既有 flow_id、selected_policy_ref、resolved_policy
     、policy_resolution_generation 和 config_generation_id
  2. 将同一份已解析 FlowContext 更新/确认到 Controller FlowRegistry
  3. 为此次 flow 生成 backend_ingress_id 和一次性
     proxy_correlation_token（随机值 + 绑定 flow/generation 的认证标签），
     再生成 relay_ticket（flow_id、resolved_policy、
     policy_resolution_generation、config_generation_id、
     backend_ingress_id、proxy_correlation_token、5-tuple、过期时间）
        │ Controller UDS control channel
        ▼
ContextRelay
  4. 校验 ticket，绑定 backend_ingress_id
  5. 调用 resolved_policy 对应的 PerPolicyProxyAdapter；它将原始
     TUN flow 编码成 regular-proxy HTTP/CONNECT，并在首个 request/CONNECT
     的 X-SongsterX-Relay-Token header 中携带一次性 token
  6. 通过受保护 UDS 写入 token → context 的单次消费映射，供
     SongsterXMitmproxyFrontend 绑定 mitmproxy-side connection
        │ data plane + UDS side channel
        ▼
MitmproxyBackend / SongsterXMitmproxyFrontend / SongsterXMitmAddon
  7. BackendIngress 在真实 client socket accept/FD handoff 时原子绑定
     backend_ingress_id；PerPolicyProxyAdapter 创建 mitmproxy-facing
     connection 时保留该绑定，并在首个 request/CONNECT 发送 token
  8. 自研 SongsterXMitmproxyFrontend 在 HTTPFlow 对 addon 可见前提取
     X-SongsterX-Relay-Token，原子消费 UDS 映射，将 token 绑定到当前
     client_conn，删除该 header（绝不转发给 upstream），再写入
     flow.metadata["songsterx"]
  9. addon 以 flow_id 取回 selected_policy_ref、resolved_policy、
     policy_resolution_generation、source、device、process
 10. context 缺失、过期、policy_resolution_generation 或 5-tuple
     不匹配时拒绝关联并按 fail_closed 策略处理
 11. MitmproxyBackend 只连接到该 policy 的固定 bridge
     → mixed-in-{policy}:2081+
     → sing-box selected outbound
```

`backend_ingress_id` 是每条 BackendIngress client socket 唯一的随机标识，必须在 accept/FD handoff 时与真实 socket 原子绑定；一条 BackendIngress client connection 必须一对一对应一条 mitmproxy-facing connection。两者之间不能只靠拓扑推断：`PerPolicyProxyAdapter` 必须先删除或覆盖用户原始请求中可能存在的 `X-SongsterX-Relay-Token`，再在首个 HTTP absolute-form request 或 HTTPS CONNECT 中写入内部 token。token 为一次性、短 TTL、不可猜测且绑定 `flow_id`、`backend_ingress_id`、`resolved_policy`、`policy_resolution_generation`、`config_generation_id` 和 `expires_at` 的认证 opaque 值；SongsterXMitmproxyFrontend 通过 UDS 原子消费 token → context 映射，绑定当前 `client_conn` 后立即删除 header，禁止进入 upstream。无效、重复、重放、过期、generation 不匹配或绑定到其他 `client_conn` 的 token 一律 fail closed。stock mitmproxy 不负责这个 carrier、外部 FD handoff 或 metadata transport；这些是 SongsterX 自研 frontend/adapter 的职责。side channel 使用本机 Unix domain socket、短 TTL、单次消费、权限校验和 generation 校验；数据面只承载字节流，不能由请求方伪造上下文。Controller 维护：

```
FlowRegistry[flow_id] = {
  original_5tuple, selected_policy_ref, resolved_policy,
  policy_resolution_generation,
  source_process, source_pid,
  source_ip, source_mac, device_id, device_name,
  backend_ingress_id, backend_socket_fingerprint,
  proxy_correlation_token_hash,  # canonical binding fields above
  config_generation_id, expires_at
}
```

这是 Controller/ContextRelay/MitmproxyBackend 的 P0 接口，不是当前普通 sing-box 配置已经提供的能力。当前仓库仅提供“用于 M0 单策略 DIRECT 链路的静态设计/配置基线”；在该协议实现并通过 100+ 并发关联测试前，不得宣称多策略 MITM 已支持。

规则决策和 HTTP Processing 是正交维度：

```
第一次路由
  ├─ selected_policy_ref = Final / Backup / ...
  └─ resolved_policy = DIRECT / Proxy / HK / JP
     http_processing_required = true/false

需要 HTTP Processing：
  请求 → HTTPBackend → 原 resolved_policy 出口
不需要：
  请求 → 原 resolved_policy 出口
```

严禁 MITM 进入 mixed-in 后统一强制 proxy，否则会丢失第一次策略决策和进程/设备上下文。

### 4.3 MITM policy-preservation

这是 P0：

1. M0 只做单策略 DIRECT 链路：TUN → selected_policy_ref=Final / resolved_policy=DIRECT → ContextRelay → mitmproxy-direct → mixed-in-direct → DIRECT。此阶段只能证明 MITM 可用，不能宣称多策略保持。
2. M1 采用每个策略一个 BackendIngress（8181+ / UDS）+ MitmproxyBackend + 固定 post-MITM bridge：例如 BackendIngress-direct:8181 → mitmproxy-direct → mixed-in-direct:2081、BackendIngress-proxy:8182 → mitmproxy-proxy → mixed-in-proxy:2082、BackendIngress-hk:8183 → mitmproxy-hk → mixed-in-hk:2083；每个 bridge 在 sing-box 中固定到对应 outbound。
3. Context Relay 只负责把已由 FlowTap 注册的数据连接送入对应 BackendIngress；BackendIngress 在真实 socket accept/FD handoff 时原子绑定 backend_ingress_id，再交给 MitmproxyBackend。MitmproxyBackend 完成 HTTP Processing 后，才通过该策略固定 bridge 回到 sing-box。禁止 ContextRelay 直接绕过 mitmproxy 进入 bridge，也禁止依赖单一静态 upstream 来实现 per-flow 动态出口；标准 sing-box HTTP outbound 也不能被假定为 metadata transport。
4. 每个 backend 只接受已注册且未过期的 flow_id；resolved_policy、selected_policy_ref、source/device/process、policy_resolution_generation 或 config_generation 不一致时 fail closed。未完成多 bridge、side channel 和并发关联测试前，MITM + 多策略标为 △。

BackendIngress 的字节协议固定为 mitmproxy regular proxy mode：普通 HTTP 使用 absolute-form request，HTTPS 使用 `CONNECT host:port`。在 `songsterx-singbox` 内由每个策略的 `PerPolicyProxyAdapter` 作为 wire-format 和 correlation-carrier producer：它把原始 TUN flow 编码为 HTTP proxy request 或 CONNECT，在首个 request/CONNECT 添加 `X-SongsterX-Relay-Token`，CONNECT 成功后才对隧道 payload 做 byte-preserving relay。ContextRelay 负责 ticket/context 校验和连接转运，不把原始透明流量直接伪装成 SOCKS 或 regular proxy。BackendIngress wrapper 负责真实 client socket 与 `backend_ingress_id` 的绑定；SongsterXMitmproxyFrontend 负责从首个 request/CONNECT 取 token、通过 UDS 绑定 mitmproxy `client_conn` 并删除 header。不能假定 stock mitmproxy 原生接受任意外部 FD handoff 或外部 metadata。若未来采用 transparent/custom frontend，必须另设协议和 conformance fixture。

BackendRegistry 按 `resolved_policy` lazy instantiate backend，设置最大 backend pool、idle eviction、启动超时和故障熔断；不因订阅中存在 100~500 个节点而无条件预启动同等数量的 Python/mitmproxy 实例。

稳定接口：

```
HTTPBackend
├── start / stop
├── handle_request(context, request)
├── handle_response(context, response)
├── make_local_response(context, request)
├── modify_body(context, body)
├── websocket_message(context, message)
├── attach_resolved_policy(context, resolved_policy)
└── flow_end(context)
```

Mitmproxy addon 的明确输入契约是：Context Relay/自定义 backend adapter 在 flow 进入 HTTP Processing 前写入 `flow.metadata["songsterx"]`。stock mitmproxy 本身不会读取 Controller 的 FlowRegistry，也不会自动生成这些字段；因此 addon 只能校验、读取和记录上下文，不能自行猜测 policy 或恢复进程/设备身份。

当前使用 MitmproxyBackend，未来可以替换 Rust/hyper/hudsucker，不重写 Profile、Policy、Script、Flow 和 Dashboard。

### 4.4 组件边界

- Controller/Surge Runtime：Profile IR、Module、PolicyEngine、RuleCompiler、HTTP pipeline、脚本、原子切换、Flow Store、API。
- sing-box：TUN、TCP、UDP、DNS、FakeIP、代理协议、基础 Route、Selector、URLTest。
- MitmproxyBackend：TLS MITM、HTTP/1/2、WebSocket、gRPC 基础处理、Flow、Hook、Map/Rewrite、Replay。
- Native macOS Layer：权限、System Proxy、网络变化、SSID、Keychain、CA trust UI、launchd/helper。
- Linux guest Gateway：L3 Gateway semantics（构建在 vfkit virtio-net 上）、Ethernet、ARP、IPv4、IPv6、NDP、RA、DHCP、DeviceRegistry、LAN ACL、UDP Fast Path。
- Network Service：独立监听器、TCP Port Forwarding、目标连接、IPv4/IPv6 绑定和 ACL。guest Gateway 可以为它提供设备与地址信息，但不拥有 Port Forwarding 功能。

## 5. HTTP Processing 语义

### 5.1 固定顺序

```
Request:
  HTTP parse
    → URL Rewrite
    → Header Rewrite
    → Body Rewrite (Surge fixed buffering semantics)
    → request Script (optional body contract)
    → upstream using resolved_policy

Response:
  HTTP parse
    → Header Rewrite
    → Body Rewrite (Surge fixed buffering semantics)
    → response Script (optional body contract)
    → client
```

Map Local 是 request-path short-circuit：命中后生成 local response，不访问 upstream。官方文档没有把 Map Local 相对 Script 的位置作为可依赖的固定编号；SongsterX 将其作为独立短路分支，并用 conformance test 锁定兼容行为，而不是在设计文档中武断指定它位于 Body Rewrite 和 Script 之间。Python hook 不等于 Surge JS。

### 5.2 Body 和脚本约束

Body Rewrite 和 HTTP Script 使用两套不同的语义，不能共用一个 generic body rule model：

| 能力 | 兼容语义 |
|---|---|
| Surge Body Rewrite | 自带 buffering；request/response body 上限、response 超限 passthrough 和 request 使用 chunked 或 `Expect: 100-continue` 时的行为由 `surge_compat_version` 查版本矩阵；当前公开实现的约 32 MiB/10 MiB 只作为待验证的版本化 fixture，不是 SongsterX 永久协议常量。 |
| Surge HTTP Script body | 由 `requires-body`、`max-size`、`binary-body-mode` 控制；request 超限终止，response 超限 passthrough；必须分别记录 body 是否可读、是否可写和是否 streaming。 |
| SongsterX Python hook | 当前 addon 只做 bounded inspection，不实现上面任一套完整兼容语义；超限不允许悄悄改写部分 body。 |

Body Rewrite 规则必须单独描述 content-encoding、固定 buffering、chunked/100-continue 行为；Script 规则才可以声明 `requires-body`、`max-size`、`binary-body-mode`。`full-header-mode` 是 HTTP Runtime / `[General]` 级全局选项，使 Header Rewrite、Script、Capture 等看到完整重复 Header，不属于某一条 Script 的 body 参数。大 body 默认流式转发，`stream_large_bodies` 开启后不能假设 body 仍可修改。

完整 Surge JS 需要 JavaScriptCore、WebView、request/response/httpClient/persistentStore/notification/httpAPI 桥接、done 生命周期、超时、取消、full-header、JSC session 上限和 WebView session 上限。

当前产品状态必须显示：

```
HTTP hook: supported
Surge JavaScript compatibility: HTTP Script subset via QuickJS
```

## 6. vfkit / Linux Gateway VM

### 6.1 目标

```
LAN devices
  → Linux guest Gateway（L3 Gateway semantics on top of vfkit virtio-net）
      ├─ Ethernet / ARP / IPv4
      ├─ IPv6 / NDP / RA
      ├─ DHCP
      ├─ DeviceRegistry
      ├─ LAN ACL
      └─ UDP Fast Path
  → Network Service（独立 TCP Port Forwarding）
  → sing-box `tun0` L3/L4
  → HTTPProcessingRuntime (selected hosts only)
  → selected policy egress
```

ip_forwarding + shell NAT/DHCP 可用于 Linux/OpenWrt 早期适配，不能作为 Surge Mac 6 目标架构。

### 6.2 DHCP、双栈、设备

Linux guest Gateway 后续必须实现 DHCP Discover/Offer/Request/Ack、lease time、单客户端单 lease、地址冲突 ping check、默认网关和 DNS，以及 IPv6 NDP、RA、IPv6 gateway 和 hostname 绑定。只有 DHCPv4 没有 NDP/RA 的网关不算完整双栈。

DeviceRegistry 至少保存：

```
device_id, mac, ipv4[], ipv6[], dhcp_hostname
custom_name, vendor, first_seen, last_seen
upload, download, active_flows
fast_path_enabled, handled_by_proxy
```

SRC-IP、DEVICE-NAME、MAC-ADDRESS 从 DeviceRegistry 生成 FlowContext，不依赖 sing-box 某个版本才有设备身份。

UDP Fast Path：设备 1 秒 10 个或 10 秒 30 个短 UDP flow 时进入候选；低于 1024 的端口正常处理；destination address 是 FakeIP 时**禁止**进入 fast path；可按设备开关；绕过 L4 proxy、细粒度规则和 MITM，只做 L3 forwarding；进入和退出记录原因、设备、时间和统计。不能默认对所有设备开启，否则会丢失 FakeIP → domain mapping 和规则语义。

Network Service 的 TCP Port Forwarding 独立定义监听地址、端口、目标设备、目标端口、入站 ACL、IPv4/IPv6 绑定和规则优先级。Surge parity 第一阶段只承诺 TCP；UDP forwarding 是后续独立能力，不能从 guest Gateway 的泛化描述中推导出来。

### 6.3 macOS 部署与权限边界

本项目由外部 `vmnet-helper` 持有 Apple vmnet 附件，vfkit 通过 Unix socket 接入两张 virtio-net；应用本身不把 LAN Ethernet 转成 macOS TUN。vmnet-helper 的安装、签名、root/sudoers 规则和系统版本限制必须按其项目文档独立验证，不能把应用签名当作 helper 权限的替代品。

这是一项生产发布 gate：Linux guest 是 Gateway data plane，supervisor 启动时会真实验收进程、guest-agent、配置激活和 `networkReady`；应用随后读取 guest LAN/`tun0` 计数器，只有当前会话观察到两侧新增流量才把 packet path 标为已验收，这仍不代替真实 IPv4 的 ARP/TCP/UDP/DNS/MITM 协议测试。DHCP、IPv6/RA 不在本模式范围内；实体客户端接入前仍必须确认 helper 安装、签名、权限、sandbox model、管理员授权边界和 LAN 双向流量。

## 7. DNS、QUIC、IPv6、CA

### 7.1 DNS 泄漏

验收定义：

> 受管系统的传统 UDP/TCP 53 查询和 Gateway DNS 查询不得出现非预期旁路；应用自有 DoH/DoH3/DoQ、bootstrap、代理节点域名解析和 IPv6 DNS 必须单独测试并按 policy 记录。

示例配置中的 sing-box `local` DNS 只用于验证基础解析和配置结构，不代表生产环境的隐私保护或“无泄漏”实现；生产配置必须显式选择受管 DNS、bootstrap 和代理节点解析路径，并运行上述审计。

### 7.2 QUIC

禁止全局 UDP/443 reject 作为默认行为。使用 per-policy force_tcp 或 block_quic，只对需要 MITM 的 domain/process/device 生效；其他 QUIC 按原 resolved_policy；阻断后记录 TCP fallback 或无 fallback 的失败原因。示例配置显式启用 `http`、`tls`、`quic` 和 `dns` sniffing，先取得 QUIC SNI/DNS protocol 再匹配 rule；没有对应 sniffer 时，不能声称按域名或 DNS protocol 可靠命中。

### 7.3 IPv6

必须覆盖 TUN IPv6、IPv6-only、IPv6 proxy、IPv6 MITM、AAAA/DNS64/Happy Eyeballs、Gateway NDP/RA、IPv6 source rule 和 IPv6 leak。示例 TUN IPv6 地址不代表 Gateway 双栈已完成。

### 7.4 CA

开发阶段可以使用 mitm.it。产品阶段使用 Native CertificateManager 和 Keychain，支持生成、public certificate 导出、轮换、删除、reset、有效期、hostname SAN、上游验证、mTLS 和 pinning 诊断。默认不关闭 upstream certificate verification。

## 8. sing-box 适配

Controller 保存 sing_box_version、feature_matrix_version、config_schema_version。当前按 1.13.14 校验。生成器必须使用 route action reject、WireGuard Endpoint、guest Gateway/Controller 设备身份，不能把 Apple 图形客户端能力假定为独立 CLI 能力。

sing-box 负责 TCP/UDP/DNS/代理协议；Controller 负责 Profile、Module、策略和健康状态；Mitmproxy 只作为 HTTPBackend；guest Gateway 不把所有 LAN 流量送进 Python；未加入 MITM 的 HTTPS 必须 passthrough；HTTPBackend 停止时明确 fail_closed 或 bypass。

## 9. Profile IR 和 PolicyEngine

```
version: 1
profile:
  name: default
  platform: macos
  sing_box:
    minimum: 1.13.14

listeners:
  mixed: 127.0.0.1:2080
  http_backend:
    m0_management_listener: 127.0.0.1:8080
    m1_data_plane: per_policy_backend_ingress
  control_api: 127.0.0.1:9090

policies:
  - id: direct
    type: direct
  - id: proxy
    type: provider_ref
    provider_ref: user-selected-proxy
    required: true

policy_groups:
  - id: final
    type: select
    members: [proxy, direct]
  - id: backup
    type: fallback
    members: [proxy, direct]

rules:
  - match: {domain_suffix: [example.com]}
    action: {selected_policy_ref: final, http_processing: true}
  - match: {ip_is_private: true}
    action: {selected_policy_ref: direct, http_processing: false}
  - action: {selected_policy_ref: final, http_processing: false}

http_processing:
  hosts: [api.example.com]
  pipeline: [url_rewrite, header_rewrite, body_rewrite, script]
  full_header_mode: true
  surge_compat_version: surge-mac-6.x
  body_rewrite:
    limits: derived_from_compatibility_matrix
    over_limit: matrix_defined_response_passthrough_request_abort
    chunked_expect_100_continue: matrix_defined
  script_body:
    requires_body: false
    max_size: 1048576
    binary_body_mode: false
    unsupported_binary_body_policy: reject

gateway:
  enabled: false
  mode: vmnet_l2
  dhcp: false
  ipv6_ra: false
  udp_fast_path: false
```

PolicyEngine 必须分别实现 select、url-test、fallback、load-balance、smart、subnet，并明确以下语义：nested group 展开、cycle 拒绝、empty group 的错误状态、手动 selector/automatic group temporary override 的持久化与清除、url-test 的 `interval`/`tolerance`/`evaluate-before-use`、fallback 的 `interval`/`timeout`/健康检查顺序、load-balance `persistent=true` 按目标 hostname 保持策略、Smart 的真实连接首字节延迟/retransmission/URL test/retry candidate（未实现前只能叫 smart-like）、Subnet 的 `SSID`/`BSSID`/`ROUTER`/`TYPE`/`default` 变量，以及 policy including 的 `policy-path`、`update-interval`、`include-all-proxies`、`include-other-group`、`policy-regex-filter`、`external-policy-modifier`、`external-policy-name-prefix`。偶尔切换 selector 不能模拟 load-balance；每次决策写入 FlowContext 并可审计。

Module Engine 必须完成来源/HTTPS/hash 校验、解析、`%APPEND%`、`%INSERT%`、override、Arguments/Requirement 求值、优先级合并、来源映射和失败回滚。必须拒绝 Module 修改 `[Proxy]`、`[Proxy Group]` 和 MITM CA；`#!system=mac`、`#!name`、`#!desc`、`#!arguments`、`#!requirement` 属于 Module metadata，必须解析，其中 `#!system` 用于平台筛选而不是简单拒绝。允许 section whitelist 还要覆盖 `[WireGuard *]`、`[Ruleset *]`；`[MITM]` 只允许显式字段 `hostname`、`skip-server-cert-verify`、`tcp-connection`，其余字段拒绝。Module Rule 只能使用允许的 internal policy。`[Rule]`、`[Script]`、`[URL Rewrite]`、`[Header Rewrite]`、`[Host]` 等 section 按主配置顶部插入语义处理。`#!requirement=`（Module-level）与 `#!REQUIREMENT`（line-level）分开解析；invalid section、循环引用和 requirement 不满足都要产生可审计的拒绝原因。

Surge JS Runtime 的规格还必须列出 `generic`、`http-request`、`http-response`、`rule`、`dns`、`event`、`cron` 七类 Script type，以及 remote `script-path` 下载/缓存、`script-update-interval`、`pattern` first-match-only、`debug`、`$argument`、`$script`、`$environment`、`$network`、`$trigger`、timeout、event-name 和 cronexp。当前实现仍为未实现，不得以 Python addon 替代。

## 10. Controller、API、进程

建议目录：

```
controller/
  main.py, schema.py, profile_loader.py, module_parser.py
  ir.py, rule_compiler.py, policy_engine.py, flow_context.py
  http_processing.py, surge_js_runtime.py
  singbox_renderer.py, mitm_renderer.py, gateway_bridge.py
  context_relay.py, flow_registry.py
  process_manager.py, healthcheck.py, api.py, metrics.py, scheduler.py
```

Clash API 仅作为 adapter。SongsterX Control API 要覆盖 feature toggles、policies、groups、profiles、modules、rules、rewrites、scripts、Flow、kill request、DNS audit、devices、DHCP、Port Forwarding、Fast Path、CA/Keychain、events、health、traffic、metrics、dry-run、apply、rollback。

配置切换（transactional best-effort reload with rollback，不把多进程状态误称为严格 atomic）：

```
生成 generation=v2 的 config.tmp
  → schema validate → render all components
  → sing-box check → backend/gateway dry run
  → Controller prepare(v2)
  → sing-box/ContextRelay/Mitmproxy/Gateway ready(v2)
  → commit(v2)；每个组件回报实际 generation
  → atomic rename + reload
  → healthcheck 与 generation 一致性检查
  → active(v2) 或恢复上一代并 rollback
```

如果任一组件仍运行 v1，Controller 必须把状态标为 generation mismatch，并停止新 flow 的 MITM/策略切换；文件 rename 的 atomic 性不能掩盖多进程运行状态的不一致。

端口：2080 本机 mixed；2081+ per-policy post-MITM bridge；8181+ per-policy BackendIngress；8080/808x MitmproxyBackend 管理入口；8081 mitmweb；9090 Control API；LAN Gateway guest agent。除显式 Gateway 模式外均只监听 127.0.0.1。

## 11. 安全

- Gateway LAN 模式显式启用、防火墙和 ACL。
- Control API、mitmweb 不暴露公网。
- loopback Control API 使用 token；LAN API 必须显式启用、TLS、token 和 ACL；Web dashboard 使用 CSRF/origin policy，不能只依赖“监听 127.0.0.1”。
- API 的配置 apply、Flow kill、CA、Gateway 和设备操作写入审计日志并带 config generation。
- 如果提供 Surge HTTP API 兼容层，支持 `X-Key` 认证语义；SongsterX 原生 API 仍使用独立 token、TLS 和 ACL contract。
- CA 私钥进入 Keychain/受保护目录，永不进 Git。
- 节点密码、UUID、Token 使用 secret 文件或环境变量。
- 远程 Module/rule-set 使用 HTTPS、来源、hash、版本锁定。
- 脚本有超时、内存/Body 上限、取消和异常隔离。
- 记录 MITM、Fast Path、DNS bypass、policy downgrade。
- 每类流量明确 bypass/fail_closed，故障时不能隐式降级。

## 12. 测试方案

### 12.1 静态和生成器

```
sing-box version
sing-box check -c config/sing-box.example.json
sing-box format -c config/sing-box.example.json >/dev/null
jq empty config/sing-box.example.json
python3 -m py_compile scripts/mitm_addon.py
```

还要测试旧字段拒绝、reject action、WireGuard Endpoint、mixed-in 防环路、无 external localhost SOCKS 默认出口和失败回滚。

### 12.2 P0 路由

- process + MITM + DIRECT 最终仍为 DIRECT。
- process + MITM + Proxy 最终仍为 Proxy。
- domain + selector 的 selected policy 可审计。
- source IP/device/process 穿越 Context Relay/backend 不丢失，并由唯一 flow_id 关联；backend 根据 resolved_policy 选 bridge。
- 多 bridge 每个策略只到自己的 outbound。
- 100+ 同目的地并发 flow 不串 context，过期 ticket 和 generation mismatch 必须拒绝。
- 100+ 同目的地并发 flow 的 `BackendIngress socket → mitmproxy-facing socket → HTTPFlow` 链路中，每个 HTTPFlow 必须通过一次性 `X-SongsterX-Relay-Token` 唯一恢复正确的 `backend_ingress_id`/`flow_id`。
- ContextRelay 不得直接连接 2081+；必须经过对应 8181+/UDS BackendIngress 和 MitmproxyBackend。
- mitmproxy 停止按配置 fail closed/bypass，不死循环。
- sing-box 停止清理 TUN，系统恢复或明确失败。
- network switch、sleep/wake、proxy endpoint 变化。

### 12.3 P0 HTTP/TLS

HTTP/1、HTTP/2、WebSocket、gRPC、trailers；TLS 1.2/1.3、ALPN、SNI、无 SNI；duplicate Set-Cookie、`full_header_mode`；gzip/br/zstd/chunked；100 MB streaming body；Body Rewrite 版本矩阵限制；Script 的 requires-body/max-size/binary-body-mode；invalid upstream cert、mTLS、pinning；Map Local request-path short circuit；URL → Header → Body → Script 的顺序和 Map Local 相对行为由 conformance fixture 验证。

### 12.4 P0 DNS/QUIC/IPv6

UDP/TCP 53、DoH/DoH3/DoT/DoQ、bootstrap、proxy hostname、系统 resolver、AAAA、IPv6-only、IPv6 proxy、IPv6 MITM、NDP、RA、IPv6 gateway、per-policy block-quic、TCP fallback、无 fallback 失败、应用私有 DoH/DoQ 单独审计。

### 12.5 Gateway 与故障安全

DHCP lease、单客户端 lease、冲突检测、ARP/NDP/RA、双栈、DeviceRegistry、SRC-IP/DEVICE-NAME/MAC-ADDRESS、独立 TCP Port Forwarding ACL、Fast Path 阈值/开关/低端口豁免/FakeIP 排除/统计、设备离线重连和 MAC 随机化。还要测试 sing-box/mitmproxy/Controller 崩溃、schema/渲染/reload 回滚、CA 轮换和日志不泄漏密钥。

### 12.6 Conformance 验收格式

任何矩阵能力都必须绑定一个 fixture、expected result、platform、component versions 和 failure assertion；§3 的 ✅ 只表示上游 primitive 存在，不能被解释为 SongsterX 已通过 conformance。只有当对应 fixture 通过后，独立的 `SongsterX implementation_status` 才能标为 verified；当前仓库仍以 planned/partial/design 为准。最低 conformance 集：

| 测试组 | Fixture / expected result | 失败判定 |
|---|---|---|
| FlowContext correlation | 100+ 并发、相同 destination、不同 process/device/policy；每个 backend flow 精确回到唯一 `flow_id` | 任一 context 串线、过期仍被接受或 generation 不一致 |
| FlowContext producer hook | 原始 TUN/packet flow 出现后，唯一生成点 `FlowTapPre` 同步创建 pending `flow_id`；sniff 后由 `FlowTapRoute` 在同一记录写入 selected rule、resolved policy、`policy_resolution_generation`、process/device，并在进入 HTTPBackend 前可查询；IngressAdapter 只消费该既有 context | 重复生成 `flow_id`、重复运行 PolicyEngine、依赖事后日志/API、producer hook 超时后仍放行，或任一字段只能靠猜测恢复 |
| Backend ingress binding | `backend_ingress_id` 在 8181+/UDS 的真实 client socket accept/FD handoff 时原子绑定；一条 BackendIngress client connection 一对一对应一条 mitmproxy-facing connection；ContextRelay → BackendIngress → MitmproxyBackend → 2081+ post-MITM bridge | side-channel ID 无 socket binding、一对多/多对一复用、ContextRelay 直达 bridge、或 resolved policy 与 bridge 不一致 |
| Proxy correlation carrier | `PerPolicyProxyAdapter` 先覆盖用户同名 header，再在首个 HTTP absolute-form/HTTPS CONNECT 中携带一次性 `X-SongsterX-Relay-Token`；SongsterXMitmproxyFrontend 原子消费 token → context 映射、绑定 `client_conn`、删除 header；100+ 并发每个 HTTPFlow 唯一恢复正确 `backend_ingress_id`/`flow_id` | token 重放/碰撞/过期、canonical binding 或 `client_conn` 不匹配、header 泄漏到 upstream、或任一 HTTPFlow 串线 |
| Regular-proxy wire | `PerPolicyProxyAdapter` 将 HTTP 编码为 absolute-form、HTTPS 编码为 `CONNECT host:port`；CONNECT 成功后 payload byte-preserving；ContextRelay 不把透明 TLS 直接喂给 regular proxy listener | 请求行/CONNECT 形态错误、CONNECT 前后字节边界错误、或原始透明流误送 regular proxy |
| QUIC | UDP/443、QUIC SNI=example.com、无 FakeIP；QUIC sniffer 提取 SNI，domain rule 命中并按 policy reject/force-TCP | 没有 SNI 仍误判为域名命中，或 FakeIP/非目标域名错误进入规则 |
| Policy Group | nested group、cycle、empty group、persistent load-balance、manual override、network change、Smart retry | 无限递归、空组静默直连、重启后选择不符合声明或 override 被错误覆盖 |
| Module golden | override、`%APPEND%`、`%INSERT%`、Arguments、Module/line Requirement、invalid section、rule insertion order | 修改禁止 section、插入顺序漂移或 requirement 失败仍激活 |
| Body Rewrite vs Script Body | 由 `surge_compat_version` 得到的 request/response 边界、chunked/`Expect: 100-continue`、requires-body、binary body、全局 `full_header_mode` | 两套限制混用、超限半改写、response/request 的 passthrough/abort 反转，或把全局 header 选项当成 Script body 参数 |
| Fast Path | 普通 UDP、低端口、阈值、设备开关、FakeIP destination | FakeIP UDP 进入 fast path，或低端口/关闭设备仍被绕过 |

每个 fixture 记录 macOS/架构、sing-box、mitmproxy、Controller、配置 generation 和日志摘要；失败时必须保留可复现输入，而不是只记录“测试失败”。

## 13. 开发里程碑

### P0：架构和错误承诺

- [ ] FlowContext/Unified Request Context。
- [ ] Context Relay、FlowRegistry、一次性 relay_ticket、backend_ingress_id 和 metadata side channel。
- [ ] outbound policy 与 HTTP Processing 分离。
- [ ] 删除 MITM 直连 Internet 分支。
- [ ] M0 单策略 direct MITM。
- [ ] per-policy bridge。
- [ ] 固定 HTTP pipeline。
- [ ] reject action、WireGuard Endpoint。
- [ ] 移除默认 127.0.0.1:7890 占位。
- [ ] per-policy/per-domain QUIC。
- [ ] 可测试 DNS 泄漏定义。

### P1：Surge 核心运行时

- [ ] fallback/load-balance/smart/subnet。
- [ ] nested/cycle/empty-group/manual-override/persistent-load-balance/Smart retry 语义。
- [ ] Module Parser/Merger、Arguments、Requirement。
- [ ] `%INSERT%`、section restriction、Module-level/line-level Requirement。
- [ ] body modes、full-header、streaming 的完整 Surge 版本矩阵。
- [ ] HTTP/2/gRPC/trailers 测试。
- [x] HTTP Surge Script Runtime：QuickJS bridge；[ ] JSC/WKWebView 完整兼容层。
- [ ] Unified Flow Store、Control API。
- [ ] Native CA/Keychain。
- [ ] SSID/network state 原生采集。
- [ ] 完整 DNS/QUIC/IPv6 测试。

### P2：Surge Mac Gateway

- [◐] vmnet-helper、vfkit/Linux guest Gateway 源码和 guest-agent；已接入当前会话 LAN/`tun0` 计数器验收，仍待实体客户端协议级、helper 权限和真实网络环境验证。
- [ ] DHCP、ARP/NDP/RA、双栈。
- [ ] DeviceRegistry 和设备管理 API/UI。
- [ ] MAC/DEVICE-NAME/SRC-IP。
- [ ] UDP Fast Path。
- [ ] 独立 Network Service 的 TCP Port Forwarding。
- [ ] Dashboard、Logbook、CLI、Prometheus。
- [ ] per-network settings。

### P3：扩展

- [ ] MASQUE/Tailscale 协议矩阵。
- [ ] Ponte/MTProto/Snell Server 评估。
- [ ] iOS/tvOS 原生 VPN。
- [ ] Native/Rust HTTPBackend 可选路径。

## 14. 当前仓库验收状态

已完成：sing-box 1.13.14 示例静态校验（含 QUIC sniffer）、JSON/Python/Markdown 校验、最小 addon 语法校验、设计矩阵/架构/测试/路线更新，以及可重复执行的 `scripts/validate_static.sh`。

未完成：Context Relay/FlowRegistry 实际实现、HTTP/2/gRPC E2E、多策略 MITM policy-preservation、Surge JS 的非 HTTP 类型、Module Engine 完整语义（Requirement/完整合并）、PolicyEngine、Control API、guest VMNET/DHCP/DeviceRegistry/UDP Fast Path。

本仓库当前是可验证的设计基线和最小链路，不是已完成的 Surge 替代品。

## 15. 官方参考

- [Surge Manual](https://manual.nssurge.com/)
- [Surge Policy Groups](https://manual.nssurge.com/policy-groups/overview.html)
- [Surge HTTP Processing](https://manual.nssurge.com/http/overview.html)
- [Surge Scripting](https://manual.nssurge.com/scripting/overview.html)
- [Surge Gateway](https://manual.nssurge.com/features/gateway.html)
- [Surge DHCP](https://manual.nssurge.com/features/dhcp.html)
- [Surge HTTP API](https://manual.nssurge.com/tools/http-api.html)
- [Surge Mac 6 Release Notes](https://kb.nssurge.com/surge-knowledge-base/release-notes/surge-mac-6-release-note)
- [Apple VMNET](https://developer.apple.com/documentation/vmnet)
- [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [sing-box Route Rule](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box DNS](https://sing-box.sagernet.org/configuration/dns/)
- [sing-box WireGuard](https://sing-box.sagernet.org/configuration/outbound/wireguard/)
- [sing-box Deprecated](https://sing-box.sagernet.org/deprecated/)
- [mitmproxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [mitmproxy Protocols](https://docs.mitmproxy.org/stable/concepts/protocols/)
- [mitmproxy Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [mitmproxy Addons](https://docs.mitmproxy.org/stable/addons/overview/)
- [mitmproxy Options](https://docs.mitmproxy.org/stable/concepts/options/)
