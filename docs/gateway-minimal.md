# macOS Surge 局域网网关最小方案（不含 DHCP）

本方案把已提供的 `Default.conf` 和 `Untitled-1.md` 适配为 SongsterX 的最小 M0 链路。目标是：Mac 通过 VMNET Bridged Mode 接入物理局域网，为同一局域网内的其他设备提供三层网关；客户端保留现有 IP，只手工把默认网关和 DNS 指向 SongsterX；系统不启动 DHCP，也不启动 IPv6 Router Advertisement。

当前实现状态：Gateway 使用 `vfkit + 极简 Linux guest`，双 virtio-net、guest 网络脚本、
guest-agent 控制通道、最终 authenticated status 和 supervisor readiness 已接通。应用不会把
“配置同步成功”冒充为实体 LAN 已验收：supervisor 启动后状态保持“等待局域网验收”，后台持续读取
guest LAN 与 `tun0` 计数器，只有实体客户端产生两侧新增流量才标记 packet path 已验收。该观测不是
完整的 ARP、TCP、UDP、DNS 或 MITM 协议测试；客户端仍由用户手工配置并做现场验证。DHCP、IPv6/RA
明确不在本模式范围内。vfkit 契约详见 `docs/vfkit-gateway.md`。

这里的“网关 IP”是局域网内未占用、由客户端使用的网关地址；它必须和物理局域网处于同一网段。物理网卡由设置页指定，例如 `en0`，不能再使用独立的 `192.168.88.0/24` 虚拟网段。SongsterX 不修改本机默认路由，也不把本机 Enhanced Mode 冒充成局域网网关。

网关参数直接写在 `SongsterX.conf`，不需要额外的网关 JSON：

```ini
[General]
mode = gateway-no-dhcp
listen = 127.0.0.1
port = 2080
dns-mode = fakeip
gateway-guest-lan-selector = "if:eth0"
gateway-guest-host-selector = "if:eth1"
gateway-upstream-gateway = 192.168.88.1

[Gateway]
enabled = true
interface = en0
gateway-ip = 192.168.88.2
cidr = 192.168.88.0/24
dns-ip = 198.18.0.2
dhcp = false
ipv6 = false
client-policy = all
clients = ""
```

`client-policy = all` 时，应用从 `interface` 对应的物理网卡读取 IPv4 地址和掩码，再由 Linux guest 在该 LAN 内通过 ARP/IPv4 处理客户端的 IP/MAC。两张 guest virtio-net 默认按设备顺序绑定为 `if:eth0`（LAN）和 `if:eth1`（host-only）；allowlist 当前拒绝启动，实体客户端仍需现场验证。

## 1. 先说边界：sing-box 本身不能完成 macOS 局域网网关接管

sing-box 的 TUN 入站可以在 macOS 上建立本机 TUN，但 macOS 版本没有 Linux `auto_redirect` 那种把独立 LAN 二层帧直接送入 TUN 的能力。因此不能把“启动 sing-box TUN”误写成“已经接管了所有 LAN 客户端”。

目标数据流需要 `vmnet-helper` 负责 Apple vmnet 接口、权限和生命周期，vfkit 提供两张 virtio-net，Linux guest 内的 gateway-agent/sing-box 负责 LAN 三层处理。macOS host 只保留 Mixed 入口；不能把下面的目标图当作已联通链路：

```text
局域网客户端（动态学习或可选名单）
  │ 保留现有 IP，手工设置 LAN Gateway/FakeIP DNS
  ▼
`vmnet-helper --operation-mode=bridged`（物理 LAN 二层）
  ▼
Linux guest Gateway（三层转发、ARP/邻居处理、无 DHCP/无 RA）
  ▼
Linux guest `tun0`
  ▼
sing-box FakeIP DNS + route/policy
  ├─ api.day.app → mitmproxy → 127.0.0.1:2081 → sing-box direct bridge
  ├─ Final → smart(tunnel / snell-bridge) 或 direct
  └─ tcp/8000 → reject
```

仓库包含 `vmnet-helper` 的源码、构建脚本及 arm64 资源；Release `.app` 打包 helper、vfkit 和 Linux guest 镜像。`scripts/run_gateway_minimal.sh --check` 只验证 Gateway 契约，不能代替真实 LAN 客户端现场验证。当前 supervisor 的无特权 vmnet-helper 路径要求 macOS 26 或更高版本；macOS 15 及更早版本必须先实现受信任的 root-owned privileged helper，应用会在启动前 fail-fast，不会把权限问题伪装成 `VMNET_FAILURE`。应用启动时会检查 guest runtime readiness，UI 另以当前会话的 LAN/`tun0` 计数器验收 packet path；防火墙对未被 `tun0` 接管的 LAN forwarding 仍保持 fail-closed。

## 2. 输入配置的适配关系

| `Default.conf` 能力 | M0 适配 |
| --- | --- |
| Trojan + WebSocket + TLS | `tunnel` 原生 sing-box Trojan outbound |
| Snell v4 + HTTP obfs | 通过 `127.0.0.1:2082` 的 `snell-bridge` SOCKS outbound；sing-box 1.13.14 不提供原生 Snell outbound，外接 Snell v4 bridge 才能启用 |
| `smart` / `Final` | sing-box `urltest` + `selector`；这是 M0 的 local subset + urltest approximation，不是 Surge Smart/外部 policy parity |
| `DEST-PORT,8000,REJECT` | route rule + `block` 行为 |
| OpenAI、ChatGPT、V2EX 等 Final 规则 | domain/domain-suffix route rules |
| 局域网直连 | `ip_is_private → direct`，且使用客户端静态网段 |
| `PROCESS-NAME` | 仅对网关 Mac 本机有意义；远程 LAN 客户端必须改为 source IP/MAC/device rule，M0 不猜测映射 |
| `[Host]` | M0 先保留在 `config/surge-default-adapted.redacted.conf`；转成 sing-box hosts/rule-set 是 P1 |
| `[MITM] api.day.app` | M0 只允许 `api.day.app` 进入 mitmproxy；当前固定回 `DIRECT`，标记为 `forced_direct_m0_semantic_deviation`，不宣称等价于原始 Final |
| Surge JS `EmbyRefresh` | M0 禁用；当前没有 Surge JS runtime |
| `policy-path` | M0 不拉取原策略 URL；保留为脱敏说明，避免把 token 写入配置 |

对应文件：

- `SongsterX.conf` 的 `[Gateway]` 段：vfkit guest、vmnet-helper、无 DHCP 和客户端接入策略的实际控制面配置。
- `config/songsterx.gateway-minimal.conf`：网关 `[Gateway]` 段示例，可直接导入或复制到 `SongsterX.conf`。
- `config/sing-box.gateway-minimal.json`：可由 sing-box 1.13.14 校验的脱敏数据面模板。
- `config/surge-default-adapted.redacted.conf`：供对照的脱敏 Surge 适配稿。

## 3. 手工配置客户端（不启动 DHCP）

以物理局域网 `192.168.1.0/24` 为例，为每台客户端保留原有 IP/掩码，只修改：

```text
IP：      保留现有地址（例如 192.168.1.20）
掩码：    保留现有掩码（例如 255.255.255.0）
网关：    <SONGSTERX_LAN_GATEWAY_IP>
DNS：     198.18.0.2
IPv6：    关闭或不配置
```

SongsterX 设置页保存物理网卡、网关 IP 和客户端策略字段；启动 Gateway 后这些字段会生成 guest 网络配置。macOS host 不创建网关 TUN，Linux guest 使用 `tun0`；客户端仍需手工配置，UI 只有在观察到 LAN/`tun0` 两侧新增计数后才显示 packet path 已验收。

网关本机需要接入上游网络，并由 `vmnet-helper` 持有物理网卡的 VMNET/L2 bridged 附件。仓库中的尖括号值不是可用凭据或网络地址。旧的 standalone runner 已移除；Gateway supervisor 在 vmnet/vfkit/guest-agent runtime readiness 失败时 fail-closed，runtime 成功后 UI 仍等待当前会话的实体流量验收，防火墙会拒绝未被 `tun0` 接管的 LAN forwarding，避免启动后静默放行旁路流量。

网关模式使用 sing-box 1.12+ 的 FakeIP DNS server：A/AAAA 查询映射到 `198.18.0.0/15` 和 `fc00::/18`，`lan`、`local`、`localhost` 仍走系统 DNS；TUN 流量先执行 `resolve`，再按恢复出的域名匹配规则。FakeIP 只在网关模式启用，Mixed 模式继续使用系统 DNS，不修改本机 DNS 或系统路由。

## 4. 模块与远程脚本的离线输入

仓库中的 `modules/` 仅作为开发校验样本，不会随 Release `.app` 预置。用户在设置页导入 `.sgmodule` 或 `.module` 时，可以同时多选模块依赖的脚本和规则集；导入内容会保存到应用数据目录并生成本地哈希清单。仓库当前仍保留一组用于回放测试的模块样本：

- 脚本：`modules/remote-scripts/`
- 数据：`modules/remote-assets/`
- 模块哈希：`config/modules.manifest.yaml`
- 脚本/数据哈希和来源：`config/module-assets.manifest.json`

它们现在进入“已下载、哈希校验、按本地运行时激活”。静态规则和 HTTP 层的 MITM/URL Rewrite/Map Local/Header Rewrite/Body Rewrite 已由本地 Module Engine 接入；脚本在内置 QuickJS 上下文执行，支持请求/响应 body、二进制 body 和模块默认参数。下载不等于安全，也不等于完整实现 Surge Module Engine；完整策略保持、事件脚本和通用远程更新仍未等价。

1. 校验模块和脚本 SHA-256；
2. 将 `script-path` 解析为本地 asset ID，而不是继续运行时拉取 URL；
3. 实现 HTTP request/response、body 解压/重压缩、binary-body-mode、header/url/body rewrite 语义；
4. 为每个脚本提供沙箱、超时、最大 body 大小和权限 allowlist；
5. 注入完整 flow context 后再执行；
6. 逐模块做回放测试，任何失败都 fail-closed。

当前不执行运行时远程下载；模块 MITM 作为 `127.0.0.1:8080` 的内部 upstream，由统一入口 `127.0.0.1:2080` 按主机规则转发，不会自动接管流量。Release `.app` 将携带自包含的 mitmdump 和 QuickJS；开发版若未完成打包或无法找到应用内二进制，会阻止需要 HTTP 引擎的模块启动，不会静默降级成“模块已生效”。

## 5. 启动

先把真实凭据放入当前 shell 或 macOS Keychain 注入层，不能写回仓库：

```bash
export SONGSTERX_TROJAN_PASSWORD='从私有密钥存储读取'
export SONGSTERX_SNELL_PSK='从私有密钥存储读取'
export SONGSTERX_SNELL_BRIDGE_BIN='/绝对路径/snell-bridge-wrapper'
export SONGSTERX_MITMPROXY_CONFDIR='/私有持久路径/songsterx-mitmproxy'
```

安装依赖后先做静态检查：

```bash
brew install sing-box jq mitmproxy
scripts/run_gateway_minimal.sh --check
```

`scripts/run_gateway_minimal.sh --check` 只验证配置、资源闭包和 fail-closed 不变量。实际 Gateway 进程由应用 supervisor 按 bridged vmnet-helper、host-only vmnet-helper、vfkit、guest-agent 的顺序管理；UI 会在当前会话的 guest packet path gate 通过前保持“等待局域网验收”，guest 防火墙只允许 LAN 与 `tun0` 之间的转发。

第一次做 HTTPS MITM 时，还要把 mitmproxy 的 M0 CA 安装到需要测试的客户端；生产环境应改成受控的 macOS Keychain CA，并只信任明确的 MITM 主机。

## 6. 已知未覆盖项

M0 不是完整 Surge 替代品，明确未覆盖：DHCP、IPv6/RA、原生 Snell（由外部 bridge 提供）、旧版 macOS 的 vmnet-helper root/sudoers 自动配置、Surge JS runtime、模块脚本/Body Rewrite/binary body、GeoIP CN、远程客户端的进程名识别、完整 Host 映射、基于多策略的 MITM policy preservation、Dashboard/Controller API、UDP 高性能 fast path。IPv4 guest packet path 只有在当前会话观察到 LAN 与 `tun0` 两侧新增计数后才标记为已验收；这不代替协议级测试，实体客户端接入仍需现场验证。

## 7. 安全要求

原始 `Default.conf` 含控制器 token、代理密码/PSK、MITM 私钥材料、远程策略 token 和真实客户端标识。仓库只保留脱敏占位符；提交网页版审核的材料也只使用脱敏文件。由于这些值曾经出现在配置文件中，正式部署前应轮换所有相关凭据，并将控制器绑定到 `127.0.0.1`，不要监听 `0.0.0.0`。
