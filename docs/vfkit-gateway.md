# vfkit Gateway 第一阶段

SongsterX 的轻量 Gateway 路线使用 `vfkit + 极简 Linux guest + sing-box + gateway-agent`。
它不依赖 macOS host TUN，也不要求在 host 进程里把 LAN Ethernet 转成平台 TUN
packet。Linux guest 自己通过 virtio-net 承担 Gateway data plane。

## 数据面

```text
LAN client
  -> virtio-net #1
  -> vmnet-helper bridged(en0)
  -> Linux guest gateway-agent/sing-box
  -> guest WAN
  -> macOS network

Linux guest
  -> virtio-net #2
  -> vmnet-helper host-only(192.168.250.0/24)
  -> macOS host-only IP 192.168.250.1:8080
  -> host mitmdump
```

第二张 virtio-net 只服务 host 与 guest 之间的 MITM 和管理通道，不能直接暴露在物理
LAN 上。Gateway 不提供 DHCP、IPv6 RA/NDP；客户端的网关和 DNS 仍需要显式配置。
guest tun 的自动路由会排除 LAN 和 host-only 网段，确保客户端回程以及
192.168.250.2 上的 guest-agent 管理连接保持直连。

## 当前实现

`src-tauri/src/vfkit.rs` 已完成以下内容：

- 构造两个 `vmnet-helper` 命令：一个 bridged LAN，一个隔离的 host-only 网络；
- 构造两个 `virtio-net,unixSocketPath=...` 设备参数；
- 构造 kernel、initrd、guest cmdline、CPU、内存和 guest agent 参数；
- 注入并校验 LAN CIDR、上游网关、guest DNS、host-only CIDR，以及 `if:NAME`/`mac:...`
  两张 virtio-net 网卡 selector；默认使用 `if:eth0`（LAN）和 `if:eth1`（host-only），需要时
  才按 MAC 或自定义接口名覆盖；用户 cmdline 不能覆盖 `songsterx.*` 保留参数；
- 校验 host-only 地址、CIDR、socket 路径、资源限制和必要文件；
- 单元测试只生成命令计划，不启动 VM、不请求 root 权限、不下载镜像。

guest initramfs 的网络控制器位于 `guest-runtime/songsterx-gateway-net.sh`。它只配置
guest 自己拥有的两张 virtio-net、默认路由、IPv4 forwarding 和本次创建的防火墙规则；
host-only 网卡不会被转发，且不提供 DHCP、IPv6 RA/NDP。`guest-runtime/init` 先等待
`network.ready`，再启动 guest-agent；agent 的 `ready` 还要求控制监听、sing-box 进程和
readiness 文件同时成立。网络控制器会把 `songsterx.dns_server` 原子写入 guest 的
`/etc/resolv.conf`，完整停止时恢复原文件；网络状态会记录 agent 端口、DNS 和实际创建的
地址/路由/防火墙对象，清理时不会覆盖或删除非本次启动拥有的状态。

`src-tauri/src/guest_agent.rs` 定义了独立升级通道。sing-box 不需要随 kernel/initrd 一起
替换：host 侧按 64 KiB 分块上传版本文件，先发送版本、架构、大小和 SHA-256，guest
agent 校验后写入 inactive slot。激活时 guest agent 先执行
`sing-box check -c <config>`，停止旧进程，启动候选版本并等待启动窗口确认进程仍存活，
最后才提交 `active`/`previous` 指针；候选版本失败时会恢复旧进程和指针。host 端在响应
丢失或失败时先查询实际 active/healthy 状态，避免重复降级。对应的 Tauri command 是
`get_gateway_guest_status` 和 `upgrade_gateway_sing_box`。

配置也可以通过 authenticated guest-agent 通道下发：host 侧先发送
`stage_config` 和配置大小/SHA-256，再发送字节流，最后执行 `activate_config`。
对应的 Tauri command 是 `sync_gateway_guest_config`。guest 会保留上一份配置，候选配置
检查或重启失败时恢复旧配置和旧进程。

host 侧还可以调用 `generate_gateway_guest_config` 生成应用数据目录中的
`sing-box.gateway-guest.json`，或调用 `sync_gateway_guest_runtime_config` 直接生成并下发。
这份配置与 macOS host 配置分开：host 只生成 Mixed 入站且不自动改路由，Linux guest 使用
`tun0`，开启 `auto_route`、`strict_route` 和 Linux `auto_redirect`。

guest agent 默认读取 `/var/lib/songsterx/sing-box.json`，也可以通过
`--sing-box-config PATH` 指定配置。启动时如果 active 版本缺少配置、`sing-box check`
失败或进程立即退出，agent 仍保持管理端口可用，但 status 会报告 `healthy: false` 和
`lastError`，不会伪装成已就绪的数据面。

guest agent 使用 state dir 下的 `ready` 文件作为数据面 readiness 标记。agent 启动时先
删除旧标记，sing-box 通过 `check`、启动窗口和进程存活检查后才写入；sing-box 停止或
异常退出时删除。host 的配置/版本激活确认以及失败后的状态恢复都要求 `ready: true`，
不能只因为管理端口可连接或进程短暂存活就认为 guest 数据面可用。

控制协议需要预共享 token。guest 内通过
`--auth-token-file /etc/songsterx/agent.token`（默认是 state dir 下的
`agent.token`）读取；host 端通过 `SONGSTERX_GATEWAY_AGENT_TOKEN` 或
`SONGSTERX_GATEWAY_AGENT_TOKEN_FILE` 提供同一 token。token 只进入 JSONL 请求，不写入
SongsterX 配置或 vfkit kernel cmdline，长度必须为 32-256 个 ASCII 可打印字符。

控制协议使用 host-only TCP 的 JSONL 请求：

```text
status
stage_upgrade -> ready_for_upload
<exactly size bytes>
             <- staged
activate_upgrade -> active
             <- failed: agent restores previous version
```

`status` 响应包含 `healthy`、`ready`、`networkReady`、`gatewayLanIp` 和
`upstreamInterface`。`ready` 同时要求 guest 网络、控制监听、active sing-box 进程和
readiness 文件成立；它只表示 guest 内部已就绪，不表示 LAN 到 guest 的真实 packet path
已完成验收。

guest agent 将文件写入临时文件，完成大小和 SHA-256 校验后 `fsync`，再原子移动到
版本目录。激活时保留当前版本作为 rollback slot。当前 token 是 host-only TCP 上的
预共享认证，仍应在生产接入前限制 agent 只监听 host-only 网卡并替换为带挑战的会话认证。

Gateway 模式仍对运行时错误保持 fail-closed。启动计划只负责校验静态配置和资源，然后进入
supervisor 的真实 vmnet/vfkit/guest-agent readiness 检查；guest agent 下发配置、最终
authenticated status 或 runtime 检查失败时不会发布 Gateway runtime。实体 LAN packet path
仍是独立的转发 gate，不会因为 supervisor 启动成功而自动标记为 Ready。缺少 vfkit、kernel
或 initrd 时会在预检阶段给出具体错误。

## 本地资源

设置页不会自动下载或打包完整 Ubuntu/VyOS。需要用户提供与当前 Mac 架构匹配的 Linux
kernel 和极简 initrd；initrd 需要包含 sing-box、gateway-agent、virtio-net 驱动以及
静态配置网络所需的工具。默认 guest 资源限制为 1 vCPU、512 MiB。

构建时复用现有 `src-tauri/target`，使用单线程、关闭 Cargo 增量编译；镜像下载和 Cargo
构建产物都位于临时目录并在脚本退出时清理。执行 `npm run build:app` 时，应用会把 arm64
`vfkit` 以及 guest 的 `kernel`、`initrd`、`gateway-agent`、Linux arm64 `sing-box`、
`agent.token` 和 `manifest.json` 放入 `Contents/Resources`。设置页的 kernel、initrd、
vfkit 和 token 路径留空即可使用这些内置资源；填写路径时仍优先使用用户指定文件。

### 构建 arm64 guest

在 arm64 macOS 上可以用仓库脚本生成可供 vfkit 使用的最小 guest：

```sh
scripts/build_gateway_guest.sh --output "/absolute/path/songsterx-gateway-guest"
```

脚本按 `config/gateway-guest-inputs.json` 锁定版本、文件名和 SHA-256 下载 Alpine arm64
`virt` kernel/rootfs，提取 vfkit 要求的未压缩 Linux `Image`，
加入 virtio-net、tun、netfilter/NAT modules、`iproute2`、iptables、guest-agent 和
Linux arm64 musl sing-box。编译目录和下载目录都在临时目录，结束时自动清理；输出目录
只保留 kernel、initrd、agent、sing-box、token 和 manifest。

单独运行 guest 构建脚本时，仍可以将设置页的 Linux kernel/initrd 指向输出目录中的
`kernel`/`initrd`，并设置：

```sh
export SONGSTERX_GATEWAY_AGENT_TOKEN_FILE="/absolute/path/songsterx-gateway-guest/agent.token"
```

guest-agent 已预置一个 active sing-box 版本。Gateway supervisor 在 guest-agent 控制
端口可达后，会自动生成并 authenticated 上传当前应用配置，再等待 guest data-plane
readiness；后续 sing-box 升级继续使用 `upgrade_gateway_sing_box` 的分块校验和 rollback
通道，不需要重建 kernel/initrd。

资源构建成功不等于运行时 readiness。当前仓库已完成配置、guest-agent 协议和脚本级验收，
但真实 IPv4 LAN client 的 ARP、TCP、UDP、DNS 和 MITM 回程仍需要在实体设备上验证；首次真实
启动还需要 macOS Virtualization.framework 可用和 vmnet-helper 所需权限。DHCP、IPv6/RA 不在
本模式范围内，实体 LAN 客户端由部署者现场验证。

## 部署前现场检查

1. 确认 macOS Virtualization.framework、vmnet-helper 权限和物理网卡可用。
2. 在实体 LAN 客户端手工设置网关和 DNS，验证 IPv4 ARP、TCP、UDP、DNS 和 MITM 回程。
