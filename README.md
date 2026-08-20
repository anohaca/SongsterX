# SongsterX

SongsterX 是一个以 sing-box 和 mitmproxy 为数据面、以 Surge Runtime 和 Tauri/Rust 控制面为基础的 Surge-like 网络工具设计。

当前状态：Mixed 直连链路和 Module Engine HTTP/JavaScript 运行时可用。Gateway 采用 `vfkit + 极简 Linux guest + vmnet-helper`：双 virtio-net、guest 网络初始化、guest-agent 升级/配置通道、readiness 契约和 host supervisor 启动路径已接通；启动时会实际检查 vmnet、vfkit、guest-agent 和 `networkReady`。启动后 UI 会持续读取 guest LAN 与 `tun0` 的计数器，只有真实客户端产生两侧新增流量才标记 packet path 已验收，不会把单纯 supervisor readiness 误报为 ARP、TCP、UDP、DNS 或 MITM 的完整验收；实体手机/电脑接入仍需现场验证。当前 Gateway 范围不包含 DHCP、IPv6/RA，allowlist 也尚未实现。完整的 Surge policy preservation、PolicyEngine、Control API、Device Manager 和 UDP Fast Path 仍在路线中。

文档：

- [Surge-like Proxy 完整开发文档](docs/surge-like-proxy.md)
- [Surge 功能一一对应审查清单](docs/feature-mapping-review.md)
- [按状态详细功能清单](docs/feature-status-detailed.md)
- [最小 mixed 直连方案（不使用 TUN）](docs/mix-direct-minimal.md)
- [Surge 逻辑规则结构化对照](config/surge-logic-rules.redacted.json)
- [sing-box 1.13.14 示例配置](config/sing-box.example.json)
- [mixed 自定义 DNS 示例配置](config/sing-box.mix-custom-dns.example.json)
- [macOS Surge 局域网网关最小方案（不含 DHCP）](docs/gateway-minimal.md)
- [vfkit Gateway 第一阶段](docs/vfkit-gateway.md)
- [Gateway guest 资源构建](scripts/build_gateway_guest.sh)
- [网关 SongsterX.conf 示例](config/songsterx.gateway-minimal.conf)
- [网关 sing-box 配置模板](config/sing-box.gateway-minimal.json)
- [模块与远程脚本清单](config/module-assets.manifest.json)
- [模块运行与安全边界](docs/gateway-minimal.md#4-模块与远程脚本的离线输入)
- [跨平台 UI 架构与运行说明](docs/ui-architecture.md)
- [mitmproxy HTTP Hook 示例](scripts/mitm_addon.py)
- [静态校验脚本](scripts/validate_static.sh)
- [网关校验脚本](scripts/validate_gateway_minimal.sh)
