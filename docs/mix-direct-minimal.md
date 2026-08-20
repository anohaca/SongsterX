# 最小 mixed 直连方案（不使用 TUN）

这是当前最小可运行版本，目标只有一件事：在本机提供一个同时接受 HTTP 代理和 SOCKS5 代理的 `mixed` 监听，所有请求直接出站，DNS 使用 macOS 系统解析器。

## 明确行为

| 项目 | 当前行为 |
|---|---|
| 入站 | 只有 `mixed`：`127.0.0.1:2080` |
| 出站 | 只有 sing-box `direct` |
| TUN | 没有 TUN inbound |
| 自动接管 | 没有 `auto_route`，没有系统路由修改 |
| DNS | sing-box `local` DNS，使用系统 DNS；不做 DNS hijack |
| MITM | 不启用 |
| Trojan/Snell | 不启用 |
| LAN 网关 | 不启用；只监听本机回环地址 |
| 生效方式 | 应用或系统代理设置中手工填写 `127.0.0.1:2080` |

## 启动

```bash
scripts/run_mix_direct_minimal.sh --check
scripts/run_mix_direct_minimal.sh --run
```

启动后：

- HTTP 代理：`http://127.0.0.1:2080`
- SOCKS5 代理：`socks5://127.0.0.1:2080`
- SOCKS5 远程解析：`socks5h://127.0.0.1:2080`

例如：

```bash
curl --proxy http://127.0.0.1:2080 https://example.com/
curl --socks5-hostname 127.0.0.1:2080 https://example.com/
```

如果系统或应用没有显式配置这两个代理地址，流量不会经过 sing-box；这是“不自动接管”的预期行为。

## 文件

- `config/sing-box.mix-direct-minimal.json`：最小数据面配置。
- `scripts/run_mix_direct_minimal.sh`：校验和启动入口。

## 与网关方案的关系

这个配置与 `config/sing-box.gateway-minimal.json` 相互独立。它不验证 Gateway guest、DHCP、MITM、模块或代理节点，只用于先确认本机 mixed 代理和系统 DNS 工作正常。后续需要时，再把它作为更大数据面的基础 fixture，而不是直接改成自动接管模式。
