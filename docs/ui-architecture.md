# SongsterX UI 架构与运行说明

## 选型

- UI：Tauri 2 + React 19 + TypeScript + Vite
- 本地控制面：Rust/Tauri commands
- 数据面：sing-box；本机始终保留 `mixed` 入站。局域网 Gateway 使用 vfkit guest、双 virtio-net 和 vmnet-helper，启动入口实际检查运行时 readiness；UI 持续读取 guest LAN/`tun0` 计数器，当前会话未观察到两侧新增流量前保持“等待局域网验收”
- 平台策略：桌面端共用一套前端和 Rust 控制面；macOS、Windows、Linux 使用各自的 Tauri 打包目标，平台特有的 TUN、系统代理和网关能力后续通过 Rust adapter 接入

## 视觉基线

- 产品外壳参考 Microsoft PowerToys 的工具型设置体验；不把 WinUI Gallery 当作完整产品页面
- 控件、状态、表格和设置行采用 Fluent 2 / Fluent UI 的组件语义
- 配置管理页参考 Windows Terminal 的分组和编辑方式
- 页面使用统一的深色设计令牌、边框和间距；避免大面积渐变、装饰性阴影和不一致的圆角
- 当前 UI 支持 Mixed 直连和 Gateway runtime 启动路径；设置页提供 vfkit、kernel/initrd、host-only 网络和 guest agent 参数，启动网关要求真实 runtime readiness，随后由 LAN/`tun0` 计数器观察当前会话的实体 packet path

## 当前已实现

- 总览页：运行模式、Mixed 监听地址、DNS、出站、PID，以及网关接口/IP/DNS 状态
- 设置页：可编辑监听地址、监听端口、DNS 模式与服务器、sing-box 路径、日志等级；网关开关独立于 Mixed
- 设置持久化：保存到 Tauri 应用数据目录；启动时根据设置生成实际运行配置
- 一键启动/停止 `sing-box`
- 运行日志页：接收 sing-box stdout/stderr，并保留最近 200 条
- 能力路线页：明确当前实现、下一步和暂未启用的能力
- 内置最小配置资源：`config/sing-box.mix-direct-minimal.json`
- 模块适配：读取 9 个模块和 16 个脚本/数据资源，校验 SHA-256，并生成本地 Module Runtime Plan
- 模块静态运行链：`Rule` 进入 sing-box；Mixed 使用 `127.0.0.1:8080`，Gateway 计划使用 host-only MITM 地址，用户无需额外配置代理端口
- 模块安全边界：只使用已校验的本地模块/资源；JavaScript 在内置 QuickJS 隔离上下文中执行，不拉取远程运行时资源
- Mixed 模式不自动接管流量：不启用 TUN、不改系统路由、不劫持 DNS；显式开启网关后仅接管手工配置到该局域网网关的客户端。macOS host 只生成 Mixed，Linux guest 才使用 `tun0`

## Rust 命令边界

| 命令 | 作用 |
| --- | --- |
| `get_runtime_status` | 返回当前 sing-box 子进程和监听状态 |
| `get_config_documents` | 返回 SongsterX 设置、代理配置、sing-box 运行配置和模块运行计划，供 UI 只读查看 |
| `get_runtime_settings` | 读取持久化设置 |
| `save_runtime_settings` | 校验并保存设置；运行中禁止修改 |
| `reset_runtime_settings` | 恢复默认设置 |
| `start_mix_direct` | 根据设置和已启用模块生成运行计划；Mixed 可启动。Gateway 模式先校验静态 vfkit guest 资源，再由 supervisor 实际检查 vmnet/vfkit/guest-agent readiness；有 HTTP 模块时按模式启动 host-only 或 loopback MITM |
| `stop_runtime` | 停止 sing-box 和 Module Engine 子进程 |
| `get_app_info` | 返回产品、版本、平台和当前模式 |
| `get_modules` | 读取用户导入的模块、解析元数据、统计规则/脚本/MITM 主机并校验哈希 |
| `import_module` | 导入一个模块文件及可选的脚本/规则集附件，复制到应用数据目录并生成本地哈希清单 |
| `set_module_enabled` | 持久化模块启用状态；未通过哈希校验或运行中禁止修改 |

前端只通过 Tauri IPC 调用这些命令，不直接访问本地进程或文件系统。

## 开发与构建

```bash
npm install
npm run dev
npm run tauri -- dev
```

生产构建：

```bash
npm run build
npm run tauri -- build --bundles app
npm run tauri -- build --bundles dmg
```

Tauri 打包前会自动执行 `npm run prepare:mitmproxy`，把 mitmproxy 和 Python runtime 封装为应用内 `Resources/mitmdump`。构建机首次需要安装：

```bash
python3 -m pip install -r scripts/mitmproxy-build-requirements.txt
```

## sing-box 路径覆盖

默认使用当前进程 `PATH` 中的 `sing-box`。如果 GUI 启动时没有继承 Homebrew 等路径，可以设置：

```bash
export SONGSTERX_SING_BOX_BIN=/absolute/path/to/sing-box
export SONGSTERX_MIX_CONFIG=/absolute/path/to/sing-box.mix-direct-minimal.json
```

模块继续使用统一入口 `127.0.0.1:2080`，不会自动接管系统流量；命中模块 MITM 主机时，sing-box 内部经 `127.0.0.1:8080` 转给 mitmproxy，客户端不需要再配置 8080，但仍需安装对应 mitmproxy CA。Release `.app` 会携带自包含的 `mitmdump` 和 QuickJS 运行时；开发调试可用 `SONGSTERX_MITMDUMP_BIN` 覆盖。最终用户不需要单独安装 mitmproxy。Script、Body Rewrite、binary body 和参数注入已经进入运行时；完整 Surge policy preservation、cron/event/dns Script 和通用远程更新仍不等价。
