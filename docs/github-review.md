# GitHub review scope

This branch contains the current SongsterX source snapshot for external review.

重点请审查：

- `src-tauri/src/lib.rs` 中的系统连接观察、lsof 解析、托管入口过滤和快照有效性；
- `src/App.tsx` 中的连接记录合并、生命周期状态和活动页展示；
- macOS 网关模式、Mixed 入口、系统网络观察之间的边界；
- 失败、重复、IPv4/IPv6、TCP/UDP 和数据量未知时的行为；
- 已有测试是否覆盖发布阻断问题。

请将问题按 P0/P1/P2 分级，并明确给出文件和行号。

## 本轮复核重点

本轮根据上一轮审查已修复：

- Host、Gateway guest、macOS system 三类快照分别维护有效性；无效 guest/system 快照不会把历史连接误判为完成；
- 活动页统一使用 epoch microseconds 计算实时连接时长；停止完成后才结束 Host/guest 连接，system 记录改为结束观察；
- wildcard Mixed 入口通过 macOS `getifaddrs()` 的本机地址集合过滤 LAN 入口；入口列表在运行时启动时冻结；
- system sampler 在阻塞式 lsof 前后和写共享缓存时检查 generation；system socket 使用连续快照 key 与生命周期 instance id 分离；
- system observer 改用 `lsof -FpcfnT` 的机器可读输出，并补充 TCP/UDP、wildcard LAN 地址、tuple 重现等单元测试；
- system 连接详情改用“首次观测/观测时长”语义，活动表更新为 8 列宽度规则。

本轮针对最新复审继续修复：

- 停止 worker 失败但仍持有进程、guest runtime 或代理资源时，后端保留运行元数据并继续发布 `running`，前端可以再次点击停止；无资源时才进入 `error`；
- system 连接进入 `observed` 后，详情页的观测时长使用 `lastSeenUs` 冻结，不再随当前时间继续增长；
- Host Clash API 请求、响应读取或 JSON 解析失败时仍发送指标帧，携带 `hostSnapshotValid=false` 和错误说明，活动页显示 Host 观察不可用，而不会丢弃整帧 guest/system 观察结果；
- 新增停止失败状态转换的 Rust 单元测试。

本轮继续修复：

- 运行启动时冻结 MetricsSession：Gateway 是否需要 Guest、Guest agent endpoint 和系统托管入口均来自本轮启动设置；metrics 轮询不再每秒读取磁盘 SongsterX.conf 来决定是否查询 Guest；
- Gateway session 在 endpoint 不可用或查询失败时保持 guestSnapshotValid=false；Mixed session 固定为没有 Guest 数据源，不会把配置漂移误判为有效空快照；
- 停止失败但仍持有资源时，使用冻结的 MetricsSession 重启 system sampler 和 metrics poller；彻底停止时清除 session；停止 Guest 也优先使用本轮冻结 endpoint。
- metrics poller 在阻塞采集返回后、发出 `runtime-metrics` 前以及执行 packet-path observer 前重新检查 generation，丢弃停止或重启期间已经失效的旧 session 快照；packet-path observer 同样只使用冻结的 Guest endpoint，不再重新读取可变配置。
