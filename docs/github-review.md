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
