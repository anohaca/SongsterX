# GitHub review scope

This branch contains the current SongsterX source snapshot for external review.

重点请审查：

- `src-tauri/src/lib.rs` 中的系统连接观察、lsof 解析、托管入口过滤和快照有效性；
- `src/App.tsx` 中的连接记录合并、生命周期状态和活动页展示；
- macOS 网关模式、Mixed 入口、系统网络观察之间的边界；
- 失败、重复、IPv4/IPv6、TCP/UDP 和数据量未知时的行为；
- 已有测试是否覆盖发布阻断问题。

请将问题按 P0/P1/P2 分级，并明确给出文件和行号。
