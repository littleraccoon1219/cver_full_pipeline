# agent-rs

Rust/Aya eBPF Agent 预留目录。第一版默认不强制加载 eBPF，运行时事件使用 mock/proc 分层模型。

计划：
1. mock runtime events；
2. `/proc` 只读采集；
3. root、BTF、内核能力满足时启用 Aya eBPF 采集 process_exec、dangerous_syscall、sensitive_path_access；
4. 所有事件统一带 `scan_id / target_id / campaign_id / scenario_id / correlation_id`。

安全边界：不加载非白名单 eBPF 程序，不执行攻击载荷，不做生产环境强制注入。
