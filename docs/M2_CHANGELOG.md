# M2改动说明

## 新增能力

1. `cver.m2`独立子系统和`cver m2`命令入口。
2. Kata/QEMU/virtiofsd/containerd/KVM环境快照与确定性兼容性诊断。
3. Root拥有的固定功能辅助程序；支持白名单依赖安装、Kata配置迁移、专用namespace镜像准备和固定Guest smoke。
4. `installed-baseline`与`research-head`双源码轨道，显式下载、Commit锁定和摘要记录。
5. 可信知识库只读匹配；外部NVD数据只生成Candidate原始快照，不自动进入Gold。
6. Kata完整攻击面模式扫描；所有静态结果均保持Candidate语义。
7. 三个可编译Harness：OCI/runtime、kata-agent wire、virtio-fs/vsock。
8. ASan/UBSan/libFuzzer执行和严格崩溃准入。
9. DeepSeek OpenAI兼容评审；API故障时分级降级和断点恢复。
10. E0–E5可利用性与L0–L5攻击链证据阶梯；M2不生成L5载荷。
11. 疑似0-day接入M1加密Vault，普通报告和Web只显示脱敏摘要。
12. SQLite持久化任务、阶段、事件、环境、源码、Finding、Evidence、Harness、Fuzz和审计。
13. REST API、脱敏Web控制台、JSON/Markdown/HTML报告。
14. 合成基准、单元测试、安装/卸载和验收脚本。

## 未宣称完成

- 没有自动Guest-to-Host逃逸执行器；
- QEMU全设备原生Fuzz在balanced档只检查适配准备度，deep档仍要求显式构建；
- Cloud Hypervisor、Firecracker、StratoVirt和Guest Kernel在本机缺少执行条件时返回`skipped_with_reason`；
- 静态候选、LLM判断和文本匹配均不等同于真实漏洞；
- 本交付是针对指定Commit的完整M2 Overlay、Patch和应用包，不是上游仓库的重新分发镜像。
