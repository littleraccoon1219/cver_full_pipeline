# M2验收标准

## 自动化验收

```bash
bash scripts/m2/acceptance.sh
```

必须满足：

- M2 Python模块编译通过；
- M2单元测试通过；
- 合成攻击面基准给出可复算的Precision、Recall和F1；
- 三个Harness均能用Clang 18、ASan、UBSan和libFuzzer构建；
- 短时Fuzz不把普通退出码误判为漏洞；
- 任务数据库支持阶段状态、断点恢复、事件和审计；
- API与Web返回脱敏数据；
- LLM不可用时产生明确`skipped_with_reason`，不伪造评审结果。

## ARM64 Kata主机验收

```bash
CVER_M2_ACK_KATA_SMOKE=yes bash scripts/m2/acceptance.sh
```

必须出现`KATA_M2_SMOKE_OK`，且Guest内核为`6.18.35 ... aarch64`，不能是宿主机`6.8.0-136-generic`。

## 证据门槛

- 静态模式只产生Candidate；
- LLM不能单独提升为已确认漏洞；
- Fuzz崩溃必须同时存在新制品和Sanitizer签名；
- 越界、权限或隔离异常达到阈值后，触发材料进入M1加密Zero-day Vault；
- 完整证据导出需要人工审批和审计；
- M2止于非武器化边界证据，不自动执行逃逸载荷。
