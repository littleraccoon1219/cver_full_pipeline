# M2真实Kata Agent源码Fuzz设计与使用

## 1. 目标与证据边界

本模块把原有的协议模型Harness扩展为**源码版本锁定、接口指纹约束、人工审批后才可执行**的真实`kata-agent` RPC Fuzz框架。首批目标为：

- `ReadStream`
- `WriteStream`
- `ExecProcess`
- `SignalProcess`
- `WaitProcess`
- `UpdateContainer`

模型Harness、Mock Backend和静态扫描结果只用于接口测试、Corpus准备和候选筛选，不能被标记为真实Handler漏洞证据。真实证据必须同时绑定：源码轨道、Kata版本、源码Commit、`rpc.rs`摘要、接口指纹、已批准Adapter、Fuzz命令、Sanitizer日志和触发制品摘要。

模块不会生成或自动执行Guest-to-Host逃逸载荷。

## 2. 工作流

```text
Kata源码目录
  → 检测src/agent/src/rpc.rs
  → 提取6个RPC签名
  → 计算源码Hash和接口指纹
  → 检查版本化Adapter Manifest
  → 创建独立cargo-fuzz工作区
  → 人工完成Adapter实现及三项测试
  → 审批精确接口指纹
  → cargo-fuzz真实执行
  → 至少3次复现
  → 分级候选
  → Candidate Bundle
  → 人工标注、实验审查和Gold准入
```

## 3. 只检查工具链，不自动安装

```bash
python -m cver m2 real-fuzz toolchain
```

必须具备：

- Stable `rustc`和`cargo`，用于普通编译和测试；
- 配置的固定Nightly，默认`nightly-2026-06-01`；
- 该Nightly下的`cargo-fuzz`；
- LLVM工具组件。

缺失时返回`SKIPPED_WITH_REASON`，不会自动安装Rust、Nightly或`cargo-fuzz`。

## 4. 检查真实源码接口

```bash
python -m cver m2 real-fuzz inspect \
  --source ~/security-src/kata-containers/installed-baseline \
  --version 3.32.0 \
  --track installed-baseline
```

`installed-baseline`和`research-head`的证据严格分开。检查结果包括：

- 六个Handler是否存在；
- 请求类型、返回类型和源码行；
- 单Handler签名Hash；
- `rpc.rs` SHA-256；
- 整体接口指纹；
- Git Commit和`git describe`结果；
- Adapter状态。

## 5. 创建独立工作区

```bash
python -m cver m2 real-fuzz prepare \
  --source ~/security-src/kata-containers/installed-baseline \
  --version 3.32.0 \
  --track installed-baseline \
  --propose-adapter
```

工作区位于：

```text
data/m2/real-fuzz/kata-agent/<track>/<version>/<commit>/
```

其中包括：

```text
workspace-lock.json
bridge/
mocks/
fuzz/fuzz_targets/
fuzz/corpus/
plans/stateful-sequence.json
plans/controlled-concurrency.json
patches/adapter-patch-policy.json
artifacts/
```

工作区不修改原Kata源码目录。未批准Adapter时，`bridge`包含编译阻断，防止Mock结果被误当作真实Handler结果。

## 6. Adapter审批

生成候选Manifest：

```bash
python -m cver m2 real-fuzz adapter propose \
  --source ~/security-src/kata-containers/installed-baseline \
  --version 3.32.0
```

Adapter只允许以下变化：

- 测试专用可见性包装；
- 确定性Mock注入；
- `cfg(cver-fuzz)`下的构造辅助；
- 独立Bridge适配代码。

禁止修改：

- 参数验证；
- 授权或策略检查；
- 生产Feature默认值；
- 安全逻辑；
- Panic或错误路径语义。

完成源码审查后，必须分别通过：

1. Stable普通编译测试；
2. RPC接口测试；
3. 未修改Handler与Adapter路径的语义差分测试。

然后执行：

```bash
python -m cver m2 real-fuzz adapter approve \
  --candidate configs/m2_adapters/<adapter>.candidate.json \
  --actor yupeng \
  --compilation-test \
  --interface-test \
  --semantic-differential-test \
  --confirm
```

候选Manifest本身不会被执行。源码接口发生变化时，状态为`ADAPTER_SEMANTIC_DRIFT`，必须重新审查。

## 7. 构建和执行

```bash
python -m cver m2 real-fuzz build \
  --workspace data/m2/real-fuzz/kata-agent/installed-baseline/3.32.0/<commit>
```

执行指定Handler：

```bash
python -m cver m2 real-fuzz run \
  --workspace data/m2/real-fuzz/kata-agent/installed-baseline/3.32.0/<commit> \
  --handler ReadStream \
  --handler WriteStream \
  --seconds 1800 \
  --seed 1337 \
  --confirm-native-fuzz
```

硬限制：

- 并行分支不超过2；
- 单次Fuzz不超过14400秒；
- 输入最大长度262144字节；
- 每个候选至少复现3次才能进入强候选；
- 触发制品默认标记为`restricted`。

## 8. 状态序列与并发计划

状态序列包括：

```text
ExecProcess → WriteStream → SignalProcess → WaitProcess
ExecProcess → UpdateContainer → WaitProcess
```

并发场景包括：

```text
WaitProcess ↔ SignalProcess
WriteStream ↔ WaitProcess
UpdateContainer ↔ WaitProcess
```

每个计划保存固定种子、初始状态、分支、交错点、预期状态和最终分类。并发分支上限为2，候选必须在同一种子下至少复现3次。

## 9. 候选分级

```text
OBSERVATION
  单次或非确定性异常

WEAK_CANDIDATE
  可重复Panic、资源异常或非法状态，但强证据不完整

STRONG_CANDIDATE
  Sanitizer/Data Race/确定性死锁，并且至少复现3次

VALIDATED_CANDIDATE
  非破坏性真实Kata Guest复验成功，或隔离不变量明确失效
```

退出码、LLM输出或关键字匹配不能单独提升候选等级。

## 10. 导出到正式知识库Candidate链

```bash
python -m cver m2 real-fuzz export-kb \
  --output-dir data/candidates/m2-kata-001 \
  --level STRONG_CANDIDATE
```

该命令只生成正式`CandidateBundleBuilder`数据包，不直接写`trusted_knowledge.db`，不自动填写根因，不自动进入Gold。受限触发输入只保留Hash和脱敏实验元数据。
