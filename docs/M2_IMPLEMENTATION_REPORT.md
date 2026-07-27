# CVER M2 0.3.0本轮实现报告

## 基线

- GitHub仓库：`littleraccoon1219/cver_full_pipeline`
- 本地补丁基线：`3200cec5f3aa6f24415f6eb26f1bb07ae575ff6f`
- 交付方式：本地Patch与M2覆盖包；未创建GitHub分支、Commit或PR。

## 已实现

### 真实Kata Agent源码研究框架

- 识别`src/agent/src/rpc.rs`中的六个首批RPC Handler；
- 保存源码Commit、文件Hash、Handler签名Hash和整体接口指纹；
- 区分`installed-baseline`与`research-head`；
- 生成独立Cargo Workspace、Corpus、状态序列和确定性双分支并发计划；
- 工具链只检查Stable Rust、固定Nightly、cargo-fuzz和LLVM组件，不自动安装；
- 真实执行需要`--confirm-native-fuzz`，并受时间、并行、内存和输入长度硬限制。

### Adapter治理

- 版本化Manifest；
- `ADAPTER_REQUIRED`、`REVIEW_REQUIRED`、`APPROVED`和`ADAPTER_SEMANTIC_DRIFT`状态；
- Candidate Manifest不参与执行选择；
- 审批强制要求人工确认、普通编译、接口测试和语义差分测试；
- 模型生成的Adapter建议不得自动执行；
- 未安装精确Bridge时保持编译阻断，避免把Mock结果伪装成真实Handler证据。

### 候选与复验

- `OBSERVATION`、`WEAK_CANDIDATE`、`STRONG_CANDIDATE`和`VALIDATED_CANDIDATE`；
- Exit Code或LLM输出不能单独提升等级；
- 强候选要求Sanitizer/Data Race/确定性死锁证据和至少3次复现；
- 多版本Runtime资产按版本独立保存并进行SHA-256复核；
- Guest复验分L1、L2、L3，当前实现生成受限计划，不自动执行触发材料；
- 其他Kata版本资产不覆盖`/opt/kata`。

### 可利用性与多Agent

- 三值规则：`TRUE/FALSE/UNKNOWN`；
- E0—E5硬证据阶梯；
- 漏洞候选、环境事实、规则结果和Agent注释形成证据图；
- 六个DeepSeek顾问Agent：Triage、Exploitability、Experiment、Critic、Remediation和Evaluation；
- Agent不能审批Adapter、提升候选、执行补丁、批准Guest复验或准入Gold；
- DeepSeek不可用时确定性阶段继续运行。

### 数据集与评测

- 四层数据：公开漏洞、Hard Negative、受控合成、Fuzz候选；
- 时间排序与CVE/Commit/Crash簇分组隔离；
- 源数据和制品Hash泄漏审计；
- Accuracy、Macro-F1、Weighted-F1、每类P/R/F1、AUROC、Brier、MRR、Recall@K、NDCG@K和Fuzz指标；
- 真实漏洞与合成样本分层报告。

### 正式知识库接入

- M2候选通过正式`CandidateBundleBuilder`导出；
- 不直接写`trusted_knowledge.db`；
- 不自动填写根因；
- 不自动进入Gold；
- 受限触发材料只导出Hash和脱敏实验元数据。

## 本地验证结果

- Python编译：通过；
- Pytest：`24 passed`；
- 合成模式门控基准：Precision/Recall/F1均为1.0，仅证明合成规则门控正确；
- 三个原有C++ Harness：Clang + ASan/UBSan/libFuzzer构建通过；
- 每个Harness执行1秒短时Fuzz：无Crash，无误报；
- M2数据库：Schema 2；
- CLI帮助和初始化：通过。

## 未在本地容器完成

- 本地执行容器没有Rust、固定Nightly和cargo-fuzz，因此真实Handler构建与Fuzz返回`SKIPPED_WITH_REASON`；
- 本地容器没有你的ARM64 Kata 3.32.0运行环境，因此没有执行真实Kata Guest复验；
- 没有DeepSeek API密钥，因此未进行远程六Agent调用；
- 没有把未经你审查的源码特定Adapter自动标记为批准；
- 本交付是完整M2覆盖包，不是整个GitHub仓库的重新分发副本。

以上未完成项不会被伪装为已验证结果，需在你的Ubuntu ARM64/Kata主机上按文档继续验收。
