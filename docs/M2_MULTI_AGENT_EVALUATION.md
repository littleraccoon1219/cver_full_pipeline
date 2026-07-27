# M2六Agent、证据图与论文评测

## 1. 六Agent职责

| Agent | 职责 | 权限边界 |
|---|---|---|
| Triage | 去重、分类、优先级 | 不能提升候选等级 |
| Exploitability | 前提、缺失证据、攻击链假设 | 不能覆盖三值规则 |
| Experiment | Harness、Corpus、序列和复验建议 | 不能自动执行 |
| Critic | 冲突、无证据断言和门控审查 | 只输出注释 |
| Remediation | 最小修复、回归和回滚建议 | 不能直接修改源码 |
| Evaluation | 指标、基线和消融映射 | 不能修改Gold标签 |

DeepSeek不可用时，确定性阶段继续运行，并记录`SKIPPED_WITH_REASON`。所有Agent输出均保存模型、输入摘要、Token使用量和Provenance Hash。

Agent永久禁止：审批Adapter、执行模型补丁、批准Guest复验、提升证据等级和直接准入Gold。

## 2. 证据图与E0—E5

三值规则引擎支持：

```text
TRUE / FALSE / UNKNOWN
and / or / not
equals / contains / version_in_range
has_capability / path_mounted / socket_exposed
```

缺失事实保持`UNKNOWN`，不会强制转换为False或True。

```text
E0：仅有漏洞或候选描述
E1：版本受影响证据成立
E2：环境前提成立
E3：真实调用路径可达
E4：受控触发成立
E5：边界影响或隔离不变量失效
```

每一级只由硬证据计算。Agent只可提出缺失证据和补充实验。

## 3. 数据集层次

```text
public_vulnerability
  真实公开漏洞、公告、修复Commit和实验

hard_negative
  修复后Commit、不受影响版本、关闭攻击面的配置

controlled_synthetic
  受控注入或合成边界样本

fuzz_candidate
  M2发现但尚未完成公开漏洞确认的候选
```

真实漏洞和合成样本必须分层报告，不能合并成一个“漏洞发现准确率”。

## 4. 切分与泄漏控制

```bash
python -m cver m2 dataset split \
  --input data/datasets/m2_records.jsonl \
  --release-id m2-paper-v1
```

切分原则：

- 按时间排序；
- 同一CVE不能跨集合；
- 同一修复Commit不能跨集合；
- 同一Crash簇不能跨集合；
- 相同源数据或制品Hash不能跨集合；
- 测试集保留未见版本、未见Handler和Research Head候选。

输出`train.jsonl`、`validation.jsonl`、`test.jsonl`和泄漏审计。

## 5. 指标

分类：

- Accuracy；
- Macro-F1；
- Weighted-F1；
- 每类Precision、Recall和F1。

可利用性：

- Accuracy和Macro-F1；
- AUROC；
- Brier Score；
- E0—E5混淆分析。

候选排序：

- MRR；
- Recall@K；
- NDCG@K。

Fuzz：

- 代码/边覆盖；
- Crash Run和唯一Crash Hash；
- Time to First Crash；
- 三次复现率；
- CPU、内存、磁盘和总运行时间。

## 6. 基线与消融

基线：

1. 版本/CVE规则匹配；
2. 传统机器学习分类；
3. 通用LLM零样本；
4. 单Agent；
5. 无证据图；
6. 无真实源码Fuzz；
7. 完整六Agent系统。

消融分别移除：证据图、三值规则、多Agent、真实源码Fuzz、Guest复验、Hard Negative和版本差异分析。

评测命令：

```bash
python -m cver m2 evaluate --predictions outputs/m2_predictions.jsonl
```
