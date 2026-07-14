# CVER可信知识库论文正式版Schema v1.0.0

## 1. 目标

正式版Schema用于支撑博士论文中的四类研究对象：漏洞、错误配置、攻击模式和供应链事件，并形成以下可审计闭环：

```text
权威来源 → 不可变快照 → 证据片段 → 字段级断言 → 根因分类
→ 环境事实 → 可执行规则 → 可利用性评估 → 攻击链
→ 受控实验 → 防护/修复 → 复验 → 冻结数据集发布
```

数据库共建立 **67张表、4个视图、4个约束触发器**。

## 2. 表分组

### A. 数据库治理、采集和审计（5表）

| 表 | 作用 |
|---|---|
| `kb_schema_migrations` | Schema版本及迁移记录 |
| `kb_actors` | 人工标注者、系统、模型和组织身份 |
| `kb_ingestion_runs` | 一次数据采集任务 |
| `kb_ingestion_items` | 采集任务中的单条处理状态 |
| `kb_audit_events` | 对实体、断言、规则和发布操作的审计日志 |

### B. 分类体系（5表）

| 表 | 作用 |
|---|---|
| `kb_taxonomy_versions` | 分类体系版本 |
| `kb_taxonomy_nodes` | 一级/二级根因及其他分类节点 |
| `kb_taxonomy_edges` | 分类节点之间的层级和语义关系 |
| `kb_record_taxonomy_assignments` | 安全记录的多轴分类标注 |
| `kb_external_taxonomy_mappings` | 与CWE、CAPEC、ATT&CK等标准的映射 |

### C. 核心知识实体与产品版本（8表）

| 表 | 作用 |
|---|---|
| `kb_records` | 漏洞、错误配置、攻击模式、供应链事件主实体 |
| `kb_record_identifiers` | CVE、GHSA、厂商编号等多标识符 |
| `kb_record_revisions` | 记录历史修订 |
| `kb_record_relations` | 漏洞、配置、攻击模式之间的语义关系 |
| `kb_products` | 产品/生态实体 |
| `kb_components` | runtime、kubelet、VMM等组件 |
| `kb_record_components` | 记录与受影响组件的关系 |
| `kb_version_ranges` | 受影响、修复、未受影响版本范围 |

### D. 来源、证据、断言和冲突（9表）

| 表 | 作用 |
|---|---|
| `kb_sources` | 来源身份和权威等级 |
| `kb_source_snapshots` | 来源不可变原始快照 |
| `kb_evidence_fragments` | 可精确定位的证据片段 |
| `kb_assertions` | 字段级事实断言 |
| `kb_assertion_revisions` | 断言历史版本 |
| `kb_assertion_evidence` | 断言与证据的支持/反驳关系 |
| `kb_assertion_conflicts` | 来源或断言冲突 |
| `kb_conflict_assertions` | 冲突所涉及的断言集合 |
| `kb_conflict_resolutions` | 冲突裁决及依据 |

### E. 人工标注与一致性（4表）

| 表 | 作用 |
|---|---|
| `kb_annotation_tasks` | 待标注任务 |
| `kb_annotation_decisions` | 每个字段的人工决策和理由 |
| `kb_annotation_rechecks` | 延迟盲式重标注和测试—重测一致性 |
| `kb_gold_admission_reviews` | 自动Gold检查和人工最终准入决定 |

### F. 环境事实、规则与可利用性（9表）

| 表 | 作用 |
|---|---|
| `kb_environments` | 可复用环境画像 |
| `kb_environment_snapshots` | 不可变环境快照 |
| `kb_environment_facts` | 点路径形式的结构化环境事实 |
| `kb_environment_relations` | 基线、漏洞环境、修复环境之间关系 |
| `kb_rules` | 与执行器无关的规则中间表示 |
| `kb_rule_evidence` | 规则与证据的正规化绑定 |
| `kb_rule_evaluations` | 三值逻辑规则执行结果和轨迹 |
| `kb_exploitability_assessments` | 分层可利用性最终评估 |
| `kb_assessment_inputs` | 评估所依据的规则、实验、断言和攻击链 |

### G. 攻击链（5表）

| 表 | 作用 |
|---|---|
| `kb_attack_chains` | 一条完整攻击链 |
| `kb_attack_steps` | 攻击步骤、能力获取和边界跨越 |
| `kb_attack_edges` | 步骤之间的因果、依赖和替代关系 |
| `kb_attack_step_records` | 步骤所利用的漏洞、配置或攻击模式 |
| `kb_attack_step_conditions` | 步骤前置、后置和阻断条件 |

### H. 可复现实验（6表）

| 表 | 作用 |
|---|---|
| `kb_experiment_protocols` | 版本化实验协议和成功判据 |
| `kb_experiment_campaigns` | 正例、负例、修复例等实验批次 |
| `kb_experiments` | 单次实验运行 |
| `kb_experiment_steps` | 可复现的逐步操作记录 |
| `kb_experiment_artifacts` | 日志、镜像摘要、抓包等带哈希工件 |
| `kb_experiment_observations` | 实验中的结构化观察和测量 |

### I. 防护、策略、修复和复验（8表）

| 表 | 作用 |
|---|---|
| `kb_mitigations` | 抽象防护/缓解措施 |
| `kb_mitigation_targets` | 防护阻断的记录、步骤、链或规则 |
| `kb_mitigation_evidence` | 防护措施证据 |
| `kb_defense_policies` | seccomp、Rego、RBAC等策略版本 |
| `kb_policy_validations` | 策略安全有效性和业务兼容性验证 |
| `kb_repair_actions` | 可执行修复动作和回滚计划 |
| `kb_retest_runs` | 修复前后环境的复验 |
| `kb_retest_checks` | 安全、业务、性能、兼容性检查 |

### J. 数据集发布和质量控制（8表）

| 表 | 作用 |
|---|---|
| `kb_dataset_releases` | 冻结Gold/Silver发布版本 |
| `kb_split_groups` | 漏洞家族、补丁家族和重复簇 |
| `kb_split_group_members` | 记录所属分组 |
| `kb_dataset_memberships` | train/validation/test等划分 |
| `kb_release_artifacts` | 发布文件、清单和校验和 |
| `kb_split_leakage_audits` | 重复、家族、时间和来源泄漏审计 |
| `kb_quality_check_runs` | 一次质量检查任务 |
| `kb_quality_check_results` | 单项质量检查结果 |

## 3. 视图

| 视图 | 作用 |
|---|---|
| `kb_v_unresolved_conflicts` | 所有未解决字段冲突 |
| `kb_v_latest_environment_snapshots` | 每个环境的最新快照 |
| `kb_v_record_evidence_coverage` | 每条记录的断言、E0/E2/E3证据覆盖 |
| `kb_v_gold_readiness` | Gold结构准入的快速检查视图 |

## 4. 约束触发器

| 触发器 | 作用 |
|---|---|
| `kb_trg_no_model_gold_insert` | 禁止模型生成记录直接以Gold插入 |
| `kb_trg_no_model_gold_update` | 禁止模型生成记录被提升为Gold |
| `kb_trg_source_snapshot_immutable_update` | 禁止修改来源快照，只能新增版本 |
| `kb_trg_environment_snapshot_immutable_update` | 禁止修改环境快照，只能新增版本 |

## 5. 初始化或升级

```bash
python3 scripts/kb_upgrade_formal_schema.py \
  --db data/trusted_knowledge.db \
  --actor-id researcher-yupeng \
  --actor-name Yupeng \
  --taxonomy taxonomy/root_causes.yaml
```

脚本会在升级前自动备份旧数据库，并将MVP 0.1表无损升级到1.0.0。

检查：

```bash
python3 scripts/kb_schema_report.py --db data/trusted_knowledge.db
```

或：

```bash
python3 -m cver kb-schema-report --db data/trusted_knowledge.db
```

健康状态必须满足：

```text
missing_tables = []
foreign_key_errors = []
present_formal_table_count = 67
```

## 6. 设计原则

1. **实体与证据分离**：记录本身不是证据，任何关键字段均通过Assertion—Evidence链证明。
2. **事实与推理分离**：官方事实、规则结论、模型输出、实验结果分别存储。
3. **漏洞与环境分离**：同一漏洞复用多个正例、负例、修复例和未知环境。
4. **条件满足与实验成功分离**：规则评估不能冒充完整复现。
5. **攻击与防护闭环**：攻击步骤可被具体Mitigation、Policy、Repair和Retest对应。
6. **所有重要对象版本化**：Schema、分类、记录、断言、规则、协议、策略和数据集均可追踪。
7. **测试划分可审计**：漏洞家族和近重复簇先分组，再进行训练/测试划分。
8. **模型不得制造Ground Truth**：数据库触发器和Gold审查表共同约束。
