# Trusted Knowledge Base MVP

本模块在不破坏现有 `cve_knowledge` 接口的前提下，新增可信知识库层。

## 初始化

```bash
python3 -m cver kb-init --db data/trusted_knowledge.db
```

## Gold准入验证

```bash
python3 -m cver kb-validate REC-CVE-XXXX --db data/trusted_knowledge.db
```

## 导出字段级证据包

```bash
python3 -m cver kb-export REC-CVE-XXXX \
  --db data/trusted_knowledge.db \
  --output outputs/kb/REC-CVE-XXXX.json
```

## 当前实现

- 漏洞、错误配置、攻击模式、供应链事件分实体管理；
- 五类一级根因及专属二级分类；
- 原始来源、不可变快照、证据片段和字段级断言；
- 记录修订历史和内容哈希；
- 环境事实与规则中间表示；
- TRUE/FALSE/UNKNOWN三值规则执行；
- 确定性的Gold准入检查；
- 数据集发布与分组切分预留表。

当前版本仍使用SQLite作为最小可运行事实库。后续迁移PostgreSQL时保持实体和约束语义不变，Neo4j与Qdrant作为派生索引。

## 迁移旧知识库

旧 `container_cves_seed.json` 只能迁移为 Candidate，不会自动继承旧关键词分类为可信根因：

```bash
python3 scripts/import_legacy_knowledge.py \
  --source data/cve_knowledge/container_cves_seed.json \
  --db data/trusted_knowledge.db \
  --annotator yupeng
```

迁移后必须逐条补充官方快照、字段级证据、人工根因和环境规则，才能通过Gold准入。
