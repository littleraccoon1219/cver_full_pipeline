# CVER Full Pipeline

面向容器安全研究的博士系统第一版工程原型。系统链路：

`镜像/容器/Pod/运行时环境 -> Trivy/Syft/Docker/K8s/Kata Inspect -> Finding 标准化 -> 漏洞语义模型 -> 环境证据匹配 -> 可利用性判断 -> EscapeGraph -> 受控 RedTeam 测评 -> 防护评分 -> Repair/Retest -> 报告/Benchmark`

## 安全边界

本工程只用于授权靶场、防御验证和论文实验。默认不执行真实容器逃逸 PoC，不生成 exploit，不允许任意 shell，不对 public/prod 目标执行危险动作。RedTeam 与 Repair 的非 dry-run 动作必须满足 `cver-lab=true`、动作白名单、PolicyGuard 和人工确认。

## 快速运行

```bash
cd cver_full_pipeline
python3 -m cver doctor
python3 -m cver init-db
python3 -m cver demo
python3 -m cver benchmark
python3 -m unittest discover -s tests -v
```

Web 控制台：

```bash
pip install -r requirements.txt
python3 -m cver web --host 0.0.0.0 --port 8000
```

访问 `http://127.0.0.1:8000`。

Docker Compose：

```bash
docker compose up --build
```

## 正式可信知识库

运行流水线数据库与论文可信知识库分离：

- `data/cver_full_pipeline.db`：扫描、Finding、报告和Benchmark运行数据。
- `data/trusted_knowledge.db`：来源、快照、证据、断言、环境规则、实验与Gold数据集。

初始化正式数据库和两级根因分类：

```bash
python3 scripts/kb_upgrade_formal_schema.py \
  --db data/trusted_knowledge.db \
  --actor-id researcher-yupeng \
  --actor-name Yupeng \
  --taxonomy taxonomy/root_causes.yaml

python3 scripts/kb_schema_report.py --db data/trusted_knowledge.db
```

### Candidate采集与导入分离

四类采集器只产生本地Candidate数据包，不直接写数据库，也不自动填写根因或Gold标签：

```bash
export NVD_API_KEY='your-key'
python3 scripts/kb_fetch_nvd_candidates.py \
  --start-year 2020 --end-year 2026 --target-count 158 \
  --quota-config configs/cve_collection_2020_2026.yaml \
  --output data/staging/nvd/run-001

python3 scripts/kb_fetch_misconfiguration_candidates.py \
  --source-config configs/misconfiguration_sources.yaml \
  --max-records 50 --output data/staging/misconfiguration/run-001

python3 scripts/kb_fetch_attack_pattern_candidates.py \
  --max-records 20 --output data/staging/attack-pattern/run-001

python3 scripts/kb_fetch_supply_chain_incident_candidates.py \
  --seed-config configs/supply_chain_seed_sources.yaml \
  --max-records 20 --output data/staging/supply-chain/run-001
```

每个数据包必须先校验，再模拟导入，最后正式导入：

```bash
python3 scripts/kb_validate_candidate_bundle.py --bundle data/staging/nvd/run-001

python3 scripts/kb_import_candidate_bundle.py \
  --db data/trusted_knowledge.db \
  --bundle data/staging/nvd/run-001 \
  --actor-id researcher-yupeng --dry-run

python3 scripts/kb_import_candidate_bundle.py \
  --db data/trusted_knowledge.db \
  --bundle data/staging/nvd/run-001 \
  --actor-id researcher-yupeng --actor-name Yupeng
```

Candidate导入后仍必须补充E0官方来源、E2独立来源、版本断言和实验记录。CVE与错误配置只有在实验状态为`completed`、验证等级至少为`L1`、关联环境快照且具有实验工件或结构化观察时，才能通过Gold准入。

## 仓库清理

`.venv`、`__pycache__`、数据库、原始快照和实验工件不应提交到GitHub。首次应用本补丁后执行：

```bash
bash scripts/kb_cleanup_repository.sh
git status --short
```

## CLI

```bash
python3 -m cver full-pipeline --profile demo --target demo/nginx:lab --target-kind image
python3 -m cver scan-only --profile demo --target demo/nginx:lab
python3 -m cver reason-only --profile demo
python3 -m cver redteam-only --profile demo
```

## 输出

- `data/cver_full_pipeline.db`
- `outputs/runs/<scan_id>/report.json`
- `outputs/runs/<scan_id>/report.md`
- `outputs/runs/<scan_id>/report.html`
- `outputs/benchmarks/<benchmark_id>.json`

## 主要模块

- `cver/scanners`: Scanner插件，支持mock、dry-run和real-cli。
- `cver/normalizer.py`: Finding标准化。
- `cver/knowledge`: 正式可信知识库、证据链、Candidate导入和Gold准入。
- `cver/semantic`: 宏观/细粒度分类、Precondition DSL。
- `cver/reasoner`: 环境感知可利用性判断。
- `cver/graph`: EscapeGraph JSON与Mermaid。
- `cver/redteam`: 受控Attack Scenario DSL、Planner、Executor。
- `cver/policy`: PolicyGuard与审计日志。
- `cver/defense`: 防护评分。
- `cver/repair`: RepairPlan、PatchProposal、Retest。
- `cver/benchmark`: Ground Truth与指标计算。
- `cver/api.py` + `cver/web`: FastAPI与Jinja2 Web控制台。
- `agent-rs`: Rust/Aya eBPF Agent预留目录。
