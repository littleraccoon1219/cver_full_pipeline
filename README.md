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
python3 -m unittest discover -s tests
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

## CLI

```bash
python3 -m cver full-pipeline --profile demo --target demo/nginx:lab --target-kind image
python3 -m cver scan-only --profile demo --target demo/nginx:lab
python3 -m cver reason-only --profile demo
python3 -m cver redteam-only --profile demo
python3 scripts/fetch_real_container_cves.py --years 2021 2026 --max-records 40
```

## 输出

- `data/cver_full_pipeline.db`
- `outputs/runs/<scan_id>/report.json`
- `outputs/runs/<scan_id>/report.md`
- `outputs/runs/<scan_id>/report.html`
- `outputs/benchmarks/<benchmark_id>.json`

## 主要模块

- `cver/scanners`: Scanner 插件，支持 mock / dry-run / real-cli。
- `cver/normalizer.py`: Finding 标准化。
- `cver/vulndb.py`: CVEKnowledge 导入与查询。
- `cver/semantic`: 宏观/细粒度分类、Precondition DSL。
- `cver/reasoner`: 环境感知可利用性判断。
- `cver/graph`: EscapeGraph JSON + Mermaid。
- `cver/redteam`: 受控 Attack Scenario DSL、Planner、Executor。
- `cver/policy`: PolicyGuard 与审计日志。
- `cver/defense`: 防护评分。
- `cver/repair`: RepairPlan、PatchProposal、Retest。
- `cver/benchmark`: Ground Truth 与指标计算。
- `cver/api.py` + `cver/web`: FastAPI + Jinja2 Web 控制台。
- `agent-rs`: Rust/Aya eBPF Agent 预留目录。
