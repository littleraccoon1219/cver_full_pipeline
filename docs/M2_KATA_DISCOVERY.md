# M2：Kata漏洞发掘阶段

M2在M1的数据、分类、审批、审计和加密隔离基础上，增加Kata Containers的真实环境感知漏洞研究能力。它覆盖已知漏洞匹配、源码双轨管理、静态攻击面分析、DeepSeek评审、Sanitizer/libFuzzer验证、Kata Guest动态验收、E0–E5可利用性判定和疑似0-day加密密封。

## 安全边界

M2仅执行授权实验室中的防御性、非武器化验证。它不会生成或自动执行Guest-to-Host逃逸载荷，不提供任意Guest命令接口，也不会把LLM输出、退出码或日志关键字单独视为漏洞证据。

## 安装

```bash
cd ~/cver_full_pipeline
git rev-parse HEAD
# 本地补丁基线必须是 3200cec5f3aa6f24415f6eb26f1bb07ae575ff6f

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

bash scripts/install/install_m2_helper.sh
newgrp cver-m2
cp .env.m2.example .env.m2
```

加载环境变量时不要把密钥提交到Git：

```bash
set -a
source .env.m2
set +a
```

## 基本命令

```bash
python -m cver m2 init
python -m cver m2 doctor
python -m cver m2 kata-compat check
python -m cver m2 prepare-smoke-image
python -m cver m2 kata-smoke
```

依赖默认只检查。显式安装固定白名单：

```bash
python -m cver m2 install-deps --confirm
```

## 双轨源码

默认不下载：

```bash
python -m cver m2 source plan
```

显式开启并确认后下载：

```bash
export CVER_M2_ALLOW_SOURCE_FETCH=true
python -m cver m2 source sync \
  --component kata-containers \
  --component qemu \
  --component virtiofsd \
  --fetch --confirm
```

`installed-baseline`用于已知漏洞和环境可利用性；`research-head`用于未知候选发现。每个结果记录仓库、请求Ref、解析Commit和源码摘要，禁止跨轨混用证据。

## 完整运行

先用短时验收：

```bash
python -m cver m2 run \
  --component kata-containers \
  --component qemu \
  --component virtiofsd \
  --fuzz-seconds 60 \
  --actor yupeng
```

正式平衡档默认单Harness 30分钟、并发2、每组件最多6项任务：

```bash
python -m cver m2 run --profile balanced --actor yupeng
```

DeepSeek未配置或超时时，环境、知识库、静态分析、Harness、Fuzz和Kata阶段继续执行；未知候选保持`unreviewed`，后续通过`resume`补跑未完成阶段。

```bash
python -m cver m2 jobs list
python -m cver m2 jobs show JOB_ID
python -m cver m2 resume JOB_ID
```

## API与Web

```bash
python -m cver m2 web --host 127.0.0.1 --port 8090
```

非回环监听必须配置`CVER_M2_API_TOKEN`。Web只显示脱敏元数据，不显示Corpus、触发输入或疑似0-day敏感调用路径。

## Kata兼容性

当前ARM64环境已验证：Kata 3.32.0与QEMU 11.0.1在`cpu_features = "pmu=off"`时会因不存在`host-arm-cpu.pmu`属性而退出。M2提供显式、可回滚命令：

```bash
python -m cver m2 kata-compat check
python -m cver m2 kata-compat apply --confirm
python -m cver m2 kata-compat restore --confirm
```

普通发现任务不会自行永久修改系统配置。


## 0.3.0扩展文档

- `M2_REAL_KATA_FUZZING.md`：真实Handler源码Fuzz和Adapter审批；
- `M2_VERSIONED_RUNTIME_REPLAY.md`：多版本资产与Guest复验计划；
- `M2_MULTI_AGENT_EVALUATION.md`：六Agent、证据图、数据集和评测。
