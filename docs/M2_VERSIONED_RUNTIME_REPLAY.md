# M2多版本Kata Runtime资产与Guest复验

## 1. 分级策略

```text
当前已安装Kata 3.32.0
  → 使用现有/opt/kata配置生成复验计划

其他Kata版本
  → 独立资产目录、独立Runtime名称、独立配置
  → 不覆盖/opt/kata
  → 资产不完整时标记RUNTIME_NOT_REPRODUCED
```

源码Fuzz不要求安装每一个Kata版本；只有真实Guest复验才要求版本匹配的Runtime、Agent、Kernel、Image、QEMU和配置。

## 2. 资产目录

```text
data/m2/runtime-assets/<version>/
  manifest.json
  runtime/
  agent/
  kernel/
  image/
  config/
  qemu/
  downloads/
  build/
```

每项资产记录绝对路径、SHA-256、大小和来源。Runtime名称格式为：

```text
io.containerd.kata-cver-<version>.v2
```

## 3. 注册已有资产

```bash
python -m cver m2 runtime-assets register \
  --version 3.31.0 \
  --runtime /path/to/containerd-shim-kata-v2 \
  --agent /path/to/kata-agent \
  --kernel /path/to/vmlinux \
  --image /path/to/kata.image \
  --config /path/to/configuration.toml \
  --qemu /path/to/qemu-system-aarch64 \
  --source user-provided
```

需要复制到M2隔离目录时增加：

```bash
--copy-assets --confirm
```

注册后检查：

```bash
python -m cver m2 runtime-assets readiness --version 3.31.0
```

文件缺失或Hash变化时返回`RUNTIME_NOT_REPRODUCED`。

## 4. 官方Release资产

只允许HTTPS和固定域名白名单，并且必须提供期望SHA-256：

```bash
python -m cver m2 runtime-assets fetch-official \
  --version 3.31.0 \
  --asset-name agent \
  --url <官方Release URL> \
  --sha256 <EXPECTED_SHA256> \
  --confirm
```

下载动作不会自动注册，也不会替换系统Kata。

## 5. 显式源码构建

默认禁止。只有同时满足以下条件才执行：

```bash
export CVER_M2_ALLOW_RUNTIME_BUILD=true
python -m cver m2 runtime-assets build \
  --version 3.31.0 \
  --source ~/security-src/kata-containers/3.31.0 \
  --recipe configs/m2_runtime_build_recipes/<approved>.json \
  --confirm
```

构建Recipe必须经过人工批准，命令必须是参数数组，并由固定命令白名单执行。构建完成后仍需人工检查并注册产物。

## 6. Guest复验等级

### L1：RPC_ONLY

只验证解析、参数检查和返回状态，不产生Guest副作用。

### L2：GUEST_NON_DESTRUCTIVE

人工批准后，可在一次性Guest沙箱中创建测试进程、使用Guest临时目录、操作测试stdio、发送非致命信号和更新受限资源。

### L3：ISOLATION_INVARIANT

仅用于`STRONG_CANDIDATE`及以上，验证权限、设备、挂载、网络和Guest/Host边界不变量。仍然禁止逃逸载荷和宿主持久化。

生成计划：

```bash
export CVER_M2_ALLOW_GUEST_REPLAY=true
export CVER_M2_DISPOSABLE_LAB_READY=true
python -m cver m2 replay-plan \
  --candidate data/m2/candidates/<candidate>.json \
  --version 3.32.0 \
  --level L2_GUEST_NON_DESTRUCTIVE \
  --input-artifact <restricted-input> \
  --input-profile bounded_wait \
  --confirm
```

当前交付生成可审计复验计划，不自动执行任意RPC触发材料。真实执行必须由后续版本匹配的受限Replay Client和Root Helper完成。
