# GoWAF v1.1.12 版本发布实现方案

**版本**: v1.1.12  
**基于规格**: spec-v1.1.12.md  
**发布日期**: 2026-05-17  
**文档状态**: 已完成  

---

# 1. 实现模型

## 1.1 上下文视图

### 系统上下文

本实现方案覆盖 GoWAF v1.1.12 版本发布的完整技术流程，将 v1.1.11 基线上的 263 个文件变更（项目结构重构 + 5项Bug修复）交付为正式版本发布。

```
┌──────────────────────────────────────────────────────────┐
│                   发布管理员工作台                         │
│                                                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐   │
│  │ Makefile │  │CHANGELOG│  │   Git    │  │ Go工具链  │   │
│  │ 版本更新  │  │ 条目更新 │  │ 提交/标签 │  │ 构建/测试 │   │
│  └────┬────┘  └────┬────┘  └────┬────┘  └─────┬────┘   │
│       │            │            │              │         │
│       └────────────┴─────┬──────┴──────────────┘         │
│                          │                               │
│                   ┌──────┴──────┐                        │
│                   │ 发布编排引擎 │                        │
│                   └──────┬──────┘                        │
│                          │                               │
│            ┌─────────────┼─────────────┐                │
│            │             │             │                 │
│       ┌────┴────┐  ┌────┴────┐  ┌────┴────┐           │
│       │ GitHub  │  │ build/  │  │ gh CLI  │           │
│       │ 远程仓库 │  │ 构建产物 │  │ Release │           │
│       └─────────┘  └─────────┘  └─────────┘           │
└──────────────────────────────────────────────────────────┘
```

### 外部依赖

| 外部系统 | 交互方式 | 用途 |
|----------|----------|------|
| GitHub (github.com) | HTTPS + gh CLI | 代码推送、标签管理、Release 创建 |
| Go 工具链 (1.25.9) | CLI | 编译、测试、交叉编译 |
| Git | CLI | 版本控制、标签创建 |

## 1.2 服务/组件总体架构

### 发布流程架构

发布流程由 7 个顺序步骤组成，每一步有明确的前置条件、操作动作和验证条件：

```
步骤1: 版本元数据更新 ─────────┐
  ├── Makefile VERSION 更新      │
  └── CHANGELOG.md 条目新增      │
                                │
步骤2: 预提交验证 ◄────────────┘
  ├── go build ./...
  ├── go test ./...
  └── go vet ./...

步骤3: Git 提交 ◄────────────── 步骤2通过
  ├── git add (全部变更)
  └── git commit (Conventional Commits)

步骤4: 创建 Annotated Tag ◄─── 步骤3完成
  └── git tag -a v1.1.12 -m "..."

步骤5: 推送到 GitHub ◄──────── 步骤4完成
  ├── git push origin main
  └── git push origin v1.1.12

步骤6: 全平台构建 ◄─────────── 步骤5完成
  └── make build-all → build/ 目录

步骤7: 创建 GitHub Release ◄── 步骤6完成
  └── gh release create v1.1.12
```

### 错误处理架构

每个步骤执行失败时，流程立即中止并报告具体错误信息，不自动重试。发布管理员需手动修复后从失败步骤重新开始。

```
步骤执行 → [成功] → 下一步骤
         → [失败] → 报告错误 + 中止
                     发布管理员手动修复
                     从失败步骤重新执行
```

## 1.3 实现设计文档

### 步骤 1：版本元数据更新

#### 1.3.1 Makefile VERSION 更新

**操作对象**: `D:/Go项目/gowaf/GoWAF/Makefile`

**当前值**:
```makefile
VERSION := 1.1.11
```

**目标值**:
```makefile
VERSION := 1.1.12
```

**实现方式**: 文本替换，将 `VERSION := 1.1.11` 替换为 `VERSION := 1.1.12`

**验证命令**:
```bash
grep "VERSION" Makefile
# 预期输出: VERSION := 1.1.12
```

**异常处理**:
- 若 Makefile 中不存在 `VERSION :=` 行 → 中止，报告"Makefile 中未找到 VERSION 字段定义"
- 若 VERSION 已为 1.1.12 → 跳过此步骤，记录警告

#### 1.3.2 CHANGELOG.md 条目新增

**操作对象**: `D:/Go项目/gowaf/GoWAF/CHANGELOG.md`

**新增内容**（插入在 `## [Unreleased]` 之后、`## [1.1.7]` 之前）:

```markdown
## [1.1.12] - 2026-05-17

### 重构
- **项目结构重构 - 4层架构**：将 `internal/` 下 33 个扁平包重组为 4 层架构（domain/infra/cert/pkg），消除反向依赖、合并碎片包、补充包文档
  - 业务领域层 `domain/`：proxy（核心代理域）、security（安全检测域）、gateway（Web接口域）、auxiliary（辅助功能域）、proxyconfig（代理配置管理）
  - 基础设施层 `infra/`：config（配置管理）、storage（数据存储）、logger（异步日志）、event（事件缓冲）、notify（通知系统）
  - 证书与更新域 `cert/`：acme、geoipupdater
  - 通用工具域 `pkg/xutil/`：合并 netutil+timeutil
- **依赖方向规则强化**：infra→domain 禁止、pkg→任何内部包禁止、config→middleware 通过 apischema 回调解耦
- **包文档补充**：为 internal/ 下 31 个 Go 包补充 doc.go 文件
- **测试基础设施**：新增 testutil 包（dbutil, httputil, assertx）

### 修复
- **[严重] 拦截日志查询时区不一致**：拦截事件以 UTC 时间写入，但查询接口使用本地时间，导致 UTC+8 时区下历史数据不可见。所有查询时间统一改为 UTC（`time.Now().UTC()`）
- **[严重] logDB 未注入 logger**：`logger.InitWithRotationAndDB()` 在 logDB 创建前调用且传 nil，日志从不写入数据库。新增 `logger.SetDB()` 延迟注入方法
- **[中等] 拦截日志降级逻辑缺陷**：查询成功但返回0条记录时错误降级到内存缓冲。修正为仅当查询返回 error 时降级
- **[低] pageSize 上限调整**：后端 pageSize 上限从 1000 调整为 10000，与前端 `page_size=10000` 请求匹配
- **[低] 管理界面端口变更**：默认监听端口从 9090 变更为 8090，避开 Windows Hyper-V 保留端口范围（9085-9184）
```

**Unreleased 区段处理**: 清空 `## [Unreleased]` 下的所有条目（当前已为空，无需额外操作）

**底部链接更新**: 在 CHANGELOG.md 底部添加版本比较链接：

```markdown
[Unreleased]: https://github.com/LiveBigOrange/GoWAF/compare/v1.1.12...HEAD
[1.1.12]: https://github.com/LiveBigOrange/GoWAF/compare/v1.1.7...v1.1.12
```

**验证命令**:
```bash
grep "1.1.12" CHANGELOG.md | head -1
# 预期输出: ## [1.1.12] - 2026-05-17
```

**异常处理**:
- 若 CHANGELOG.md 已包含 `## [1.1.12]` → 中止，报告"CHANGELOG.md 已包含 v1.1.12 条目，请检查是否重复发布"

---

### 步骤 2：预提交验证

在执行 Git 提交前，必须通过以下三项验证，确保代码变更不会引入编译错误或测试回归。

#### 1.3.3 编译验证

**命令**:
```bash
go build ./...
```

**预期结果**: 零编译错误，命令退出码为 0

**失败处理**: 中止发布流程，报告编译错误详情，需修复后再重试

#### 1.3.4 测试验证

**命令**:
```bash
go test ./...
```

**预期结果**: 零测试失败，命令退出码为 0

**失败处理**: 中止发布流程，报告失败测试名称和断言详情

#### 1.3.5 静态分析验证

**命令**:
```bash
go vet ./...
```

**预期结果**: 零警告，命令退出码为 0

**失败处理**: 中止发布流程，报告 vet 警告详情

#### 1.3.6 依赖方向验证（可选增强）

**验证逻辑**: 确认重构后的依赖方向规则持续有效

```bash
# 检查 infra 不依赖 domain
grep -r "gowaf/internal/domain" internal/infra/ 2>/dev/null
# 预期输出: 空（无匹配）

# 检查 pkg 不依赖任何 internal 包
grep -r "gowaf/internal" internal/pkg/ 2>/dev/null
# 预期输出: 空（无匹配）
```

---

### 步骤 3：Git 提交

#### 1.3.7 提交所有变更

**前置条件**: 步骤 1（版本元数据更新）和步骤 2（预提交验证）均已完成

**操作序列**:

```bash
# 1. 查看当前工作区状态
git status

# 2. 暂存所有变更文件（包含重构、Bug修复、版本元数据更新）
git add .

# 3. 创建提交（Conventional Commits 格式）
git commit -m "release: v1.1.12 - 项目结构重构与Bug修复

重构:
- internal/ 33个扁平包重组为4层架构(domain/infra/cert/pkg)
- 依赖方向规则强化(infra→domain禁止, pkg→internal禁止)
- 31个doc.go包文档补充
- testutil测试基础设施新增

修复:
- [严重] 拦截日志查询时区不一致(UTC统一)
- [严重] logDB未注入logger(SetDB延迟注入)
- [中等] 拦截日志降级逻辑缺陷(仅error时降级)
- [低] pageSize上限调整1000→10000
- [低] 管理界面端口9090→8090

🤖 Generated with CodeMate"
```

**提交消息设计说明**:
- 类型前缀使用 `release`，表示版本发布提交
- 首行简洁描述版本号和核心变更类型
- 空行后按"重构"和"修复"分类列出详细变更
- 每项修复标注严重程度

**验证命令**:
```bash
# 验证提交成功
git log -1 --oneline
# 预期输出: <hash> release: v1.1.12 - 项目结构重构与Bug修复

# 验证工作区干净
git status
# 预期输出: nothing to commit, working tree clean
```

**异常处理**:
- 若 `git add .` 后无变更（工作区已是干净状态） → 报告警告"无待提交变更，请检查是否已提交"
- 若提交失败（pre-commit hook 拒绝等） → 报告错误详情

---

### 步骤 4：创建 Annotated Tag

#### 1.3.8 创建 v1.1.12 标签

**操作**:

```bash
git tag -a v1.1.12 -m "Release v1.1.12 (2026-05-17)

项目结构重构: 33个扁平包 → 4层架构(domain/infra/cert/pkg)
Bug修复: 时区一致性、logDB注入、降级逻辑、pageSize上限、端口变更"
```

**标签附注内容设计**:
- 第一行：版本号和发布日期
- 空行后：变更摘要（重构 + 修复概述）

**验证命令**:
```bash
# 验证标签存在
git tag -l v1.1.12
# 预期输出: v1.1.12

# 验证为 annotated tag（显示类型为 tag）
git cat-file -t v1.1.12
# 预期输出: tag

# 验证标签附注内容
git tag -n99 v1.1.12
# 预期输出: 包含 "Release v1.1.12 (2026-05-17)"
```

**异常处理**:
- 若标签已存在 → 中止，报告"tag 'v1.1.12' already exists"，需先删除旧标签 `git tag -d v1.1.12`

---

### 步骤 5：推送到 GitHub

#### 1.3.9 推送代码和标签

**操作序列**:

```bash
# 1. 推送代码到远程主分支
git push origin main

# 2. 推送标签到远程
git push origin v1.1.12
```

**替代方案（单命令推送）**:
```bash
git push origin main v1.1.12
```

**验证命令**:
```bash
# 验证远程分支已更新
git log origin/main -1 --oneline
# 预期输出: 包含 v1.1.12 提交

# 验证远程标签存在
git ls-remote --tags origin | grep v1.1.12
# 预期输出: refs/tags/v1.1.12
```

**异常处理**:
- 若推送被拒绝（"Updates were rejected"） → 先 `git pull --rebase origin main`，解决冲突后重新推送
- 若网络超时 → 检查网络连接后重试
- 若认证失败 → 检查 SSH 密钥或 HTTPS 凭证配置

---

### 步骤 6：全平台构建

#### 1.3.10 交叉编译所有平台

**前置条件**: 步骤 5 完成，远程代码已更新

**操作**:

```bash
make build-all
```

**等价手动命令**:
```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -v -o build/gowaf-linux-amd64 ./cmd/waf

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -v -o build/gowaf-linux-arm64 ./cmd/waf

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -v -o build/gowaf-darwin-amd64 ./cmd/waf

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -v -o build/gowaf-darwin-arm64 ./cmd/waf

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -v -o build/gowaf-windows-amd64.exe ./cmd/waf
```

**预期产物清单**:

| 文件名 | 平台 | 架构 | 预估大小 |
|--------|------|------|----------|
| `gowaf-linux-amd64` | Linux | AMD64 | ~25MB |
| `gowaf-linux-arm64` | Linux | ARM64 | ~24MB |
| `gowaf-darwin-amd64` | macOS | AMD64 | ~27MB |
| `gowaf-darwin-arm64` | macOS | ARM64 | ~26MB |
| `gowaf-windows-amd64.exe` | Windows | AMD64 | ~26MB |

**验证命令**:
```bash
# 验证构建产物存在
ls -la build/
# 预期输出: 包含上述5个文件

# 验证文件数量
ls build/ | wc -l
# 预期输出: 5
```

**异常处理**:
- 若特定平台构建失败 → 报告失败平台和错误信息，可单独重试该平台构建
- 若 CGO 相关错误 → 确认 `CGO_ENABLED=0` 环境变量设置（纯 Go SQLite 无需 CGO）

**性能约束**: 全平台构建总时间不得超过 5 分钟

---

### 步骤 7：创建 GitHub Release

#### 1.3.11 前置检查

**检查 gh CLI 可用性**:
```bash
which gh
# 预期: 返回 gh 命令路径

gh --version
# 预期: 返回 gh 版本号（≥ 2.0）
```

**检查 gh 认证状态**:
```bash
gh auth status
# 预期: 已登录到 github.com
```

#### 1.3.12 创建 Release

**Release Notes 模板**（保存为临时文件 `build/release-notes-v1.1.12.md`）:

```markdown
## GoWAF v1.1.12 (2026-05-17)

### 重构

**项目结构重构 - 4层架构**

将 `internal/` 下 33 个扁平包重组为 4 层架构，消除反向依赖、合并碎片包、补充包文档：

- **业务领域层 `domain/`**
  - `proxy/` — 核心代理域（proxy + pathbodylimit）
  - `security/` — 安全检测域（detector, rules, ratelimit, limiter, bot, vpatch, dlprule）
  - `gateway/` — Web接口域（handler, middleware, static, templates, model）
  - `auxiliary/` — 辅助功能域（blockpage, reqheader, respheader, sessionsafe, compliance, masker）
  - `proxyconfig/` — 代理配置管理（跨域共享）
- **基础设施层 `infra/`**
  - `config/` — 配置管理域（config, configversion）
  - `storage/` — 数据存储域（database, logdb, metrics, stats）
  - `logger/` — 异步日志系统
  - `event/` — 事件缓冲
  - `notify/` — 通知系统
  - `interfaces.go` — 统一接口定义（Logger/Metrics/Event/Config）
- **证书与更新域 `cert/`** — acme, geoipupdater
- **通用工具域 `pkg/xutil/`** — 合并 netutil+timeutil

**依赖方向规则**：
- `domain/` → `infra/` ✅ 允许
- `infra/` → `domain/` ❌ 禁止
- `pkg/` → 任何内部包 ❌ 禁止

### 修复

| 严重程度 | 描述 | 影响 |
|----------|------|------|
| 🔴 严重 | 拦截日志查询时区不一致 | UTC+8 下拦截日志和仪表盘数据不可见 |
| 🔴 严重 | logDB 未注入 logger | 日志 API 查询返回空数据 |
| 🟡 中等 | 拦截日志降级逻辑缺陷 | 查询无数据时返回过期内存缓冲 |
| 🟢 低 | pageSize 上限与前端不匹配 | 分页和总数不一致 |
| 🟢 低 | 管理界面端口被 Hyper-V 保留 | Windows 上服务启动失败 |

### ⚠️ 破坏性变更

- **管理界面端口变更**：默认监听端口从 `9090` 变更为 `8090`
  - 升级后需更新反向代理配置指向新端口 `8090`
  - 升级后需更新防火墙规则放行 `8090`
  - 如需保留旧端口，在 `config.yaml` 中显式设置 `listen: "0.0.0.0:9090"`

### 验证结果

| 检查项 | 结果 |
|--------|------|
| `go build ./...` | ✅ 通过 |
| `go test ./...` | ✅ 通过 |
| `go vet ./...` | ✅ 无警告 |
| infra→domain 依赖 | ✅ 零违规 |
| pkg→internal 依赖 | ✅ 零违规 |
| package 声明一致性 | ✅ 通过 |
| doc.go 完整性 | ✅ 通过 |
```

**创建 Release 命令**:

```bash
gh release create v1.1.12 \
  --title "v1.1.12" \
  --notes-file build/release-notes-v1.1.12.md \
  build/gowaf-linux-amd64 \
  build/gowaf-linux-arm64 \
  build/gowaf-darwin-amd64 \
  build/gowaf-darwin-arm64 \
  build/gowaf-windows-amd64.exe
```

**验证命令**:
```bash
# 验证 Release 已创建
gh release view v1.1.12
# 预期: 显示 Release 详情

# 验证附件数量
gh release view v1.1.12 --json assets --jq '.assets | length'
# 预期输出: 5
```

**异常处理**:
- 若 gh CLI 未安装 → 中止，提示安装命令 `winget install GitHub.cli`（Windows）或 `brew install gh`（macOS）
- 若 gh 认证失败 → 中止，提示执行 `gh auth login`
- 若 Release 已存在 → 中止，提示先删除 `gh release delete v1.1.12 --yes`
- 若二进制文件上传失败 → 可手动补充上传：`gh release upload v1.1.12 build/gowaf-linux-amd64 --clobber`

---

# 2. 接口设计

## 2.1 总体设计

本版本发布不涉及 API 接口变更。所有交互通过 CLI 命令（git、go、make、gh）完成，无程序化接口调用。

## 2.2 接口清单

### 命令行接口

| 序号 | 命令 | 用途 | 退出码预期 |
|------|------|------|-----------|
| 1 | `grep "VERSION" Makefile` | 验证版本号更新 | 0 |
| 2 | `go build ./...` | 编译验证 | 0 |
| 3 | `go test ./...` | 测试验证 | 0 |
| 4 | `go vet ./...` | 静态分析 | 0 |
| 5 | `git add . && git commit -m "..."` | 提交变更 | 0 |
| 6 | `git tag -a v1.1.12 -m "..."` | 创建标签 | 0 |
| 7 | `git push origin main` | 推送代码 | 0 |
| 8 | `git push origin v1.1.12` | 推送标签 | 0 |
| 9 | `make build-all` | 全平台构建 | 0 |
| 10 | `gh release create v1.1.12 ...` | 创建 Release | 0 |

### 文件修改接口

| 序号 | 文件路径 | 修改类型 | 修改内容 |
|------|----------|----------|----------|
| 1 | `Makefile` | 行替换 | `VERSION := 1.1.11` → `VERSION := 1.1.12` |
| 2 | `CHANGELOG.md` | 行插入 | 在 `[Unreleased]` 后插入 v1.1.12 条目 |
| 3 | `CHANGELOG.md` | 行追加 | 底部添加版本比较链接 |

---

# 4. 数据模型

## 4.1 设计目标

本发布流程的数据模型定义了版本元数据、构建产物和发布记录的核心数据结构，确保流程中各步骤的数据一致性和可追溯性。

## 4.2 模型实现

### 版本元数据模型

```
VersionMetadata {
    current_version:   "1.1.12"          // 语义化版本号
    previous_version:  "1.1.11"          // 前一版本号
    release_date:      "2026-05-17"      // 发布日期 (YYYY-MM-DD)
    version_prefix:    "v"               // Git 标签前缀
    changelog_date_format: "YYYY-MM-DD"  // CHANGELOG 日期格式
}
```

### 构建产物模型

```
BuildArtifact {
    naming_pattern:  "gowaf-{os}-{arch}{ext}"  // 文件命名规则
    output_dir:      "build/"                    // 产物输出目录
    platforms: [
        { os: "linux",   arch: "amd64", ext: ""    },
        { os: "linux",   arch: "arm64", ext: ""    },
        { os: "darwin",  arch: "amd64", ext: ""    },
        { os: "darwin",  arch: "arm64", ext: ""    },
        { os: "windows", arch: "amd64", ext: ".exe" }
    ]
    total_count: 5
}
```

### 修复记录模型

```
BugFix {
    id:                  int       // Bug 编号 (1-5)
    severity:            string    // "严重" | "中等" | "低"
    summary:             string    // 修复摘要
    affected_components: []string  // 受影响组件列表
    verification_status: string    // "已验证"
}

// v1.1.12 修复清单
BugFixes = [
    { id: 1, severity: "严重", summary: "拦截日志查询时区不一致",
      affected_components: ["dashboard.go"], verification_status: "已验证" },
    { id: 2, severity: "严重", summary: "logDB未注入logger",
      affected_components: ["logger.go", "main.go"], verification_status: "已验证" },
    { id: 3, severity: "中等", summary: "拦截日志降级逻辑缺陷",
      affected_components: ["dashboard.go"], verification_status: "已验证" },
    { id: 4, severity: "低", summary: "pageSize上限调整1000→10000",
      affected_components: ["dashboard.go"], verification_status: "已验证" },
    { id: 5, severity: "低", summary: "管理界面端口9090→8090",
      affected_components: ["config.yaml"], verification_status: "已验证" }
]
```

### 依赖方向模型

```
DependencyRule {
    source_layer: string   // "domain" | "infra" | "cert" | "pkg"
    target_layer: string   // 同上
    allowed:      bool     // 是否允许
}

// 依赖方向规则
DependencyRules = [
    { source: "domain", target: "infra",  allowed: true  },  // 允许
    { source: "infra",  target: "domain", allowed: false },  // 禁止
    { source: "pkg",    target: "*",      allowed: false },  // 禁止(pkg→任何internal包)
]
```

---

# 5. 完整发布执行脚本

以下为完整的发布执行命令序列，按步骤严格顺序执行：

## 5.1 一键执行脚本（仅供参考，建议分步执行）

```bash
#!/bin/bash
# GoWAF v1.1.12 发布脚本
# 工作目录: D:/Go项目/gowaf/GoWAF
# 执行前请确认: gh CLI 已安装且已认证

set -e  # 任何命令失败立即中止

echo "=== GoWAF v1.1.12 发布流程 ==="

# --- 步骤 1: 版本元数据更新 ---
echo "[步骤1] 更新 Makefile VERSION..."
# (需要手动编辑 Makefile: VERSION := 1.1.12)
# (需要手动编辑 CHANGELOG.md: 添加 v1.1.12 条目)

# --- 步骤 2: 预提交验证 ---
echo "[步骤2] 预提交验证..."
go build ./...
echo "  ✅ go build 通过"
go test ./...
echo "  ✅ go test 通过"
go vet ./...
echo "  ✅ go vet 通过"

# --- 步骤 3: Git 提交 ---
echo "[步骤3] Git 提交..."
git add .
git commit -m "release: v1.1.12 - 项目结构重构与Bug修复

重构:
- internal/ 33个扁平包重组为4层架构(domain/infra/cert/pkg)
- 依赖方向规则强化(infra→domain禁止, pkg→internal禁止)
- 31个doc.go包文档补充
- testutil测试基础设施新增

修复:
- [严重] 拦截日志查询时区不一致(UTC统一)
- [严重] logDB未注入logger(SetDB延迟注入)
- [中等] 拦截日志降级逻辑缺陷(仅error时降级)
- [低] pageSize上限调整1000→10000
- [低] 管理界面端口9090→8090

🤖 Generated with CodeMate"
echo "  ✅ Git 提交完成"

# --- 步骤 4: 创建 Annotated Tag ---
echo "[步骤4] 创建 v1.1.12 标签..."
git tag -a v1.1.12 -m "Release v1.1.12 (2026-05-17)

项目结构重构: 33个扁平包 → 4层架构(domain/infra/cert/pkg)
Bug修复: 时区一致性、logDB注入、降级逻辑、pageSize上限、端口变更"
echo "  ✅ 标签 v1.1.12 创建完成"

# --- 步骤 5: 推送到 GitHub ---
echo "[步骤5] 推送到 GitHub..."
git push origin main
git push origin v1.1.12
echo "  ✅ 推送完成"

# --- 步骤 6: 全平台构建 ---
echo "[步骤6] 全平台构建..."
make build-all
echo "  ✅ 构建完成，产物列表:"
ls -la build/

# --- 步骤 7: 创建 GitHub Release ---
echo "[步骤7] 创建 GitHub Release..."
gh release create v1.1.12 \
  --title "v1.1.12" \
  --notes-file build/release-notes-v1.1.12.md \
  build/gowaf-linux-amd64 \
  build/gowaf-linux-arm64 \
  build/gowaf-darwin-amd64 \
  build/gowaf-darwin-arm64 \
  build/gowaf-windows-amd64.exe
echo "  ✅ GitHub Release v1.1.12 创建完成"

echo ""
echo "=== GoWAF v1.1.12 发布完成 ==="
```

## 5.2 回滚方案

| 步骤 | 回滚操作 | 命令 |
|------|----------|------|
| 步骤 1 | 恢复 Makefile VERSION | 恢复 `VERSION := 1.1.11`，撤销 CHANGELOG 修改 |
| 步骤 3 | 撤销 Git 提交 | `git reset --soft HEAD~1` |
| 步骤 4 | 删除本地标签 | `git tag -d v1.1.12` |
| 步骤 5 | 撤销远程推送 | `git push origin :refs/tags/v1.1.12`（仅删标签，不删代码） |
| 步骤 6 | 清理构建产物 | `make clean` |
| 步骤 7 | 删除 GitHub Release | `gh release delete v1.1.12 --yes` |

---

# 6. 验收检查清单映射

| # | 检查项 | 对应实现步骤 | 验证命令 |
|---|--------|-------------|----------|
| 1 | Makefile 版本号 | 步骤 1.3.1 | `grep "VERSION" Makefile` → `VERSION := 1.1.12` |
| 2 | CHANGELOG 条目 | 步骤 1.3.2 | `grep "1.1.12" CHANGELOG.md` → 包含 `[1.1.12] - 2026-05-17` |
| 3 | go build | 步骤 1.3.3 | `go build ./...` → 退出码 0 |
| 4 | go test | 步骤 1.3.4 | `go test ./...` → 退出码 0 |
| 5 | go vet | 步骤 1.3.5 | `go vet ./...` → 退出码 0 |
| 6 | 依赖方向检查 | 步骤 1.3.6 | `grep -r` 验证 → 零违规 |
| 7 | 包文档完整性 | 步骤 2 前置 | 已在重构阶段完成 |
| 8 | 包声明一致性 | 步骤 1.3.3 | 编译通过即验证 |
| 9 | 全平台构建 | 步骤 1.3.10 | `ls build/` → 5 个文件 |
| 10 | Git 提交 | 步骤 1.3.7 | `git status` → working tree clean |
| 11 | v1.1.12 标签 | 步骤 1.3.8 | `git cat-file -t v1.1.12` → `tag` |
| 12 | GitHub 推送 | 步骤 1.3.9 | `git ls-remote --tags origin` → v1.1.12 |
| 13 | GitHub Release | 步骤 1.3.12 | `gh release view v1.1.12` → 存在 |
| 14 | Release 附件 | 步骤 1.3.12 | `gh release view --json assets` → 5 个 |
| 15 | 时区一致性修复 | 已完成（代码变更） | 重构阶段已验证 |
| 16 | logDB 注入修复 | 已完成（代码变更） | 重构阶段已验证 |
| 17 | 降级逻辑修复 | 已完成（代码变更） | 重构阶段已验证 |
| 18 | pageSize 上限 | 已完成（代码变更） | 重构阶段已验证 |
| 19 | 端口变更 | 已完成（代码变更） | 重构阶段已验证 |
| 20 | 旧路径残留 | 已完成（重构阶段） | 重构阶段已验证 |
