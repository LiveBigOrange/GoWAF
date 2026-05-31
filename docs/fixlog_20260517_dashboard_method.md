# 仪表盘敏感数据泄露拦截事件 method 字段为空修复日志

**修复日期**: 2026-05-17  
**问题等级**: 中等  
**版本**: v1.2.0  

---

## 一、问题描述

仪表盘中攻击类型为"敏感数据泄露"的拦截数据中，有一部分数据的 `method`（请求方式）字段为空（显示为"-"），但在拦截日志中会正常显示。同样的问题也影响"响应异常"和"DLP"类型的拦截事件。

## 二、根因分析

### 2.1 问题定位

在 `internal/domain/proxy/forward.go` 中，响应体检测路径调用 `recordBlock` 时，`method` 和 `userAgent` 参数传入了空字符串 `""`，而正确的值应从 `resp.Request` 中获取。

### 2.2 受影响的调用点

| 行号 | 函数 | 原始调用 |
|------|------|----------|
| 290 | `detectResponseBodyContent` | `recordBlock(..., "", "", "响应异常:...", ...)` |
| 368 | `detectSensitiveData` | `recordBlock(..., "", "", "敏感数据泄露:...", ...)` |
| 417 | `detectDLPInResponse` | `recordBlock(..., "", "", "DLP:...", ...)` |

### 2.3 对比正确实现

请求阶段拦截（`detect.go`）中正确传入了 `r.Method` 和 `userAgent`：

```go
p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "攻击检测:"+attackType, ...)
```

### 2.4 下游影响链路

`recordBlock` 的 `method` 参数会被传播至以下下游模块：

1. `stats.IncBlockedPath(path, method, clientIP)` — Top 路径统计
2. `event.AddEvent(..., method, userAgent, ...)` — 内存事件缓冲区（Dashboard 数据源）
3. `metricEvent{method: method, ...}` — Metrics 数据库（Dashboard 数据源）
4. `IntelCollectFn(..., "method": method, ...)` — IntelCenter 情报上报
5. `logger.NewAccessLog().SetMethod(method)...` — 日志系统

当 method 为空字符串时，上述所有下游均收到空值，导致仪表盘显示"-"。

## 三、修复方案

### 3.1 修改内容

将 3 处 `recordBlock` 调用的 `method` 和 `userAgent` 参数从空字符串改为从 `resp.Request` 获取：

```go
// 修改前
p.recordBlock(clientIP, resp.Request.URL.Path, "", "", "敏感数据泄露:...", ...)

// 修改后
p.recordBlock(clientIP, resp.Request.URL.Path, resp.Request.Method, resp.Request.Header.Get("User-Agent"), "敏感数据泄露:...", ...)
```

### 3.2 空指针安全性

3 处调用均位于 `if resp.Request == nil { return }` 守卫之后：

| 函数 | 守卫行号 | 调用行号 |
|------|----------|----------|
| `detectResponseBodyContent` | 249 | 290 |
| `detectSensitiveData` | 316 | 368 |
| `detectDLPInResponse` | 393 | 417 |

不存在空指针解引用风险。

### 3.3 修改文件

| 文件 | 变更类型 | 变更行数 |
|------|----------|----------|
| `internal/domain/proxy/forward.go` | Bug修复 | 3行 |
| `internal/domain/proxy/forward_test.go` | 新增测试 | +69行 |

## 四、新增单元测试

| 测试函数 | 验证内容 |
|----------|----------|
| `TestDetectResponseBodyContent_BlockMode_MethodAndUserAgent` | 验证 `detectResponseBodyContent` 在拦截模式下 `resp.Request.Method` 和 `resp.Request.Header.Get("User-Agent")` 可正确访问且不 panic |
| `TestDetectSensitiveData_BlockMode_MethodAndUserAgent` | 验证 `detectSensitiveData` 在拦截模式下同上 |
| `TestDetectDLPInResponse_BlockMode_MethodAndUserAgent` | 验证 `detectDLPInResponse` 在非观察模式下同上 |

## 五、验证结果

| 检查项 | 结果 |
|--------|------|
| `gofmt` | ✅ 通过 |
| `go vet` | ✅ 通过 |
| 全部 23 个测试 | ✅ 通过（含 3 个新增） |
| `recordBlock` 签名未变更 | ✅ |
| 传参模式与 `detect.go` 对齐 | ✅ |
| 全项目无遗漏空参数调用 | ✅ |
| 修改范围仅限 `forward.go` + `forward_test.go` | ✅ |

## 六、影响范围

- 仪表盘中"敏感数据泄露"、"响应异常"、"DLP"类型的拦截事件 `method` 字段将正确显示请求方式（GET/POST/PUT 等）
- 同一拦截事件的 `userAgent` 字段也将正确显示
- Top 路径统计中这些类型的 `method` 聚合数据将完整
- IntelCenter 情报上报中 `method` 和 `user_agent` 字段将正确填充
- 拦截日志中这些类型的 `method` 和 `user_agent` 字段将正确记录
