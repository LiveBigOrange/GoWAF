# GoWAF 日志审计模块修复与优化日志

**日期**: 2026-05-17  
**版本**: v1.2.1  
**基于版本**: v1.2.0

---

## 一、Bug修复

### 1. [严重] 访问日志/管理日志详情面板自动关闭

**问题**: 点击日志条目查看详情后，等待约30秒详情面板会自动关闭。

**根因**: `logs_table.js` 和 `adminlog.js` 中每30秒执行 `setInterval(loadLogs, 30000)`，触发 `loadLogs` → `applyFilters` → `renderLogs`，而 `renderLogs` 中 `tbody.innerHTML = ''` 清空整个表格并重建DOM，导致已展开的详情行（`.detail-row`）被销毁。

**修复方案**:
- 新增 `log_autorefresh.js` 公共组件（`LogAutoRefresh`），支持多原因暂停/恢复自动刷新
- 新增 `log_detail.js` 公共组件（`LogDetailManager`），追踪详情行展开状态，与 `LogAutoRefresh` 联动
- 展开详情时调用 `autoRefresh.pause('detail-viewing')` 暂停自动刷新
- 收起所有详情后调用 `autoRefresh.resume('detail-viewing')` 恢复自动刷新
- `renderLogs` 结尾新增 `restoreExpandedDetails()` 调用，自动刷新触发渲染后恢复已展开的详情行

**涉及文件**:
- `static/js/log_autorefresh.js`（新增）
- `static/js/log_detail.js`（新增）
- `static/js/logs_table.js`（修改）
- `static/js/adminlog.js`（修改）

### 2. [中等] 系统日志自动刷新时翻页状态重置

**问题**: 用户翻到第3页后，等待5秒自动刷新，页码被重置回第1页。

**根因**: `syslog_page.js` 中 `loadLogs()` 调用 `applyFilter()`，而 `applyFilter()` 中 `currentPage = 1`，自动刷新时无条件重置页码。

**修复方案**:
- 为 `loadLogs` 添加 `silent` 参数：`loadLogs(true)` 为静默模式
- 静默模式下调用 `applyFilterSilent()`，仅更新数据和统计卡片，保持当前页码不变
- 用户主动筛选/刷新时调用 `loadLogs()`（非静默），正常重置页码
- 将原有的 `setInterval` + 手动启停替换为 `LogAutoRefresh` 组件，`onRefresh` 回调调用 `loadLogs(true)`

**涉及文件**:
- `static/js/syslog_page.js`（重写）

### 3. [中等] 翻页/筛选时详情行状态残留导致错误展开

**问题**: 用户在第1页展开某条详情后翻页，`restoreExpandedDetails()` 会基于旧的 index 在新页面上错误地展开不同数据的详情行。

**根因**: `detailManager` 追踪的 detailId 基于 index（如 `log-detail-0`），翻页后 index=0 对应不同数据。

**修复方案**: 在 `prevPage`、`nextPage`、`changePageSize`、`applyFilters` 中，翻页/筛选前先调用 `detailManager.collapseAll()` 清除所有详情状态。

**涉及文件**:
- `static/js/logs_table.js`
- `static/js/adminlog.js`
- `static/js/intercepts_table.js`

---

## 二、翻页功能统一

### 修改前差异

| 页面 | 默认pageSize | 可选项 |
|------|-------------|--------|
| 拦截日志 | 10 | 10, 20, 50, 100 |
| 访问日志 | 50 | 20, 50, 100, 200 |
| 管理日志 | 50 | 20, 50, 100, 200 |
| 系统日志 | 50 | 50, 100, 200, 500 |

### 修改后统一

| 项目 | 统一值 |
|------|--------|
| 默认pageSize | 50 |
| 可选项 | 20, 50, 100, 200 |
| URL状态同步 | 全部支持 |

**涉及文件**:
- `templates/intercepts.html`（分页选项修改）
- `static/js/intercepts_table.js`（pageSize=50, syncURL判断修改）
- `templates/syslog.html`（分页选项修改）

---

## 三、默认展示设置统一

### 1. 移除loadLimit选择器

**问题**: 访问日志和管理日志页面有"加载500条/1000条/2000条/5000条"下拉框，用户需手动选择加载数量，与其他页面不一致。

**修复**: 移除 `loadLimit` 选择器，固定 `limit=5000`，与系统日志一致。

**涉及文件**:
- `templates/logs.html`（移除loadLimit select）
- `templates/adminlog.html`（移除loadLimit select）
- `static/js/logs_table.js`（移除loadLimit变量引用）
- `static/js/adminlog.js`（移除loadLimit变量引用）

### 2. 统一自动刷新控件

**修改前**:
- 拦截日志：无自动刷新
- 访问日志：30秒固定刷新，无开关
- 管理日志：30秒固定刷新，无开关
- 系统日志：5秒可开关刷新

**修改后**:
- 拦截日志：新增自动刷新按钮（默认关闭，30秒）
- 访问日志：新增自动刷新按钮（默认开启，30秒）
- 管理日志：新增自动刷新按钮（默认开启，30秒）
- 系统日志：保持原有（默认开启，5秒），底层替换为LogAutoRefresh组件

**涉及文件**:
- `templates/intercepts.html`（新增autoRefreshBtn）
- `templates/logs.html`（新增autoRefreshBtn）
- `templates/adminlog.html`（新增autoRefreshBtn）
- `static/js/intercepts_table.js`（初始化LogAutoRefresh）

### 3. 拦截日志加载方式优化

**修改**: API调用从 `page_size=10000` 改为 `page_size=5000`，减少不必要的大批量加载。

---

## 四、分页布局与样式统一

### 1. 分页居中布局

**修改前**: 分页栏采用 `justify-content: space-between`，页码信息左对齐、翻页按钮右对齐。

**修改后**: 改为 `justify-content: center`，页码信息和翻页按钮作为整体居中显示，符合 Element Plus / Ant Design 等现代UI规范。

**涉及文件**:
- `static/common.css`（`.pagination` justify-content改为center）
- `static/css/syslog.css`（同步修改）
- `static/css/smartlimit.css`（同步修改）

### 2. 分页固定在页面底部

**问题**: 当页面数据少（如只有1条）或无数据时，分页组件紧跟在数据下方，悬浮在页面中间，而非固定在页面底部。

**根因**: 
- 分页组件 `margin-top: auto` 需在 flex column 父容器中才能生效
- 部分页面的分页在 `.list-container` 内部，`.list-container` 的滚动区域不是 flex 容器
- 部分页面的 `.card` 容器没有 `flex: 1`，无法占满 `.main` 剩余空间

**修复方案**:
- 将 `.pagination` 的 `margin-top` 从固定值改为 `auto`，利用 flex 布局自动推到底部
- 将分页从 `.list-container` 内部移到外部（`.card` 内、`.list-container` 后）
- 为 `.card` 添加 `display: flex; flex-direction: column` 默认布局
- 为包含分页的 `.card` 添加 `flex: 1; min-height: 0` 使其占满 `.main` 剩余空间

**涉及文件（分页移出list-container）**:

| 页面 | 修改内容 |
|------|---------|
| `templates/proxyconfig.html` | 分页从list-container内移到外部，card添加flex:1 |
| `templates/backend.html` | 同上 |
| `templates/domain.html` | 同上 |
| `templates/path.html` | 同上，card添加flex:1 |
| `templates/rules.html` | 同上 |
| `templates/ua.html` | 同上 |

**涉及文件（CSS）**:
- `static/common.css`（`.pagination` margin-top改为auto；`.card` 默认flex column）
- `static/css/syslog.css`（margin-top改为auto）
- `static/css/smartlimit.css`（margin-top改为auto）

### 3. 分页选项格式统一

**问题**: 各页面分页选项文本格式不一致，混用 `X 条`、`X条/页`、`X 条/页` 三种格式。

**修改后**: 全站统一为 `X 条/页`（X和条之间有空格），与 Element Plus 规范一致。

**涉及文件（7个页面）**:

| 页面 | 修改前 | 修改后 |
|------|--------|--------|
| backend.html | `5 条` `10 条` | `5 条/页` `10 条/页` |
| proxyconfig.html | `5 条` `10 条` | `5 条/页` `10 条/页` |
| cert.html | `10条/页`（无空格） | `10 条/页` |
| domain.html | `5条/页`（无空格） | `5 条/页` |
| path.html | `5条/页`（无空格） | `5 条/页` |
| rules.html | `5条/页`（无空格） | `5 条/页` |
| ua.html | `5条/页`（无空格） | `5 条/页` |

日志四页面（intercepts/logs/adminlog/syslog）的 `100 条` `200 条` 也统一为 `100 条/页` `200 条/页`。

---

## 五、公共CSS样式扩展

将 `syslog.css` 中独有的自动刷新按钮样式（`.auto-refresh-btn`、`.ar-icon`、`@keyframes spin`）提升到 `common.css`，使所有页面共享：

```css
.auto-refresh-btn { ... display: inline-flex; ... }
.auto-refresh-btn:hover { ... }
.auto-refresh-btn.active { ... }
.auto-refresh-btn .ar-icon { ... display: inline-block; }
.auto-refresh-btn.active .ar-icon { animation: ar-spin 1s linear infinite; }
@keyframes ar-spin { to { transform: rotate(360deg); } }
```

移除 `syslog.css` 中的重复定义，避免样式冲突。

---

## 六、JS模块加载顺序

确保公共组件在各页面中按正确顺序加载（先依赖后业务）：

| 页面 | JS加载顺序 |
|------|-----------|
| 拦截日志 | `log_autorefresh.js` → `log_detail.js` → `intercepts_table.js` → `intercepts_filter.js` |
| 访问日志 | `log_autorefresh.js` → `log_detail.js` → `logs_table.js` → `logs_export.js` |
| 管理日志 | `log_autorefresh.js` → `log_detail.js` → `adminlog.js` |
| 系统日志 | `log_autorefresh.js` → `syslog_page.js` |

---

## 七、变更文件清单

### 新增文件（2个）
| 文件 | 说明 |
|------|------|
| `static/js/log_autorefresh.js` | 自动刷新启停管理器 |
| `static/js/log_detail.js` | 详情行状态追踪管理器 |

### 修改文件（15个）
| 文件 | 修改内容 |
|------|---------|
| `static/js/logs_table.js` | 替换setInterval为LogAutoRefresh、toggleDetail联动LogDetailManager、新增restoreExpandedDetails、翻页/筛选前collapseAll、移除loadLimit、固定limit=5000 |
| `static/js/adminlog.js` | 同上 |
| `static/js/syslog_page.js` | 重写：LogAutoRefresh替换手动启停、新增silent模式applyFilterSilent、翻页保持 |
| `static/js/intercepts_table.js` | pageSize改为50、syncURL判断修改、新增LogAutoRefresh/LogDetailManager、翻页前collapseAll、page_size改为5000 |
| `templates/logs.html` | 移除loadLimit、新增autoRefreshBtn、引入公共JS、分页选项格式统一 |
| `templates/adminlog.html` | 同上 |
| `templates/syslog.html` | 分页选项统一、引入log_autorefresh.js |
| `templates/intercepts.html` | 分页选项统一、新增autoRefreshBtn、引入公共JS |
| `templates/proxyconfig.html` | 分页从list-container内移出、card添加flex:1、分页选项格式统一 |
| `templates/backend.html` | 同上 |
| `templates/domain.html` | 同上 |
| `templates/path.html` | 同上 |
| `templates/rules.html` | 同上 |
| `templates/ua.html` | 同上 |
| `templates/cert.html` | 分页选项格式统一（加空格） |
| `static/common.css` | 分页居中+margin-top:auto、card默认flex column、新增auto-refresh-btn公共样式 |
| `static/css/syslog.css` | 分页居中+margin-top:auto、移除重复auto-refresh样式 |
| `static/css/smartlimit.css` | 分页居中+margin-top:auto |

---

## 八、验证结果

| 检查项 | 结果 |
|--------|------|
| `go build ./cmd/waf/` | ✅ 通过 |
| `go test ./... -short` | ✅ 全部通过 |
| LogAutoRefresh组件 | ✅ pause/resume/toggle/destroy 正常工作 |
| LogDetailManager组件 | ✅ expand/collapse/collapseAll 正常工作 |
| 详情展开暂停刷新 | ✅ 展开详情后自动刷新暂停 |
| 详情收起恢复刷新 | ✅ 收起所有详情后自动刷新恢复 |
| 系统日志翻页保持 | ✅ 静默刷新不重置页码 |
| 翻页选项统一 | ✅ 四页面均为[20,50,100,200]，默认50 |
| 分页选项格式 | ✅ 全站统一为 `X 条/页` |
| loadLimit移除 | ✅ 访问/管理日志不再显示加载条数选择器 |
| 分页居中布局 | ✅ 页码信息和翻页按钮整体居中 |
| 分页固定底部 | ✅ 数据少时分页在页面底部 |
| 分页在list-container外 | ✅ 所有页面分页已移出list-container |
| card flex:1 | ✅ 含分页的card均占满main剩余空间 |
