/**
 * crud.js — GoWAF 防护规则通用 CRUD 工具模块
 * 提供模态框管理、删除确认、Toggle开关、表格事件委托、Loading指示等公共功能
 */

var WAF = window.WAF || {};

// 模态框管理
WAF.Modal = {
    open: function(id) { document.getElementById(id).classList.add('show'); },
    close: function(id) { document.getElementById(id).classList.remove('show'); },
    clickOutside: function(modalId, closeFn) {
        var el = document.getElementById(modalId);
        if (el) el.addEventListener('click', function(e) { if (e.target === this) closeFn(); });
    }
};

// 按钮防重复提交
WAF.submitWithLock = function(btnSelector, fetchFn) {
    var btn = document.querySelector(btnSelector);
    if (btn && btn.disabled) return Promise.resolve();
    if (btn) btn.disabled = true;
    return fetchFn().finally(function() { if (btn) btn.disabled = false; });
};

// 删除确认
WAF.confirmDelete = function(msg, apiUrl, body, onSuccess) {
    if (!confirm(msg || '确认删除此规则？')) return;
    fetch(apiUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) { showToast('success', '删除成功'); if (onSuccess) onSuccess(); }
        else showToast('error', d.error || '删除失败');
    }).catch(function(e) { showToast('error', '删除失败: ' + e.message); });
};

// 通用确认操作（confirm + fetch POST + toast）
WAF.confirmAction = function(msg, apiUrl, body, successMsg, onSuccess) {
    if (!confirm(msg)) return;
    fetch(apiUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: body ? JSON.stringify(body) : undefined
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) { showToast('success', successMsg || '操作成功'); if (onSuccess) onSuccess(d); }
        else showToast('error', d.error || d.message || '操作失败');
    }).catch(function(e) { showToast('error', '操作失败: ' + e.message); });
};

// 确认重置配置（无 body 的 POST）
WAF.confirmReset = function(msg, apiUrl, onSuccess) {
    if (!confirm(msg)) return;
    fetch(apiUrl, {method: 'POST'})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { showToast('success', '已恢复默认配置'); if (onSuccess) onSuccess(d); }
            else showToast('error', d.error || d.message || '恢复失败');
        }).catch(function(e) { showToast('error', '恢复失败: ' + e.message); });
};

// Toggle 开关（change 事件监听）
WAF.setupToggleSwitch = function(tbodySelector, apiUrl, reloadFn) {
    var tbody = document.querySelector(tbodySelector);
    if (!tbody) return;
    tbody.addEventListener('change', function(e) {
        if (e.target.matches('.toggle-switch input[type=checkbox]')) {
            var id = parseInt(e.target.dataset.id);
            var enabled = e.target.checked;
            fetch(apiUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: id, enabled: enabled})
            }).then(function(r) { return r.json(); }).then(function(d) {
                if (d.success) {
                    showToast('success', enabled ? '已启用' : '已禁用');
                    reloadFn();
                } else {
                    showToast('error', d.error || '操作失败');
                    e.target.checked = !enabled;
                }
            }).catch(function() {
                showToast('error', '操作失败');
                e.target.checked = !enabled;
            });
        }
    });
};

// 表格事件委托（编辑/删除按钮）
WAF.setupTableActions = function(tbodySelector, config) {
    var tbody = document.querySelector(tbodySelector);
    if (!tbody) return;
    tbody.addEventListener('click', function(e) {
        var editBtn = e.target.closest('.btn-edit');
        if (editBtn && config.onEdit) { config.onEdit(parseInt(editBtn.dataset.id)); return; }
        var delBtn = e.target.closest('.delete-btn');
        if (delBtn && config.onDelete) { config.onDelete(parseInt(delBtn.dataset.id)); return; }
        var toggleBtn = e.target.closest('.toggle-btn');
        if (toggleBtn && config.onToggle) { config.onToggle(toggleBtn); }
    });
};

// Loading 指示
WAF.withLoading = function(cardSelector, fetchFn) {
    var card = document.querySelector(cardSelector || '.card');
    if (card) card.classList.add('loading-overlay');
    return fetchFn().finally(function() { if (card) card.classList.remove('loading-overlay'); });
};

// 渲染启用/禁用 Toggle 开关 HTML
WAF.renderToggle = function(enabled, id) {
    return '<label class="toggle-switch"><input type="checkbox" data-id="' + id + '" ' +
        (enabled ? 'checked' : '') + '><span class="slider"></span></label>';
};

// 渲染启用/禁用文本
WAF.renderEnabledText = function(enabled) {
    return enabled ? '<span style="color:#27ae60">启用</span>' : '<span style="color:#95a5a6">禁用</span>';
};

// JSON POST 请求封装
WAF.jsonPost = function(url, data) {
    return fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    }).then(function(r) { return r.json(); });
};

// 搜索框处理
WAF.handleSearch = function(inputId, clearId, filterFn) {
    var input = document.getElementById(inputId);
    var clear = document.getElementById(clearId);
    if (!input) return;
    if (input.value.trim()) { if (clear) clear.classList.add('show'); }
    else { if (clear) clear.classList.remove('show'); }
    if (filterFn) filterFn();
};

WAF.clearSearch = function(inputId, clearId, filterFn) {
    var input = document.getElementById(inputId);
    var clear = document.getElementById(clearId);
    if (input) { input.value = ''; input.focus(); }
    if (clear) clear.classList.remove('show');
    if (filterFn) filterFn();
};

// 分页状态管理
WAF.Pagination = function(config) {
    var currentPage = 1;
    var pageSize = config.pageSize || 10;

    function getPaginationInfo(totalItems) {
        var totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;
        var start = (currentPage - 1) * pageSize;
        var end = Math.min(start + pageSize, totalItems);
        return { currentPage: currentPage, totalPages: totalPages, start: start, end: end, pageSize: pageSize };
    }

    return {
        getInfo: getPaginationInfo,
        prevPage: function() { currentPage--; },
        nextPage: function() { currentPage++; },
        setPageSize: function(size) { pageSize = size; currentPage = 1; },
        reset: function() { currentPage = 1; },
        updateUI: function(info, paginationId) {
            var el = document.getElementById(paginationId);
            if (!el) return;
            document.getElementById('pageInfo').textContent =
                '第' + info.currentPage + ' 页 / 第' + info.totalPages + ' 页（共' + arguments[2] + ' 条）';
            document.getElementById('prevBtn').disabled = info.currentPage <= 1;
            document.getElementById('nextBtn').disabled = info.currentPage >= info.totalPages;
            el.style.display = 'flex';
        }
    };
};

window.WAF = WAF;
