(function() {
            var allLogs = [];
            var filteredLogs = [];
            var currentPage = 1;
            var pageSize = 50;
            var currentViewMode = 'detail';
            var urlRestored = false;
            var groupCurrentPage = 1;
            var groupPageSize = 20;

            function syncURL() {
                var params = new URLSearchParams();
                params.set('view', currentViewMode);
                var action = document.getElementById('filterAction').value;
                var status = document.getElementById('filterStatus').value;
                var ip = document.getElementById('filterIP').value;
                var path = document.getElementById('filterPath').value;
                if (action) params.set('action', action);
                if (status) params.set('status', status);
                if (ip) params.set('ip', ip);
                if (path) params.set('path', path);
                if (currentPage > 1) params.set('page', currentPage);
                if (pageSize !== 50) params.set('size', pageSize);
                if (groupCurrentPage > 1) params.set('gpage', groupCurrentPage);
                history.replaceState(null, '', '?' + params.toString());
            }

            function restoreFromURL() {
                var params = new URLSearchParams(location.search);
                if (params.get('view')) currentViewMode = params.get('view');
                if (params.get('action')) document.getElementById('filterAction').value = params.get('action');
                if (params.get('status')) document.getElementById('filterStatus').value = params.get('status');
                if (params.get('ip')) document.getElementById('filterIP').value = params.get('ip');
                if (params.get('path')) document.getElementById('filterPath').value = params.get('path');
                var urlPage = parseInt(params.get('page')) || 1;
                if (urlPage > 1) currentPage = urlPage;
                var gpage = parseInt(params.get('gpage')) || 1;
                if (gpage > 1) groupCurrentPage = gpage;
                if (params.get('size')) {
                    var s = parseInt(params.get('size'));
                    if (s > 0) { pageSize = s; document.getElementById('pageSize').value = String(s); }
                }
                urlRestored = true;
            }
            var geoCache = {};
            var geoQueue = [];
            
            function escapeHtml(text) {
                if (text == null) return '';
                var div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            function formatTime(timeStr) {
                if (!timeStr) return '-';
                try {
                    var date = new Date(timeStr);
                    if (isNaN(date.getTime())) return timeStr;
                    var year = date.getFullYear();
                    var month = String(date.getMonth() + 1).padStart(2, '0');
                    var day = String(date.getDate()).padStart(2, '0');
                    var hours = String(date.getHours()).padStart(2, '0');
                    var minutes = String(date.getMinutes()).padStart(2, '0');
                    var seconds = String(date.getSeconds()).padStart(2, '0');
                    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
                } catch (e) {
                    return timeStr;
                }
            }
            
            window.loadLogs = function() {
                fetch('/api/adminlog/list?limit=5000')
                    .then(r => r.json())
                    .then(data => {
                        allLogs = Array.isArray(data.data) ? data.data : [];
                        applyFilters();
                        updateStats();
                        if (currentViewMode !== 'detail') {
                            document.getElementById('detailTable').style.display = 'none';
                            document.getElementById('groupViewContainer').style.display = '';
                            document.getElementById('pagination').style.display = 'none';
                            renderGroupView();
                        }
                    })
                    .catch(err => {
                        console.error('加载日志失败:', err);
                        document.getElementById('logBody').innerHTML = '<tr><td colspan="9" class="empty-message">加载失败</td></tr>';
                    });
            }
            
            window.applyFilters = function() {
                var actionFilter = document.getElementById('filterAction').value;
                var statusFilter = document.getElementById('filterStatus').value;
                var ipFilter = document.getElementById('filterIP').value.toLowerCase().trim();
                var pathFilter = document.getElementById('filterPath').value.toLowerCase().trim();
                
                filteredLogs = allLogs.filter(function(log) {
                    if (actionFilter && log.action !== actionFilter) return false;
                    
                    if (statusFilter) {
                        var status = log.status;
                        if (statusFilter === '2xx' && (status < 200 || status >= 300)) return false;
                        else if (statusFilter === '3xx' && (status < 300 || status >= 400)) return false;
                        else if (statusFilter === '4xx' && (status < 400 || status >= 500)) return false;
                        else if (statusFilter === '5xx' && status < 500) return false;
                        else if (!isNaN(statusFilter) && status !== parseInt(statusFilter)) return false;
                    }
                    
                    if (ipFilter && log.client_ip && log.client_ip.toLowerCase().indexOf(ipFilter) === -1) return false;
                    if (pathFilter && log.path && log.path.toLowerCase().indexOf(pathFilter) === -1) return false;
                    
                    return true;
                });
                
                if (!urlRestored) currentPage = 1;
                urlRestored = false;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            }
            
            function updateStats() {
                document.getElementById('totalCount').textContent = allLogs.length;
                
                var loginSuccess = allLogs.filter(function(l) { return l.action === 'login_success'; }).length;
                var loginFail = allLogs.filter(function(l) { return l.action === 'login_fail'; }).length;
                var apiCall = allLogs.filter(function(l) { return l.action === 'api_call'; }).length;
                
                document.getElementById('loginSuccessCount').textContent = loginSuccess;
                document.getElementById('loginFailCount').textContent = loginFail;
                document.getElementById('apiCallCount').textContent = apiCall;
            }
            
            function renderLogs() {
                var tbody = document.getElementById('logBody');
                var pagination = document.getElementById('pagination');
                
                if (!filteredLogs || filteredLogs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="9" class="empty-message">暂无日志记录</td></tr>';
                    pagination.style.display = 'none';
                    return;
                }
                
                var totalPages = Math.ceil(filteredLogs.length / pageSize);
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;
                
                var start = (currentPage - 1) * pageSize;
                var end = Math.min(start + pageSize, filteredLogs.length);
                var pageData = filteredLogs.slice(start, end);
                
                tbody.innerHTML = '';
                pageData.forEach(function(log, index) {
                    var tr = document.createElement('tr');
                    
                    var statusClass = 'success';
                    if (log.status >= 300 && log.status < 400) statusClass = 'redirect';
                    else if (log.status >= 400 && log.status < 500) statusClass = 'client-error';
                    else if (log.status >= 500) statusClass = 'server-error';
                    
                    var actionText = log.action || '-';
                    var actionClass = log.action || '';
                    
                    tr.innerHTML = 
                        '<td style="color:#7f8c8d;">' + escapeHtml(formatTime(log.timestamp)) + '</td>' +
                        '<td style="color:#e74c3c;font-weight:500;">' + escapeHtml(log.client_ip) + '</td>' +
                        '<td class="geo-cell" data-ip="' + escapeHtml(log.client_ip) + '">-</td>' +
                        '<td><span style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:11px;">' + escapeHtml(log.method) + '</span></td>' +
                        '<td style="color:#2c3e50;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(log.path) + '">' + escapeHtml(log.path) + '</td>' +
                        '<td><span class="status-badge ' + statusClass + '">' + log.status + '</span></td>' +
                        '<td><span class="action-badge ' + actionClass + '">' + escapeHtml(actionText) + '</span></td>' +
                        '<td style="color:#95a5a6;">' + (log.latency_ms || 0) + 'ms</td>' +
                        '<td><button class="view-btn" onclick="toggleDetail(' + index + ', event)">查看详情</button></td>';
                    
                    tbody.appendChild(tr);
                });
                
                document.getElementById('pageInfo').textContent = '第' + currentPage + ' 页 / 第' + totalPages + ' 页（共' + filteredLogs.length + ' 条）';
                RenderPageBtns('pageBtns', currentPage, totalPages, 'goPage');
                pagination.style.display = 'flex';
                
                loadGeoForVisibleIPs();
                restoreExpandedDetails();
            }

            function restoreExpandedDetails() {
                var expandedIds = detailManager.getExpandedIds();
                if (expandedIds.size === 0) return;
                expandedIds.forEach(function(detailId) {
                    var indexStr = detailId.replace('admin-detail-', '');
                    var index = parseInt(indexStr);
                    if (isNaN(index)) return;
                    var start = (currentPage - 1) * pageSize;
                    var log = filteredLogs[start + index];
                    if (!log) { detailManager.collapse(detailId); return; }
                    var rows = document.getElementById('logBody').children;
                    if (index >= rows.length) return;
                    var row = rows[index];
                    var btn = row.querySelector('.view-btn');
                    var detailTr = document.createElement('tr');
                    detailTr.className = 'detail-row';
                    detailTr.id = 'detail-' + index;
                    detailTr.setAttribute('data-detail-id', detailId);
                    detailTr.innerHTML = buildAdminLogDetailHtml(log);
                    if (row.nextSibling) {
                        row.parentNode.insertBefore(detailTr, row.nextSibling);
                    } else {
                        row.parentNode.appendChild(detailTr);
                    }
                    if (btn) {
                        btn.textContent = '收起详情';
                        btn.setAttribute('data-detail-id', detailId);
                    }
                });
            }
            
            window.goPage = function(p) {
                var total = Math.ceil(filteredLogs.length / pageSize);
                if (p < 1) p = 1;
                if (p > total) p = total;
                currentPage = p;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            };
            
            window.changePageSize = function() {
                pageSize = parseInt(document.getElementById('pageSize').value);
                currentPage = 1;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            };
            
            window.exportLogs = function() {
                var dataStr = JSON.stringify(filteredLogs, null, 2);
                var blob = new Blob([dataStr], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                var d = new Date(); a.download = 'admin_logs_' + d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0') + '.json';
                a.click();
                URL.revokeObjectURL(url);
            };
            
            function loadGeoForVisibleIPs() {
                var cells = document.querySelectorAll('.geo-cell[data-ip]');
                var ipsToFetch = [];
                cells.forEach(function(cell) {
                    var ip = cell.getAttribute('data-ip');
                    if (!ip) return;
                    if (geoCache[ip]) {
                        applyGeoToCell(cell, geoCache[ip]);
                    } else if (ipsToFetch.indexOf(ip) === -1) {
                        ipsToFetch.push(ip);
                    }
                });
                ipsToFetch.forEach(function(ip) {
                    fetch('/api/geo/lookup?ip=' + encodeURIComponent(ip))
                        .then(function(r) { return r.json(); })
                        .then(function(d) {
                            if (d.success && d.data) {
                                var label = '';
                                if (d.data.flag) label += d.data.flag + ' ';
                                if (d.data.country) label += d.data.country;
                                if (d.data.city && d.data.city !== d.data.country) label += ' ' + d.data.city;
                                if (!label && d.data.country_iso) label = d.data.country_iso;
                                geoCache[ip] = label;
                                document.querySelectorAll('.geo-cell[data-ip]').forEach(function(c) {
                                    if (c.getAttribute('data-ip') === ip) applyGeoToCell(c, label);
                                });
                            } else {
                                geoCache[ip] = '';
                            }
                        })
                        .catch(function() { geoCache[ip] = ''; });
                });
            }
            
            function applyGeoToCell(cell, geoLabel) {
                if (!geoLabel) return;
                cell.textContent = geoLabel;
            }
            
            function getStatusClass(status) {
                if (status >= 300 && status < 400) return 'redirect';
                if (status >= 400 && status < 500) return 'client-error';
                if (status >= 500) return 'server-error';
                return 'success';
            }

            function buildAdminLogDetailHtml(log) {
                var html = '<td colspan="9"><div class="detail-content">';
                html += '<div class="detail-item"><span class="detail-label">时间戳：</span><span class="detail-value">' + formatTime(log.timestamp) + '</span></div>';
                html += '<div class="detail-item"><span class="detail-label">客户端IP：</span><span class="detail-value"><code>' + escapeHtml(log.client_ip || '-') + '</code></span></div>';
                if (log.username) {
                    html += '<div class="detail-item"><span class="detail-label">用户名：</span><span class="detail-value"><code>' + escapeHtml(log.username) + '</code></span></div>';
                }
                if (log.user_agent) {
                    html += '<div class="detail-item"><span class="detail-label">User-Agent：</span><span class="detail-value">' + escapeHtml(log.user_agent) + '</span></div>';
                }
                if (log.referer) {
                    html += '<div class="detail-item"><span class="detail-label">Referer：</span><span class="detail-value">' + escapeHtml(log.referer) + '</span></div>';
                }
                html += '<div class="detail-item"><span class="detail-label">请求Host：</span><span class="detail-value"><code>' + escapeHtml(log.host || '-') + '</code></span></div>';
                html += '<div class="detail-item"><span class="detail-label">请求方法：</span><span class="detail-value"><code>' + escapeHtml(log.method || '-') + '</code></span></div>';
                html += '<div class="detail-item"><span class="detail-label">请求路径：</span><span class="detail-value"><code>' + escapeHtml(log.path || '-') + '</code></span></div>';
                if (log.query) {
                    html += '<div class="detail-item"><span class="detail-label">查询参数：</span><span class="detail-value"><code>' + escapeHtml(log.query) + '</code></span></div>';
                }
                html += '<div class="detail-item"><span class="detail-label">操作类型：</span><span class="detail-value"><span class="action-badge ' + (log.action || '') + '">' + escapeHtml(log.action || '-') + '</span></span></div>';
                html += '<div class="detail-item"><span class="detail-label">状态码：</span><span class="detail-value"><span class="status-badge ' + getStatusClass(log.status) + '">' + log.status + '</span></span></div>';
                html += '<div class="detail-item"><span class="detail-label">响应延迟：</span><span class="detail-value">' + (log.latency_ms || 0) + 'ms</span></div>';
                if (log.error_message) {
                    html += '<div class="detail-item"><span class="detail-label">错误信息：</span><span class="detail-value" style="color:#e74c3c;">' + escapeHtml(log.error_message) + '</span></div>';
                }
                html += '</div></td>';
                return html;
            }
            
            window.toggleDetail = function(index, event) {
                event.stopPropagation();
                var detailId = 'admin-detail-' + index;
                var existingDetail = document.getElementById('detail-' + index);
                var btn = event.target;
                if (existingDetail) {
                    existingDetail.parentNode.removeChild(existingDetail);
                    btn.textContent = '查看详情';
                    detailManager.collapse(detailId);
                    return;
                }
                var start = (currentPage - 1) * pageSize;
                var log = filteredLogs[start + index];
                if (!log) return;
                var detailTr = document.createElement('tr');
                detailTr.className = 'detail-row';
                detailTr.id = 'detail-' + index;
                detailTr.setAttribute('data-detail-id', detailId);
                detailTr.innerHTML = buildAdminLogDetailHtml(log);
                var dataRow = btn.closest('tr');
                if (dataRow.nextSibling) {
                    dataRow.parentNode.insertBefore(detailTr, dataRow.nextSibling);
                } else {
                    dataRow.parentNode.appendChild(detailTr);
                }
                btn.textContent = '收起详情';
                btn.setAttribute('data-detail-id', detailId);
                detailManager.expand(detailId);
            };
            
            window.switchViewMode = function(mode) {
                currentViewMode = mode;
                groupCurrentPage = 1;
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
                });
                var detailTable = document.getElementById('detailTable');
                var groupContainer = document.getElementById('groupViewContainer');
                var pagination = document.getElementById('pagination');
                if (mode === 'detail') {
                    detailTable.style.display = '';
                    groupContainer.style.display = 'none';
                    pagination.style.display = 'flex';
                    document.getElementById('groupPagination').style.display = 'none';
                    renderLogs();
                } else {
                    detailTable.style.display = 'none';
                    groupContainer.style.display = '';
                    pagination.style.display = 'none';
                    renderGroupView();
                }
                syncURL();
            };

            function renderGroupView() {
                var thead = document.getElementById('groupThead');
                var tbody = document.getElementById('groupBody');
                if (!filteredLogs || filteredLogs.length === 0) {
                    thead.innerHTML = '';
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-message">暂无日志数据</td></tr>';
                    return;
                }
                var groups = {};
                if (currentViewMode === 'ip') {
                    thead.innerHTML = '<tr><th>排名</th><th>IP地址</th><th>操作次数</th><th>涉及操作类型</th><th>最近活动</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = log.client_ip || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', actions: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var a = log.action || 'unknown';
                        groups[key].actions[a] = (groups[key].actions[a] || 0) + 1;
                    });
                } else if (currentViewMode === 'action') {
                    thead.innerHTML = '<tr><th>排名</th><th>操作类型</th><th>操作次数</th><th>涉及IP数</th><th>最近活动</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = log.action || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', ips: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var ip = log.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
                    });
                } else if (currentViewMode === 'status') {
                    thead.innerHTML = '<tr><th>排名</th><th>状态码</th><th>请求次数</th><th>涉及IP数</th><th>最近活动</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = String(log.status || 0);
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', ips: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var ip = log.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
                    });
                }
                var arr = Object.values(groups);
                arr.sort(function(a, b) { return b.count - a.count; });
                var maxCount = arr.length > 0 ? arr[0].count : 1;

                var totalGroups = arr.length;
                var groupTotalPages = Math.max(1, Math.ceil(totalGroups / groupPageSize));
                if (groupCurrentPage > groupTotalPages) groupCurrentPage = groupTotalPages;
                var gStart = (groupCurrentPage - 1) * groupPageSize;
                var gEnd = Math.min(gStart + groupPageSize, totalGroups);
                var pageArr = arr.slice(gStart, gEnd);

                tbody.innerHTML = '';
                pageArr.forEach(function(group, idx) {
                    var rank = gStart + idx + 1;
                    var tr = document.createElement('tr');
                    var barWidth = Math.max(8, Math.round((group.count / maxCount) * 100));
                    var lastTime = formatTime(group.lastTime);
                    if (currentViewMode === 'ip') {
                        var actionArr = [];
                        for (var a in group.actions) { actionArr.push(escapeHtml(a) + '(' + group.actions[a] + ')'); }
                        var actionStr = actionArr.length > 3 ? actionArr.slice(0, 3).join(', ') + '...' : actionArr.join(', ');
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td style="font-size:12px;">' + actionStr + '</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'ip\',\'' + escapeHtml(group.key) + '\')">查看明细</a></td>';
                    } else if (currentViewMode === 'action') {
                        var ipCount = Object.keys(group.ips).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><span class="action-badge ' + escapeHtml(group.key) + '">' + escapeHtml(group.key) + '</span></td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + ipCount + '-IP</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'action\',\'' + escapeHtml(group.key) + '\')">查看明细</a></td>';
                    } else if (currentViewMode === 'status') {
                        var ipCount = Object.keys(group.ips).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + ipCount + '-IP</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'status\',' + group.key + ')">查看明细</a></td>';
                    }
                    tbody.appendChild(tr);
                });

                var gPagination = document.getElementById('groupPagination');
                if (totalGroups > groupPageSize) {
                    document.getElementById('groupPageInfo').textContent = '第' + groupCurrentPage + ' 页 / 第' + groupTotalPages + ' 页（共' + totalGroups + ' 组）';
                    document.getElementById('groupPrevBtn').disabled = groupCurrentPage <= 1;
                    document.getElementById('groupNextBtn').disabled = groupCurrentPage >= groupTotalPages;
                    gPagination.style.display = 'flex';
                } else {
                    gPagination.style.display = 'none';
                }
            }

            window.groupPrevPage = function() {
                if (groupCurrentPage > 1) {
                    groupCurrentPage--;
                    renderGroupView();
                    syncURL();
                }
            };

            window.groupNextPage = function() {
                var totalGroups = Object.keys((function() {
                    var g = {};
                    filteredLogs.forEach(function(log) {
                        var key = currentViewMode === 'ip' ? (log.client_ip || 'unknown') : currentViewMode === 'action' ? (log.action || 'unknown') : String(log.status || 0);
                        g[key] = true;
                    });
                    return g;
                })()).length;
                var groupTotalPages = Math.max(1, Math.ceil(totalGroups / groupPageSize));
                if (groupCurrentPage < groupTotalPages) {
                    groupCurrentPage++;
                    renderGroupView();
                    syncURL();
                }
            };

            window.drillDown = function(field, value) {
                currentViewMode = 'detail';
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === 'detail');
                });
                document.getElementById('detailTable').style.display = '';
                document.getElementById('groupViewContainer').style.display = 'none';
                document.getElementById('pagination').style.display = 'flex';
                if (field === 'ip') {
                    document.getElementById('filterIP').value = value;
                } else if (field === 'action') {
                    document.getElementById('filterAction').value = value;
                } else if (field === 'status') {
                    document.getElementById('filterStatus').value = String(value);
                    if (!document.getElementById('filterStatus').querySelector('option[value="' + value + '"]')) {
                        var opt = document.createElement('option');
                        opt.value = String(value);
                        opt.textContent = String(value);
                        document.getElementById('filterStatus').appendChild(opt);
                    }
                }
                applyFilters();
            };

            // 初始加载
            restoreFromURL();
            if (currentViewMode !== 'detail') {
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === currentViewMode);
                });
                document.getElementById('detailTable').style.display = 'none';
                document.getElementById('groupViewContainer').style.display = '';
                document.getElementById('pagination').style.display = 'none';
            }
            loadLogs();
            
            // 每30秒自动刷新
            var autoRefresh = LogAutoRefresh.create({
                interval: 30000,
                autoStart: true,
                onRefresh: function() { loadLogs(); }
            });

            var detailManager = LogDetailManager.create({
                autoRefresh: autoRefresh
            });

            window.toggleAutoRefresh = function() {
                autoRefresh.toggle();
            };

            window.addEventListener('beforeunload', function() {
                autoRefresh.destroy();
                detailManager.destroy();
            });
        })();
