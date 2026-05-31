(function() {
            var editingId = null;
            var allData = [];
            var currentPage = 1;
            var pageSize = 10;

            function escapeHtml(text) {
                if (text == null) return '';
                var div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            function $(id) { return document.getElementById(id); }

            function protocolCheckboxes() {
                return { http: $("protocolHttp"), https: $("protocolHttps"), ws: $("protocolWs"), wss: $("protocolWss") };
            }

            window.onProtocolChange = function () {
                var cb = protocolCheckboxes();
                var h = cb.http.checked, s = cb.https.checked, w = cb.ws.checked, ws = cb.wss.checked;
                var errEl = $("protocolError"), hintEl = $("protocolHint");
                errEl.style.display = "none";
                if (!h && !s && !w && !ws) { showProtocolError("请至少选择一个协议"); return; }
                if (h && s) { showProtocolError("HTTP和HTTPS不能同时选择"); return; }
                if (w && ws) { showProtocolError("WS和WSS不能同时选择"); return; }
                if (h && ws) { showProtocolError("HTTP和WSS不匹配"); return; }
                if (s && w) { showProtocolError("HTTPS和WS不匹配"); return; }
                if (w && !h) { showProtocolError("WS必须搭配HTTP"); return; }
                if (ws && !s) { showProtocolError("WSS必须搭配HTTPS"); return; }
                if (s && ws) hintEl.textContent = "HTTPS + WSS";
                else if (h && w) hintEl.textContent = "HTTP + WS";
                else if (s) hintEl.textContent = "HTTPS";
                else if (h) hintEl.textContent = "HTTP";
                else hintEl.textContent = "HTTP 搭配 WS，HTTPS 搭配 WSS";
            };

            function showProtocolError(msg) { var e = $("protocolError"); e.textContent = msg; e.style.display = "block"; }

            function getProtocolFromCheckboxes() {
                var cb = protocolCheckboxes(), parts = [];
                if (cb.http.checked) parts.push("http");
                if (cb.https.checked) parts.push("https");
                if (cb.ws.checked) parts.push("ws");
                if (cb.wss.checked) parts.push("wss");
                return parts.join(",");
            }

            function setProtocolCheckboxes(protocol) {
                var cb = protocolCheckboxes();
                cb.http.checked = false; cb.https.checked = false; cb.ws.checked = false; cb.wss.checked = false;
                if (!protocol) { cb.http.checked = true; return; }
                protocol.split(",").forEach(function(p) {
                    p = p.trim().toLowerCase();
                    if (p === "http") cb.http.checked = true;
                    else if (p === "https") cb.https.checked = true;
                    else if (p === "ws") cb.ws.checked = true;
                    else if (p === "wss") cb.wss.checked = true;
                });
                onProtocolChange();
            }

            function renderProtocolTags(protocol) {
                if (!protocol) return '<span class="protocol-tag http">http</span>';
                return protocol.split(",").map(function(s) {
                    s = s.trim().toLowerCase();
                    return '<span class="protocol-tag ' + s + '">' + s + '</span>';
                }).join("");
            }

            window.validateListenAddr = function() {
                var addr = document.getElementById('listenAddr').value.trim();
                var errorEl = document.getElementById('addrError');
                var saveBtn = document.getElementById('saveBtn');
                
                if (!addr) {
                    errorEl.style.display = 'none';
                    saveBtn.disabled = false;
                    return true;
                }

                var portRegex = /^(:[0-9]{1,5}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5})$/;
                if (!portRegex.test(addr)) {
                    errorEl.style.display = 'block';
                    saveBtn.disabled = true;
                    return false;
                }

                var portMatch = addr.match(/:([0-9]+)$/);
                if (portMatch) {
                    var port = parseInt(portMatch[1]);
                    if (port < 1 || port > 65535) {
                        errorEl.textContent = '端口号必须在1-65535之间';
                        errorEl.style.display = 'block';
                        saveBtn.disabled = true;
                        return false;
                    }
                }

                errorEl.style.display = 'none';
                saveBtn.disabled = false;
                return true;
            };

            function loadList() {
                fetch('/api/proxy/list').then(r => r.json()).then(data => {
                    allData = data.data || data || [];
                    renderData();
                }).catch(err => {
                    console.error('加载代理列表失败:', err);
                    document.getElementById('proxyList').innerHTML = '<tr><td colspan="7" style="text-align:center;color:#95a5a6;padding:20px;">加载失败</td></tr>';
                });
            }

            function renderData() {
                var tbody = document.getElementById('proxyList');
                var pagination = document.getElementById('pagination');
                
                if (!allData || allData.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#95a5a6;padding:20px;">暂无配置</td></tr>';
                    pagination.style.display = 'none';
                    return;
                }
                
                var totalPages = Math.ceil(allData.length / pageSize);
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;
                
                var start = (currentPage - 1) * pageSize;
                var end = Math.min(start + pageSize, allData.length);
                var pageData = allData.slice(start, end);
                
                tbody.innerHTML = '';
                pageData.forEach(function(item) {
                    var tr = document.createElement('tr');
                    var escapedAddr = escapeHtml(item.listen_addr);
                    var toggleText = item.enabled ? '禁用' : '启用';
                    tr.innerHTML = '<td><code>' + escapedAddr + '</code></td>' +
                        '<td>' + renderProtocolTags(item.protocol) + '</td>' +
                        '<td><span class="status-badge ' + (item.enabled ? 'status-enabled' : 'status-disabled') + '">' + (item.enabled ? '已启用' : '已禁用') + '</span></td>' +
                        '<td>' +
                            '<button class="edit-btn" data-id="' + escapeHtml(item.id) + '" data-addr="' + escapeHtml(item.listen_addr) + '" data-protocol="' + escapeHtml(item.protocol) + '" data-enabled="' + item.enabled + '">编辑</button> ' +
                            '<button class="toggle-btn" data-id="' + escapeHtml(item.id) + '" data-enabled="' + !item.enabled + '">' + toggleText + '</button> ' +
                            '<button class="delete-btn" data-id="' + escapeHtml(item.id) + '">删除</button>' +
                        '</td>';
                    tbody.appendChild(tr);
                });

                document.getElementById('pageInfo').textContent = '第' + currentPage + ' 页 / 第' + totalPages + ' 页（共' + allData.length + ' 条）';
                RenderPageBtns('pageBtns', currentPage, totalPages, 'goPage');
                pagination.style.display = 'flex';
            }

            // 事件委托 - 只绑定一次
            document.getElementById('proxyList').addEventListener('click', function(e) {
                var target = e.target;
                var id = target.getAttribute('data-id');
                if (!id) return;
                
                if (target.classList.contains('delete-btn')) {
                    if (confirm('确定删除？')) {
                        fetch('/api/proxy/delete', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
                            body: JSON.stringify({id: id})
                        }).then(r => r.json()).then(res => {
                            if (res.success) loadList();
                            else alert('删除失败: ' + (res.error || '未知错误'));
                        }).catch(err => alert('删除失败: ' + err.message));
                    }
                } else if (target.classList.contains('edit-btn')) {
                    var addr = target.getAttribute('data-addr');
                    var protocol = target.getAttribute('data-protocol');
                    var enabled = target.getAttribute('data-enabled') === 'true';
                    editingId = id;
                    document.getElementById('modalTitle').textContent = '编辑代理';
                    document.getElementById('listenAddr').value = addr;
                    setProtocolCheckboxes(protocol);
                    document.getElementById('enabled').checked = enabled;
                    document.getElementById('addrError').style.display = 'none';
                    document.getElementById('saveBtn').disabled = false;
                    document.getElementById('addModal').classList.add('show');
                } else if (target.classList.contains('toggle-btn')) {
                    var enabled = target.getAttribute('data-enabled') === 'true';
                    var item = null;
                    for (var i = 0; i < allData.length; i++) {
                        if (allData[i].id === id) {
                            item = allData[i];
                            break;
                        }
                    }
                    if (item) {
                        var data = {
                            id: id,
                            listen_addr: item.listen_addr,
                            protocol: item.protocol,
                            enabled: enabled
                        };
                        fetch('/api/proxy/update', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
                            body: JSON.stringify(data)
                        }).then(r => r.json()).then(res => {
                            if (res.success) loadList();
                            else alert('操作失败: ' + (res.error || '未知错误'));
                        }).catch(err => alert('操作失败: ' + err.message));
                    }
                }
            });

            window.goPage = function(p) { var total = Math.ceil(allData.length / pageSize); if (p < 1) p = 1; if (p > total) p = total; currentPage = p; renderData(); };
            window.changePageSize = function() { pageSize = parseInt(document.getElementById('pageSize').value); currentPage = 1; renderData(); };

            window.showAddModal = function() {
                editingId = null;
                document.getElementById('modalTitle').textContent = '添加代理';
                document.getElementById('listenAddr').value = '';
                setProtocolCheckboxes('http');
                document.getElementById('enabled').checked = true;
                document.getElementById('addrError').style.display = 'none';
                document.getElementById('saveBtn').disabled = false;
                document.getElementById('addModal').classList.add('show');
            };

            window.closeModal = function() {
                document.getElementById('addModal').classList.remove('show');
            };

            window.saveProxy = function() {
                if (!validateListenAddr()) {
                    alert('请检查监听地址格式');
                    return;
                }

                var protocolError = document.getElementById('protocolError');
                if (protocolError.style.display !== 'none') {
                    alert('请检查协议组合是否正确');
                    return;
                }

                var data = {
                    listen_addr: document.getElementById('listenAddr').value.trim(),
                    protocol: getProtocolFromCheckboxes(),
                    enabled: document.getElementById('enabled').checked
                };

                if (!data.listen_addr) {
                    alert('请输入监听地址');
                    return;
                }

                var btn = document.getElementById('saveBtn'); btn.disabled = true;
                var url = '/api/proxy/add';
                if (editingId) {
                    data.id = editingId;
                    url = '/api/proxy/update';
                }

                fetch(url, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
                    body: JSON.stringify(data)
                }).then(r => r.json()).then(res => {
                    if (res.success) {
                        closeModal();
                        loadList();
                    } else {
                        alert('保存失败: ' + (res.error || '未知错误'));
                    }
                }).catch(err => {
                    console.error('保存失败:', err);
                    alert('保存失败: ' + err.message);
                }).finally(function() { btn.disabled = false; });
            };

            loadList();
        })();
