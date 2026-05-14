(function () {
    var allData = [];
    var allGroups = [];
    var backendGroupMap = {};
    var selectedGroupId = "all";


    var currentPage = 1;
    var pageSize = 10;
    var isEdit = false;
    var currentEnabled = true;
    var editingGroupId = null;

    var lbPolicyLabels = {
        round_robin: "轮询",
        weighted_round_robin: "加权轮询",
        least_connections: "最少连接",
        ip_hash: "IP Hash",
        url_hash: "URL Hash",
        random: "加权随机"
    };

    var schemeCategories = [
        { key: "http",      label: "HTTP",      icon: "\u{1f513}" },
        { key: "http,ws",   label: "HTTP+WS",   icon: "\u{1f513}" },
        { key: "https",     label: "HTTPS",     icon: "\u{1f512}" },
        { key: "https,wss", label: "HTTPS+WSS", icon: "\u{1f512}" }
    ];

    var itemCache = {};

    function $(id) { return document.getElementById(id); }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }


    function getGroupProtocolStats(groupId) {
        var tls = 0, nonTLS = 0;
        allData.forEach(function(b) {
            var groups = backendGroupMap[b.id] || [];
            if (groups.some(function(g) { return g.id === groupId; })) {
                var s = (b.scheme || "").toLowerCase();
                if (s.indexOf("https") >= 0 || s.indexOf("wss") >= 0) tls++;
                else nonTLS++;
            }
        });
        return { tls: tls, nonTLS: nonTLS };
    }

    function csrfHeaders() {
        return { "X-CSRF-Token": (window.CSRFToken || "") };
    }

    function loadAll() {
        Promise.all([
            fetch("/api/backend/list", { headers: csrfHeaders() }).then(function(r) { return r.json(); }),
            fetch("/api/backend/group/list", { headers: csrfHeaders() }).then(function(r) { return r.json(); }),
            fetch("/api/backend/group/map", { headers: csrfHeaders() }).then(function(r) { return r.json(); })
        ]).then(function(results) {
            if (results[0].success) {
                allData = results[0].data || [];
                itemCache = {};
                allData.forEach(function(b) { itemCache[b.id] = b; });
                window.itemCache = itemCache;
            }
            if (results[1].success) allGroups = results[1].data || [];
            if (results[2].success) backendGroupMap = results[2].data || {};
            renderGroupPanel();
            renderData();
        });
    }

    function refreshGroups() {
        Promise.all([
            fetch("/api/backend/group/list", { headers: csrfHeaders() }).then(function(r) { return r.json(); }),
            fetch("/api/backend/group/map", { headers: csrfHeaders() }).then(function(r) { return r.json(); })
        ]).then(function(results) {
            if (results[0].success) allGroups = results[0].data || [];
            if (results[1].success) backendGroupMap = results[1].data || {};
            renderGroupPanel();
            renderData();
        });
    }

    function refreshAll() { loadAll(); }

    // ========== Group Panel ==========

    window.selectGroup = function (groupId) {
        selectedGroupId = groupId;
        currentPage = 1;
        renderGroupPanel();
        renderData();
    };

    window.toggleGroupPanel = function () {
        var panel = $("groupPanel");
        var collapsed = $("groupPanelCollapsed");
        if (panel.style.display === "none") {
            panel.style.display = "flex";
            collapsed.style.display = "none";
        } else {
            panel.style.display = "none";
            collapsed.style.display = "flex";
            renderCollapsedPanel();
        }
    };

    function getGroupStats(groupId) {
        var healthy = 0, unhealthy = 0;
        allData.forEach(function(b) {
            var groups = backendGroupMap[b.id] || [];
            if (groups.some(function(g) { return g.id === groupId; })) {
                if (b.healthy) healthy++; else unhealthy++;
            }
        });
        return { healthy: healthy, unhealthy: unhealthy };
    }

    function getAllStats() {
        var h = 0, u = 0;
        allData.forEach(function(b) { if (b.healthy) h++; else u++; });
        return { healthy: h, unhealthy: u, total: allData.length };
    }

    function getUngroupedStats() {
        var h = 0, u = 0, t = 0;
        allData.forEach(function(b) {
            if (!backendGroupMap[b.id] || backendGroupMap[b.id].length === 0) {
                t++; if (b.healthy) h++; else u++;
            }
        });
        return { healthy: h, unhealthy: u, total: t };
    }

    function renderGroupPanel() {
        var html = "";
        var s = getAllStats();
        html += '<div class="group-card ' + (selectedGroupId === "all" ? "active" : "") + '" onclick="selectGroup(\'all\')">';
        html += '<div class="group-card-header"><span class="group-card-name"><span class="group-icon">\u{1f4cb}</span>\u5168\u90e8\u540e\u7aef</span><span class="group-card-count">' + s.total + '</span></div>';
        html += '<div class="group-card-stats"><span class="stat-healthy">\u2705' + s.healthy + '</span><span class="stat-unhealthy">\u274c' + s.unhealthy + '</span></div></div>';

        allGroups.forEach(function(g) {
            var gs = getGroupStats(g.id);
            var ps = getGroupProtocolStats(g.id);
            var ac = selectedGroupId === g.id ? "active" : "";
            var dc = !g.enabled ? "disabled-group" : "";
            var pl = lbPolicyLabels[g.lb_policy] || g.lb_policy;
            html += '<div class="group-card ' + ac + ' ' + dc + '" onclick="selectGroup(\'' + g.id + '\')">';
            html += '<div class="group-card-header">';
            html += '<span class="group-card-name"><span class="group-icon">\u{1f4e6}</span>' + escapeHtml(g.name) + '</span>';
            html += '<span class="group-card-right">';
            html += '<button class="group-action-btn" onclick="event.stopPropagation();openEditGroupModal(\'' + g.id + '\')" title="\u7f16\u8f91">\u270f\ufe0f</button>';
            html += '<button class="group-action-btn action-delete" onclick="event.stopPropagation();deleteGroup(\'' + g.id + '\')" title="\u5220\u9664">\u{1f5d1}\ufe0f</button>';
            html += '<span class="group-card-count">' + (g.member_cnt || 0) + '</span>';
            html += '</span></div>';
            html += '<div class="group-card-stats"><span class="stat-healthy">\u2705' + gs.healthy + '</span><span class="stat-unhealthy">\u274c' + gs.unhealthy + '</span></div>';
            html += '<div class="group-card-policy">\u2696\ufe0f ' + escapeHtml(pl) + '</div>';
            if (gs.healthy + gs.unhealthy > 0) {
                html += '<div class="group-card-protocol"><span class="proto-tls">\u{1f512}' + ps.tls + '</span> <span class="proto-nontls">\u{1f513}' + ps.nonTLS + '</span></div>';
            }
            html += '</div>';
        });

        var us = getUngroupedStats();
        html += '<div class="group-card ' + (selectedGroupId === "ungrouped" ? "active" : "") + '" onclick="selectGroup(\'ungrouped\')">';
        html += '<div class="group-card-header"><span class="group-card-name"><span class="group-icon">\u26a1</span>\u672a\u5206\u7ec4</span><span class="group-card-count">' + us.total + '</span></div>';
        html += '<div class="group-card-stats"><span class="stat-healthy">\u2705' + us.healthy + '</span><span class="stat-unhealthy">\u274c' + us.unhealthy + '</span></div></div>';

        $("groupList").innerHTML = html;
    }

    function renderCollapsedPanel() {
        var html = "";
        html += '<div class="collapsed-group-item ' + (selectedGroupId === "all" ? "active" : "") + '" onclick="selectGroup(\'all\')" title="\u5168\u90e8\u540e\u7aef">\u{1f4cb}</div>';
        allGroups.forEach(function(g) {
            var ac = selectedGroupId === g.id ? "active" : "";
            var dc = !g.enabled ? "disabled-group" : "";
            html += '<div class="collapsed-group-item ' + ac + ' ' + dc + '" onclick="selectGroup(\'' + g.id + '\')" title="' + escapeHtml(g.name) + '">\u{1f4e6}</div>';
        });
        html += '<div class="collapsed-group-item ' + (selectedGroupId === "ungrouped" ? "active" : "") + '" onclick="selectGroup(\'ungrouped\')" title="\u672a\u5206\u7ec4">\u26a1</div>';
        $("collapsedGroupList").innerHTML = html;
    }

    // ========== Group CRUD ==========

    window.openAddGroupModal = function () {
        $("addGroupName").value = "";
        $("addGroupLbPolicy").value = "weighted_round_robin";
        $("addGroupModal").classList.add("show");
    };

    window.closeAddGroupModal = function () {
        $("addGroupModal").classList.remove("show");
    };

    window.deleteGroup = function (id) {
        if (!confirm("确认删除该服务组？")) return;
        fetch("/api/backend/group/delete", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ id: id })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) { if (selectedGroupId === id) selectedGroupId = "all"; refreshGroups(); }
            else alert(data.error || "删除失败");
        });
    };

    window.openEditGroupModal = function (id) {
        var g = allGroups.find(function(x) { return x.id === id; });
        if (!g) return;
        editingGroupId = id;
        $("editGroupName").value = g.name || "";
        $("editGroupLbPolicy").value = g.lb_policy || "round_robin";
        $("editGroupEnabled").checked = g.enabled;
        updateGroupEnabledText();
        $("editGroupModal").classList.add("show");
    };

    function updateGroupEnabledText() {
        $("editGroupEnabledText").textContent = $("editGroupEnabled").checked ? "已启用" : "已禁用";
    }

    $("editGroupEnabled").addEventListener("change", updateGroupEnabledText);

    window.closeEditGroupModal = function () {
        $("editGroupModal").classList.remove("show");
        editingGroupId = null;
    };

    // ========== Search ==========

    function getFilteredBackends() {
        var list = allData;
        if (selectedGroupId === "ungrouped") {
            list = list.filter(function(b) { return !backendGroupMap[b.id] || backendGroupMap[b.id].length === 0; });
        } else if (selectedGroupId !== "all") {
            list = list.filter(function(b) {
                var groups = backendGroupMap[b.id] || [];
                return groups.some(function(g) { return g.id === selectedGroupId; });
            });
        }
        return list;
    }

    // ========== Scheme ==========

    function schemeCheckboxes() {
        return { http: $("schemeHttp"), https: $("schemeHttps"), ws: $("schemeWs"), wss: $("schemeWss") };
    }

    window.onSchemeChange = function () {
        var cb = schemeCheckboxes();
        var h = cb.http.checked, s = cb.https.checked, w = cb.ws.checked, ws = cb.wss.checked;
        var errEl = $("schemeError"), hintEl = $("schemeHint");
        errEl.style.display = "none";
        if (h && s) { showSchemeError("HTTP和HTTPS不能同时选择"); return; }
        if (w && ws) { showSchemeError("WS和WSS不能同时选择"); return; }
        if (h && ws) { showSchemeError("HTTP和WSS不匹配"); return; }
        if (s && w) { showSchemeError("HTTPS和WS不匹配"); return; }
        if (w && !h) { showSchemeError("WS必须搭配HTTP"); return; }
        if (ws && !s) { showSchemeError("WSS必须搭配HTTPS"); return; }
        if (s && ws) hintEl.textContent = "HTTPS + WSS";
        else if (h && w) hintEl.textContent = "HTTP + WS";
        else if (s) hintEl.textContent = "HTTPS";
        else if (h) hintEl.textContent = "HTTP";
        else hintEl.textContent = "HTTP 搭配 WS，HTTPS 搭配 WSS";
    };

    function showSchemeError(msg) { var e = $("schemeError"); e.textContent = msg; e.style.display = "block"; }

    function getSchemeFromCheckboxes() {
        var cb = schemeCheckboxes(), parts = [];
        if (cb.http.checked) parts.push("http");
        if (cb.https.checked) parts.push("https");
        if (cb.ws.checked) parts.push("ws");
        if (cb.wss.checked) parts.push("wss");
        return parts.join(",");
    }

    function setSchemeCheckboxes(scheme) {
        var cb = schemeCheckboxes();
        cb.http.checked = false; cb.https.checked = false; cb.ws.checked = false; cb.wss.checked = false;
        if (!scheme) { cb.http.checked = true; return; }
        scheme.split(",").forEach(function(p) {
            p = p.trim().toLowerCase();
            if (p === "http") cb.http.checked = true;
            else if (p === "https") cb.https.checked = true;
            else if (p === "ws") cb.ws.checked = true;
            else if (p === "wss") cb.wss.checked = true;
        });
    }

    function renderSchemeTags(scheme) {
        if (!scheme) return '<span class="scheme-tag http">http</span>';
        return scheme.split(",").map(function(s) {
            s = s.trim().toLowerCase();
            return '<span class="scheme-tag ' + s + '">' + s + '</span>';
        }).join("");
    }

    // ========== Group Tags ==========

    function renderGroupTags(backendId) {
        var groups = backendGroupMap[backendId] || [];
        if (groups.length === 0) return '<span class="group-tag no-group">未分组</span>';
        return groups.map(function(g) {
            var cls = g.id === selectedGroupId ? "group-tag highlight" : "group-tag";
            return '<span class="' + cls + '">' + escapeHtml(g.name) + '</span>';
        }).join("");
    }

    function isInGroup(backendId, groupId) {
        var groups = backendGroupMap[backendId] || [];
        return groups.some(function(g) { return g.id === groupId; });
    }

    // ========== Backend Modal ==========

    window.openModal = function () {
        isEdit = false;
        currentEnabled = true;
        $("addForm").reset();
        $("addModal").querySelector(".modal-title").textContent = "添加后端服务";
        var btn = $("addForm").querySelector('button[type="submit"]');
        btn.textContent = "添加";
        btn.removeAttribute("data-edit-id");
        setSchemeCheckboxes("http");
        $("backendWeight").value = 1;
        $("healthCheckConfig").style.display = "block";
        $("schemeError").style.display = "none";
        $("schemeHint").textContent = "HTTP 搭配 WS，HTTPS 搭配 WSS";
        $("addModal").classList.add("show");
    };

    window.closeModal = function () {
        $("addModal").classList.remove("show");
    };

    window.editBackend = function (item) {
        isEdit = true;
        currentEnabled = item.enabled;
        $("addModal").querySelector(".modal-title").textContent = "编辑后端服务";
        var btn = $("addForm").querySelector('button[type="submit"]');
        btn.textContent = "保存";
        btn.setAttribute("data-edit-id", item.id);
        $("backendName").value = item.name || "";
        $("backendAddress").value = item.address || "";
        setSchemeCheckboxes(item.scheme || "http");
        $("backendWeight").value = item.weight || 1;
        $("healthCheck").checked = item.health_check !== false;
        $("healthCheckConfig").style.display = item.health_check !== false ? "block" : "none";
        $("checkPath").value = item.check_path || "/health";
        $("checkInterval").value = item.check_interval || 10;
        $("checkTimeout").value = item.check_timeout || 5;
        $("failThreshold").value = item.fail_threshold || 3;
        $("recoverThreshold").value = item.recover_threshold || 2;
        $("schemeError").style.display = "none";
        onSchemeChange();
        $("addModal").classList.add("show");
    };

    // ========== Backend Actions ==========

    window.deleteBackend = function (id) {
        if (!confirm("确认删除该后端服务？")) return;
        fetch("/api/backend/delete", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ id: id })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) refreshAll();
            else alert(data.error || "删除失败");
        });
    };

    window.toggleBackend = function (id) {
        var item = allData.find(function(b) { return b.id === id; });
        if (!item) return;
        fetch("/api/backend/update", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({
                id: item.id,
                name: item.name || "",
                address: item.address,
                scheme: item.scheme || "http",
                weight: item.weight || 1,
                enabled: !item.enabled,
                health_check: item.health_check,
                check_path: item.check_path || "/health",
                check_interval: item.check_interval || 10,
                check_timeout: item.check_timeout || 5,
                fail_threshold: item.fail_threshold || 3,
                recover_threshold: item.recover_threshold || 2
            })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) refreshAll();
            else alert(data.error || "操作失败");
        });
    };

    window.addToGroup = function (backendId, groupId) {
        var item = allData.find(function(b) { return b.id === backendId; });
        if (!item) return;
        fetch("/api/backend/group/member/add", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ group_id: groupId, backend_id: backendId, weight: item.weight || 1 })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) refreshGroups();
            else alert(data.error || "添加失败");
        });
    };

    window.removeFromGroup = function (backendId, groupId) {
        fetch("/api/backend/group/member/delete", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ group_id: groupId, backend_id: backendId })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) refreshGroups();
            else alert(data.error || "移除失败");
        });
    };

    window.toggleJoinMenu = function (btn, backendId) {
        var openMenu = document.querySelector(".join-group-menu.open");
        if (openMenu && openMenu !== btn.nextElementSibling) {
            openMenu.classList.remove("open");
            openMenu.style.display = "none";
        }
        var menu = btn.nextElementSibling;
        var isOpen = menu.classList.contains("open");
        if (isOpen) {
            menu.classList.remove("open");
            menu.style.display = "none";
        } else {
            menu.classList.add("open");
            menu.style.display = "block";
        }
    };

    window.closeJoinMenu = function () {
        var menu = document.querySelector(".join-group-menu.open");
        if (menu) {
            menu.classList.remove("open");
            menu.style.display = "none";
        }
    };

    document.addEventListener("click", function(e) {
        if (!e.target.closest(".join-group-wrap")) closeJoinMenu();
    });

    // ========== Render Data ==========

    function renderRow(item) {
        var name = item.name || "";
        var html = "<tr>";
        html += "<td>" + (name ? "<strong>" + escapeHtml(name) + "</strong>" : "-") + "</td>";
        html += '<td><code>' + escapeHtml(item.address) + '</code></td>';
        html += "<td>" + renderSchemeTags(item.scheme) + "</td>";
        html += "<td>" + renderGroupTags(item.id) + "</td>";
        html += "<td>" + (item.weight || 1) + "</td>";
        html += '<td><span class="status-badge ' + (item.healthy ? "badge-success" : "badge-danger") + '">' + (item.healthy ? "\u5065\u5eb7" : "\u5f02\u5e38") + "</span></td>";
        html += '<td><span class="status-badge ' + (item.enabled ? "badge-success" : "badge-danger") + '">' + (item.enabled ? "\u5df2\u542f\u7528" : "\u5df2\u7981\u7528") + "</span></td>";
        html += '<td class="action-cell">';
        html += '<button class="btn btn-sm" onclick="editBackend(itemCache[\'' + item.id + '\'])">\u7f16\u8f91</button> ';
        html += '<button class="btn btn-sm ' + (item.enabled ? "btn-warning" : "btn-success") + '" onclick="toggleBackend(\'' + item.id + '\')">' + (item.enabled ? "\u7981\u7528" : "\u542f\u7528") + "</button> ";
        html += '<button class="btn btn-sm btn-danger" onclick="deleteBackend(\'' + item.id + '\')">\u5220\u9664</button>';
        if (selectedGroupId !== "all" && selectedGroupId !== "ungrouped") {
            if (isInGroup(item.id, selectedGroupId)) {
                html += ' <button class="inline-group-action action-leave" onclick="removeFromGroup(\'' + item.id + '\',\'' + selectedGroupId + '\')">\u79fb\u51fa\u7ec4</button>';
            } else {
                html += ' <button class="inline-group-action action-join" onclick="addToGroup(\'' + item.id + '\',\'' + selectedGroupId + '\')">\u52a0\u5165\u7ec4</button>';
            }
        }
        if (selectedGroupId === "ungrouped" && allGroups.length > 0) {
            html += ' <span class="join-group-wrap">';
            html += '<button class="btn btn-sm btn-primary join-group-btn" onclick="event.stopPropagation();toggleJoinMenu(this,\'' + item.id + '\')">\u52a0\u5165\u7ec4</button>';
            html += '<div class="join-group-menu" style="display:none;">';
            allGroups.forEach(function(g) {
                html += '<div class="join-group-item" onclick="addToGroup(\'' + item.id + '\',\'' + g.id + '\');closeJoinMenu()">' + escapeHtml(g.name) + '</div>';
            });
            html += '</div></span>';
        }
        html += "</td></tr>";
        return html;
    }

    function renderData() {
        var filtered = getFilteredBackends();
        var isGroupView = selectedGroupId !== "all" && selectedGroupId !== "ungrouped";
        var html = "";

        if (filtered.length === 0) {
            html = '<tr><td colspan="8" style="text-align:center;color:#999;padding:40px;">\u6682\u65e0\u540e\u7aef\u670d\u52a1</td></tr>';
        } else if (isGroupView) {
            var buckets = {};
            schemeCategories.forEach(function(c) { buckets[c.key] = []; });
            filtered.forEach(function(item) {
                var scheme = (item.scheme || "http").toLowerCase();
                if (buckets[scheme]) buckets[scheme].push(item);
                else buckets["http"].push(item);
            });
            schemeCategories.forEach(function(cat) {
                var items = buckets[cat.key];
                if (items.length === 0) return;
                html += '<tr class="subset-divider"><td colspan="8">' + cat.icon + ' ' + cat.label + ' <span class="subset-count">(' + items.length + ')</span></td></tr>';
                items.forEach(function(item) { html += renderRow(item); });
            });
        } else {
            var totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
            if (currentPage > totalPages) currentPage = totalPages;
            var start = (currentPage - 1) * pageSize;
            var pageData = filtered.slice(start, start + pageSize);
            pageData.forEach(function(item) { html += renderRow(item); });
        }

        $("tableBody").innerHTML = html;

        var paginationEl = $("pagination");
        if (isGroupView) {
            paginationEl.style.display = "none";
        } else {
            paginationEl.style.display = "";
            var totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
            $("pageInfo").textContent = "\u7b2c" + currentPage + "\u9875 / \u7b2c" + totalPages + "\u9875\uff08\u5171" + filtered.length + "\u6761\uff09";
            $("prevBtn").disabled = currentPage <= 1;
            $("nextBtn").disabled = currentPage >= totalPages;
        }
    }

    // ========== Pagination ==========

    window.prevPage = function () {
        if (currentPage > 1) { currentPage--; renderData(); }
    };

    window.nextPage = function () {
        var filtered = getFilteredBackends();
        var totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
        if (currentPage < totalPages) { currentPage++; renderData(); }
    };

    window.changePageSize = function () {
        pageSize = parseInt($("pageSize").value) || 10;
        currentPage = 1;
        renderData();
    };

    // ========== Form Submit ==========

    $("addForm").addEventListener("submit", function(e) {
        e.preventDefault();
        var name = $("backendName").value.trim();
        var address = $("backendAddress").value.trim();
        if (!address) { alert("\u8bf7\u8f93\u5165\u540e\u7aef\u5730\u5740"); return; }
        var scheme = getSchemeFromCheckboxes();
        if (!scheme) { alert("请选择协议"); return; }

        var btn = e.target.querySelector('button[type="submit"]');
        var editId = btn.getAttribute("data-edit-id");
        isEdit = !!editId;

        var payload = {
            name: name,
            address: address,
            scheme: scheme,
            weight: parseInt($("backendWeight").value) || 1,
            enabled: isEdit ? currentEnabled : true,
            health_check: $("healthCheck").checked,
            check_path: $("checkPath").value || "/health",
            check_interval: parseInt($("checkInterval").value) || 10,
            check_timeout: parseInt($("checkTimeout").value) || 5,
            fail_threshold: parseInt($("failThreshold").value) || 3,
            recover_threshold: parseInt($("recoverThreshold").value) || 2
        };

        var url = "/api/backend/add";
        if (isEdit) {
            url = "/api/backend/update";
            payload.id = editId;
        }

        btn.disabled = true;
        fetch(url, {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify(payload)
        }).then(function(r) { return r.json(); }).then(function(data) {
            btn.disabled = false;
            if (data.success) {
                if (!isEdit && selectedGroupId !== "all" && selectedGroupId !== "ungrouped") {
                    var newId = data.data && data.data.id;
                    if (newId) {
                        fetch("/api/backend/group/member/add", {
                            method: "POST",
                            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
                            body: JSON.stringify({ group_id: selectedGroupId, backend_id: newId, weight: payload.weight })
                        }).then(function() { closeModal(); refreshAll(); });
                        return;
                    }
                }
                closeModal();
                refreshAll();
            } else {
                var msg = data.error || "操作失败";
                if (msg.indexOf("UNIQUE constraint") >= 0 || msg.indexOf("已存在") >= 0) {
                    alert("该后端地址+协议组合已存在");
                } else {
                    alert(msg);
                }
            }
        }).catch(function() { btn.disabled = false; });
    });

    $("healthCheck").addEventListener("change", function() {
        $("healthCheckConfig").style.display = this.checked ? "block" : "none";
    });

    // ========== Group Edit Form ==========

    $("editGroupForm").addEventListener("submit", function(e) {
        e.preventDefault();
        if (!editingGroupId) return;
        var name = $("editGroupName").value.trim();
        if (!name) { alert("\u8bf7\u8f93\u5165\u7ec4\u540d\u79f0"); return; }
        fetch("/api/backend/group/update", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ id: editingGroupId, name: name, lb_policy: $("editGroupLbPolicy").value, enabled: $("editGroupEnabled").checked })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) { closeEditGroupModal(); refreshGroups(); }
            else alert(data.error || "\u66f4\u65b0\u5931\u8d25");
        });
    });

    $("addGroupForm").addEventListener("submit", function(e) {
        e.preventDefault();
        var name = $("addGroupName").value.trim();
        if (!name) { alert("\u8bf7\u8f93\u5165\u7ec4\u540d\u79f0"); return; }
        fetch("/api/backend/group/add", {
            method: "POST",
            headers: Object.assign({ "Content-Type": "application/json" }, csrfHeaders()),
            body: JSON.stringify({ name: name, lb_policy: $("addGroupLbPolicy").value })
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) { closeAddGroupModal(); refreshGroups(); }
            else alert(data.error || "\u6dfb\u52a0\u5931\u8d25");
        });
    });

    // ========== Init ==========
    loadAll();
})();
