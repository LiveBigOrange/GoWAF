(function() {
    var currentDetectorType = null;
    var panelFilters = {};
    var configs = {};
    var rules = {};
    var rulesLoaded = {};

    var DETECTORS = [
        {type:'sql_injection',       icon:'💉', label:'SQL注入',        prefix:'sql',   group:'main'},
        {type:'xss',                 icon:'🎯', label:'XSS攻击',       prefix:'xss',   group:'main'},
        {type:'command_injection',   icon:'⚙️', label:'命令注入',      prefix:'cmd',   group:'main'},
        {type:'ssrf',                icon:'🌐', label:'SSRF',          prefix:'ssrf',  group:'main'},
        {type:'path_traversal',      icon:'📂', label:'路径遍历',      prefix:'patht', group:'main'},
        {type:'header_injection',    icon:'📋', label:'头部注入',      prefix:'hdr',   group:'adv'},
        {type:'sensitive_data',      icon:'🔒', label:'敏感数据泄露',  prefix:'sens',  group:'adv'},
        {type:'file_upload',         icon:'📎', label:'恶意文件上传',  prefix:'fup',   group:'adv'},
        {type:'error_leak',          icon:'⚠️', label:'错误信息泄露',  prefix:'errl',  group:'adv'},
        {type:'request_smuggling',    icon:'🔄', label:'请求走私',      prefix:'rsmug', group:'adv'},
        {type:'xxe',                 icon:'📄', label:'XXE注入',       prefix:'xxe',   group:'adv'},
        {type:'nosql',               icon:'🗃️', label:'NoSQL注入',     prefix:'nosql', group:'adv'},
        {type:'ssti',                icon:'🧩', label:'SSTI注入',      prefix:'ssti',  group:'adv'}
    ];

    var typeToPrefix = {};
    var typeToLabel = {};
    var typeToIcon = {};
    DETECTORS.forEach(function(d) {
        typeToPrefix[d.type] = d.prefix;
        typeToLabel[d.type] = d.label;
        typeToIcon[d.type] = d.icon;
        panelFilters[d.type] = 'all';
    });

    function escapeHtml(text) {
        if (text == null) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function buildLayout() {
        var layout = document.getElementById('detectorLayout');
        if (!layout) return;
        var listHtml = '<div class="detector-list">'
            + '<div class="detector-list-title">📋 检测器列表</div>'
            + '<div class="detector-cards" id="detectorCards">';
        DETECTORS.forEach(function(d) {
            listHtml += '<div class="detector-card" data-type="' + d.type + '" id="card-' + d.type + '">'
                + '<div class="detector-card-header">'
                + '<span class="detector-card-icon">' + d.icon + '</span>'
                + '<span class="detector-card-name">' + d.label + '</span>'
                + '<span class="detector-card-badge" id="' + d.prefix + '-badge">-</span>'
                + '</div>'
                + '<div class="detector-card-meta" id="' + d.prefix + '-meta">-</div>'
                + '</div>';
        });
        listHtml += '</div></div>';
        listHtml += '<div class="detector-detail" id="detectorDetail">'
            + '<div class="detector-detail-empty"><span class="empty-icon">🛡️</span><span class="empty-text">点击左侧检测器卡片查看配置</span></div>'
            + '</div>';
        layout.innerHTML = listHtml;

        layout.querySelectorAll('.detector-card').forEach(function(card) {
            card.addEventListener('click', function() {
                var type = card.dataset.type;
                selectDetector(type);
            });
        });
    }

    function selectDetector(type) {
        currentDetectorType = type;
        document.querySelectorAll('.detector-card').forEach(function(c) { c.classList.remove('active'); });
        var card = document.getElementById('card-' + type);
        if (card) card.classList.add('active');
        renderDetail(type);
        loadRules(type);
    }

    function renderDetail(type) {
        var d = null;
        for (var i = 0; i < DETECTORS.length; i++) { if (DETECTORS[i].type === type) { d = DETECTORS[i]; break; } }
        if (!d) return;
        var cfg = configs[type] || {};
        var prefix = d.prefix;
        var detailEl = document.getElementById('detectorDetail');
        var enabledChecked = cfg.enabled ? ' checked' : '';
        var isObserved = cfg.observation_mode ? true : false;
        var wlIps = cfg.whitelist_ips || '';
        var wlPaths = cfg.whitelist_paths || '';
        var sensLevel = cfg.sensitivity_level || 'medium';
        var ruleList = rules[type] || [];
        var builtinCount = 0, customCount = 0;
        if (Array.isArray(ruleList)) {
            ruleList.forEach(function(r) { if (r.rule_type === 'builtin') builtinCount++; else customCount++; });
        }

        var html = '<div class="detector-detail-title"><span class="icon">' + d.icon + '</span> ' + d.label + '检测</div>'
            + '<div class="config-section"><h3>基本配置</h3>'
            + '<div class="config-row"><div class="config-label">启用状态</div>'
            + '<label class="toggle-switch"><input type="checkbox" id="' + prefix + '-enabled"' + enabledChecked + ' onchange="toggleDetector(\'' + type + '\', this.checked)"><span class="slider"></span></label>'
            + '</div>'
            + '<div class="config-row"><div class="config-label">检测模式</div>'
            + '<div class="mode-btns">'
            + '<button class="mode-btn' + (!isObserved ? ' active' : '') + '" data-mode="intercept" onclick="setObservationMode(\'' + type + '\', false)">拦截</button>'
            + '<button class="mode-btn mode-observe' + (isObserved ? ' active' : '') + '" data-mode="observe" onclick="setObservationMode(\'' + type + '\', true)">观察</button>'
            + '</div>'
            + '<span class="mode-hint" id="' + prefix + '-mode-hint">' + (isObserved ? '仅记录日志，不拦截请求' : '检测到攻击时直接拦截') + '</span>'
            + '</div>'
            + '<div class="config-row"><div class="config-label">敏感度级别</div>'
            + '<div class="sensitivity-btns">'
            + '<button class="sensitivity-btn' + (sensLevel === 'low' ? ' active' : '') + '" data-level="low" onclick="setSensitivity(\'' + type + '\', \'low\')">低</button>'
            + '<button class="sensitivity-btn' + (sensLevel === 'medium' ? ' active' : '') + '" data-level="medium" onclick="setSensitivity(\'' + type + '\', \'medium\')">中</button>'
            + '<button class="sensitivity-btn' + (sensLevel === 'high' ? ' active' : '') + '" data-level="high" onclick="setSensitivity(\'' + type + '\', \'high\')">高</button>'
            + '</div></div></div>'
            + '<div class="config-section"><h3>白名单配置</h3>'
            + '<div class="config-row"><div class="config-label">IP白名单</div>'
            + '<input type="text" class="config-input" id="' + prefix + '-whitelist-ips" value="' + escapeHtml(wlIps) + '" placeholder="多个IP用逗号分隔"></div>'
            + '<div class="config-row"><div class="config-label">路径白名单</div>'
            + '<input type="text" class="config-input" id="' + prefix + '-whitelist-paths" value="' + escapeHtml(wlPaths) + '" placeholder="多个路径用逗号分隔"></div>'
            + '<div class="config-row"><div class="config-label"></div>'
            + '<button class="btn btn-primary" onclick="saveConfig(\'' + type + '\')">保存配置</button></div></div>'
            + '<div class="config-section"><h3>检测规则 <span id="' + prefix + '-rule-count">(内置:' + builtinCount + ' 自定义:' + customCount + ')</span></h3>'
            + '<div class="rule-filter">'
            + '<button class="filter-btn active" data-filter="all" onclick="filterRules(\'' + type + '\', \'all\')">全部</button>'
            + '<button class="filter-btn" data-filter="builtin" onclick="filterRules(\'' + type + '\', \'builtin\')">内置规则</button>'
            + '<button class="filter-btn" data-filter="custom" onclick="filterRules(\'' + type + '\', \'custom\')">自定义规则</button>'
            + '</div>'
            + '<div style="margin-bottom:12px;display:flex;gap:10px;align-items:center;">'
            + '<input type="text" id="' + prefix + '-search" placeholder="搜索规则..." style="padding:8px 12px;border:1px solid #dce1e8;border-radius:6px;flex:1;font-size:13px;box-sizing:border-box;" oninput="searchRules(\'' + type + '\', this.value)">'
            + '<button class="btn btn-outline btn-small" onclick="showAddRule(\'' + type + '\')">+ 添加自定义规则</button>'
            + '</div>'
            + '<div class="rule-list" id="' + prefix + '-rules"><div class="empty-message">加载中...</div></div>'
            + '</div>';
        detailEl.innerHTML = html;
    }

    function loadConfigs() {
        fetch('/api/detector/list')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                configs = {};
                var list = data.data || data || [];
                list.forEach(function(cfg) { configs[cfg.detector_type] = cfg; });
                updateCards();
                if (currentDetectorType && !document.getElementById('detectorDetail').querySelector('.detector-detail-empty')) {
                    var prefix = typeToPrefix[currentDetectorType] || currentDetectorType;
                    var enabledEl = document.getElementById(prefix + '-enabled');
                    var cfg = configs[currentDetectorType];
                    if (enabledEl && cfg) enabledEl.checked = cfg.enabled;
                    var badgeEl = document.getElementById(prefix + '-badge');
                    if (badgeEl && cfg) {
                        if (cfg.observation_mode && cfg.enabled) {
                            badgeEl.textContent = '观察';
                            badgeEl.className = 'detector-card-badge observed';
                        } else if (cfg.enabled) {
                            badgeEl.textContent = '已启用';
                            badgeEl.className = 'detector-card-badge enabled';
                        } else {
                            badgeEl.textContent = '已禁用';
                            badgeEl.className = 'detector-card-badge disabled';
                        }
                    }
                    var modeHintEl = document.getElementById(prefix + '-mode-hint');
                    if (modeHintEl && cfg) {
                        modeHintEl.textContent = cfg.observation_mode ? '仅记录日志，不拦截请求' : '检测到攻击时直接拦截';
                    }
                    var modeBtns = document.querySelectorAll('#detectorDetail .mode-btn');
                    modeBtns.forEach(function(btn) {
                        if (btn.dataset.mode === 'observe') {
                            btn.classList.toggle('active', cfg && cfg.observation_mode);
                        } else {
                            btn.classList.toggle('active', cfg && !cfg.observation_mode);
                        }
                    });
                }
            })
            .catch(function(err) { console.error('加载配置失败:', err); });
    }

    function updateCards() {
        DETECTORS.forEach(function(d) {
            var cfg = configs[d.type];
            var badgeEl = document.getElementById(d.prefix + '-badge');
            var metaEl = document.getElementById(d.prefix + '-meta');
            if (badgeEl) {
                if (cfg) {
                    if (cfg.observation_mode && cfg.enabled) {
                        badgeEl.textContent = '观察';
                        badgeEl.className = 'detector-card-badge observed';
                    } else if (cfg.enabled) {
                        badgeEl.textContent = '已启用';
                        badgeEl.className = 'detector-card-badge enabled';
                    } else {
                        badgeEl.textContent = '已禁用';
                        badgeEl.className = 'detector-card-badge disabled';
                    }
                } else {
                    badgeEl.textContent = '未配置';
                    badgeEl.className = 'detector-card-badge disabled';
                }
            }
            if (metaEl) {
                var ruleList = rules[d.type];
                if (Array.isArray(ruleList)) {
                    metaEl.textContent = '规则 ' + ruleList.length + ' 条';
                } else {
                    metaEl.textContent = cfg ? '敏感度: ' + (cfg.sensitivity_level || '中') : '-';
                }
            }
        });
    }

    function loadRules(type) {
        if (!currentDetectorType || currentDetectorType !== type) return;
        if (rulesLoaded[type]) { renderRules(type); return; }
        fetch('/api/detector/rules?type=' + type)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var list = data.data || data || [];
                var arr = Array.isArray(list) ? list : [];
                rules[type] = arr;
                rulesLoaded[type] = true;
                renderRules(type);
                updateCards();
            })
            .catch(function(err) { console.error('加载规则失败:', err); });
    }

    window.searchRules = function(type, keyword) {
        var prefix = typeToPrefix[type] || type;
        var container = document.getElementById(prefix + '-rules');
        var countEl = document.getElementById(prefix + '-rule-count');
        if (!container) return;
        var ruleList = rules[type] || [];
        if (!Array.isArray(ruleList)) ruleList = [];
        var filteredRules = ruleList;
        var currentFilter = panelFilters[type] || 'all';
        if (currentFilter !== 'all') filteredRules = ruleList.filter(function(r) { return r.rule_type === currentFilter; });
        if (keyword && keyword.trim()) {
            keyword = keyword.toLowerCase().trim();
            filteredRules = filteredRules.filter(function(rule) {
                return (rule.pattern && rule.pattern.toLowerCase().includes(keyword)) ||
                    (rule.description && rule.description.toLowerCase().includes(keyword));
            });
        }
        var builtinCount = ruleList.filter(function(r) { return r.rule_type === 'builtin'; }).length;
        var customCount = ruleList.filter(function(r) { return r.rule_type === 'custom'; }).length;
        if (countEl) countEl.textContent = '(内置:' + builtinCount + ' 自定义:' + customCount + ')';
        if (filteredRules.length === 0) {
            container.innerHTML = '<div class="empty-message"><span class="empty-icon">📋</span><span class="empty-text">暂无' + (currentFilter !== 'all' ? currentFilter === 'builtin' ? '内置' : '自定义' : '') + '规则</span></div>';
            return;
        }
        container.innerHTML = '';
        filteredRules.forEach(function(rule) {
            var item = document.createElement('div');
            item.className = 'rule-item';
            var actionsHtml = rule.rule_type === 'custom' ? '<button class="btn btn-danger btn-small" onclick="removeRule(' + rule.id + ', \'' + type + '\')">删除</button>' : '';
            item.innerHTML =
                '<div class="rule-info">' +
                    '<span class="rule-type-badge ' + rule.rule_type + '">' + (rule.rule_type === 'builtin' ? '内置' : '自定义') + '</span>' +
                    '<code class="rule-pattern">' + escapeHtml(rule.pattern) + '</code>' +
                    '<span class="rule-desc">' + escapeHtml(rule.description || '') + '</span>' +
                '</div>' +
                '<div class="rule-actions">' +
                    '<label class="rule-toggle"><input type="checkbox" ' + (rule.enabled ? 'checked' : '') + ' onchange="toggleRule(' + rule.id + ', this.checked)"><span class="rule-slider"></span></label>' +
                    actionsHtml +
                '</div>';
            container.appendChild(item);
        });
    };

    function renderRules(type) {
        var prefix = typeToPrefix[type] || type;
        var searchEl = document.getElementById(prefix + '-search');
        searchRules(type, searchEl ? searchEl.value : '');
    }

    window.filterRules = function(type, filter) {
        panelFilters[type] = filter;
        var btns = document.querySelectorAll('#detectorDetail .filter-btn');
        btns.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.dataset.filter === filter) btn.classList.add('active');
        });
        renderRules(type);
    };

    window.toggleDetector = function(type, enabled) {
        fetch('/api/detector/toggle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({ detector_type: type, enabled: enabled })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { if (data.success) loadConfigs(); })
        .catch(function(err) { console.error('Toggle error:', err); });
    };

    window.setObservationMode = function(type, observationMode) {
        var cfg = configs[type] || {};
        var btns = document.querySelectorAll('#detectorDetail .mode-btn');
        btns.forEach(function(btn) {
            if (btn.dataset.mode === 'observe') {
                btn.classList.toggle('active', observationMode);
            } else {
                btn.classList.toggle('active', !observationMode);
            }
        });
        var prefix = typeToPrefix[type] || type;
        var modeHintEl = document.getElementById(prefix + '-mode-hint');
        if (modeHintEl) {
            modeHintEl.textContent = observationMode ? '仅记录日志，不拦截请求' : '检测到攻击时直接拦截';
        }
        fetch('/api/detector/update', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({
                detector_type: type,
                enabled: cfg.enabled,
                observation_mode: observationMode,
                sensitivity_level: cfg.sensitivity_level || 'medium',
                whitelist_ips: cfg.whitelist_ips || '',
                whitelist_paths: cfg.whitelist_paths || ''
            })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { if (data.success) { loadConfigs(); showToast('success', observationMode ? '已切换为观察模式' : '已切换为拦截模式'); } })
        .catch(function(err) { console.error('Set observation mode error:', err); });
    };

    window.setSensitivity = function(type, level) {
        var btns = document.querySelectorAll('#detectorDetail .sensitivity-btn');
        btns.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.dataset.level === level) btn.classList.add('active');
        });
        var saveBtn = document.querySelector('#detectorDetail .btn-primary');
        if (saveBtn) {
            if (!saveBtn.dataset.originalText) saveBtn.dataset.originalText = saveBtn.textContent;
            saveBtn.textContent = '● 保存配置';
            saveBtn.style.fontWeight = '600';
        }
    };

    window.saveConfig = function(type) {
        var prefix = typeToPrefix[type] || type;
        var cfg = configs[type] || {};
        var sensitivity = 'medium';
        var btns = document.querySelectorAll('#detectorDetail .sensitivity-btn');
        btns.forEach(function(btn) { if (btn.classList.contains('active')) sensitivity = btn.dataset.level; });
        var whitelistIPs = document.getElementById(prefix + '-whitelist-ips').value;
        var whitelistPaths = document.getElementById(prefix + '-whitelist-paths').value;
        var saveBtn = document.querySelector('#detectorDetail .btn-primary');
        if (saveBtn) saveBtn.disabled = true;
        fetch('/api/detector/update', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({
                detector_type: type,
                enabled: cfg.enabled,
                sensitivity_level: sensitivity,
                observation_mode: cfg.observation_mode || false,
                whitelist_ips: whitelistIPs,
                whitelist_paths: whitelistPaths
            })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { if (data.success) { loadConfigs(); showToast('success', '配置已保存'); if (saveBtn && saveBtn.dataset.originalText) { saveBtn.textContent = saveBtn.dataset.originalText; saveBtn.style.fontWeight = ''; } } })
        .catch(function(err) { console.error('Save error:', err); })
        .finally(function() { if (saveBtn) saveBtn.disabled = false; });
    };

    window.showAddRule = function(type) {
        currentDetectorType = type;
        document.getElementById('add-rule-modal').classList.add('show');
        document.getElementById('rule-pattern').value = '';
        document.getElementById('rule-description').value = '';
        document.getElementById('rule-pattern').focus();
    };

    window.closeAddRuleModal = function() {
        document.getElementById('add-rule-modal').classList.remove('show');
    };

    window.addRule = function() {
        var pattern = document.getElementById('rule-pattern').value.trim();
        var description = document.getElementById('rule-description').value.trim();
        if (!pattern) { alert('请输入规则模式'); return; }
        var btn = document.querySelector('#add-rule-modal .btn-submit');
        if (btn) btn.disabled = true;
        fetch('/api/detector/rule/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({ detector_type: currentDetectorType, pattern: pattern, description: description })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) { closeAddRuleModal(); rulesLoaded[currentDetectorType] = false; loadRules(currentDetectorType); }
            else alert('添加失败: ' + (data.error || ''));
        })
        .catch(function(err) { alert('添加失败: ' + err); })
        .finally(function() { if (btn) btn.disabled = false; });
    };

    window.removeRule = function(ruleID, type) {
        if (!confirm('确定要删除这条规则吗?')) return;
        fetch('/api/detector/rule/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({ rule_id: ruleID })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { if (data.success) { rulesLoaded[type] = false; loadRules(type); } else alert('删除失败: ' + (data.error || '')); })
        .catch(function(err) { alert('删除失败: ' + err); });
    };

    window.toggleRule = function(ruleID, enabled) {
        fetch('/api/detector/rule/toggle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({ rule_id: ruleID, enabled: enabled })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { if (!data.success) { alert('操作失败: ' + (data.error || '')); if (currentDetectorType) { rulesLoaded[currentDetectorType] = false; loadRules(currentDetectorType); } } })
        .catch(function(err) { alert('操作失败: ' + err); });
    };

    buildLayout();
    loadConfigs();
    setInterval(loadConfigs, 30000);

    window.addEventListener('click', function(event) {
        var modal = document.getElementById('add-rule-modal');
        if (event.target == modal) closeAddRuleModal();
    });
})();
