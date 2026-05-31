(function() {
    var currentRiskFilter = 'all';

    function escapeHtml(text) {
        if (text == null) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function loadConfig() {
        fetch('/api/smartlimit/config')
            .then(r => r.json())
            .then(resp => {
                if (!resp.success) { console.error('加载配置失败:', resp.error); return; }
                var cfg = resp.data || {};
                var el;
                var fieldMap = {
                    'ip_request_threshold':'ipRequestThreshold',
                    'ip_block_threshold':'ipBlockThreshold',
                    'global_qps_threshold':'globalQpsThreshold',
                    'block_threshold':'blockThreshold',
                    'challenge_threshold':'challengeThreshold',
                    'throttle_threshold':'throttleThreshold',
                    'error_ratio_threshold':'errorRatioThreshold',
                    'path_div_threshold':'pathDivThreshold',
                    'ua_div_threshold':'uaDivThreshold',
                    'rule_div_threshold':'ruleDivThreshold',
                    'interval_var_min':'intervalVarMin',
                    'sensitive_path_limit':'sensitivePathLimit',
                    'adaptive_enabled':'adaptiveEnabled',
                    'sensitivity':'sensitivity',
                    'method_div_threshold':'methodDivThreshold',
                    'no_cookie_ratio_threshold':'noCookieRatioThreshold',
                    'no_referer_ratio_threshold':'noRefererRatioThreshold',
                    'body_size_threshold':'bodySizeThreshold',
                    'asn_change_threshold':'asnChangeThreshold',
                    'auto_weight_enabled':'autoWeightEnabled',
                    'weight_learning_rate':'weightLearningRate',
                    'dynamic_baseline_pct':'dynamicBaselinePct',
                    'fingerprint_enabled':'fingerprintEnabled',
                    'fingerprint_suspect_threshold':'fingerprintSuspectThreshold',
                    'attack_chain_enabled':'attackChainEnabled',
                    'attack_chain_weight':'attackChainWeight',
                    'false_positive_repair':'falsePositiveRepair',
                    'auto_pardon_enabled':'autoPardonEnabled',
                    'hour_profile_enabled':'hourProfileEnabled',
                    'hour_anomaly_weight':'hourAnomalyWeight',
                    'auto_block_enabled':'autoBlockEnabled',
                    'auto_block_threshold':'autoBlockThreshold',
                    'auto_block_duration_sec':'autoBlockDuration'
                };
                Object.keys(fieldMap).forEach(function(apiKey) {
                    var domId = fieldMap[apiKey];
                    el = document.getElementById(domId);
                    if (el && cfg[apiKey] !== undefined) el.value = cfg[apiKey];
                });
                el = document.getElementById('globalQps');
                if (el) el.textContent = cfg.global_qps || '-';
                el = document.getElementById('profileCount');
                if (el) el.textContent = cfg.profile_count || '-';
                el = document.getElementById('windowSize');
                if (el) el.textContent = cfg.window_size || '-';
                el = document.getElementById('maxAge');
                if (el) el.textContent = cfg.profile_max_age_sec || '-';
                var badge = document.getElementById('statusBadge');
                var toggleBtn = document.getElementById('toggleBtn');
                var modeBtn = document.getElementById('modeBtn');
                if (badge) {
                    badge.textContent = cfg.enabled ? '已启用' : '已禁用';
                    badge.className = 'status-badge ' + (cfg.enabled ? 'status-enabled' : 'status-disabled');
                }
                if (toggleBtn) {
                    toggleBtn.textContent = cfg.enabled ? '禁用' : '启用';
                    toggleBtn.className = 'btn btn-sm ' + (cfg.enabled ? 'btn-danger' : 'btn-success');
                }
                if (modeBtn) {
                    if (cfg.mode === 'observe') {
                        modeBtn.textContent = '观察模式';
                        modeBtn.className = 'btn btn-sm btn-mode-observe';
                    } else {
                        modeBtn.textContent = '拦截模式';
                        modeBtn.className = 'btn btn-sm btn-mode-intercept';
                    }
                }
                if (cfg.whitelist_ips) {
                    el = document.getElementById('whitelistIPs');
                    if (el) el.value = cfg.whitelist_ips.join('\n');
                }
                loadRatelimitKeyConfig();
                renderWeightGroups(cfg);
            })
            .catch(err => console.error('加载配置失败:', err));
    }

    var weightGroups = [
        {
            name: '行为指标',
            indicator: 'group-indicator-blue',
            items: [
                {key:'w_request_rate', label:'请求速率', hint:'IP请求速率权重', defaultVal:0.20},
                {key:'w_block_rate', label:'拦截率', hint:'IP拦截率权重', defaultVal:0.15},
                {key:'w_error_ratio', label:'错误率', hint:'错误响应占比权重', defaultVal:0.12},
                {key:'w_path_div', label:'路径多样性', hint:'唯一路径数权重', defaultVal:0.12},
                {key:'w_rule_div', label:'规则多样性', hint:'命中规则种类权重', defaultVal:0.08}
            ]
        },
        {
            name: '异常指标',
            indicator: 'group-indicator-orange',
            items: [
                {key:'w_ua_div', label:'UA多样性', hint:'唯一UA数权重', defaultVal:0.06},
                {key:'w_interval_var', label:'间隔方差', hint:'请求间隔方差权重', defaultVal:0.03},
                {key:'w_sensitive_path', label:'敏感路径', hint:'敏感路径命中权重', defaultVal:0.04},
                {key:'w_geo_anomaly', label:'地理异常', hint:'国家变化异常权重', defaultVal:0.05},
                {key:'w_cookie_anomaly', label:'Cookie异常', hint:'无Cookie请求权重', defaultVal:0.04}
            ]
        },
        {
            name: '增强指标',
            indicator: 'group-indicator-green',
            items: [
                {key:'w_method_anomaly', label:'方法异常', hint:'HTTP方法异常权重', defaultVal:0.03},
                {key:'w_referer_anomaly', label:'Referer异常', hint:'无Referer请求权重', defaultVal:0.03},
                {key:'w_body_anomaly', label:'请求体异常', hint:'请求体大小异常权重', defaultVal:0.05}
            ]
        }
    ];

    function renderWeightGroups(cfg) {
        var weightListEl = document.getElementById('weightList');
        if (!weightListEl) return;
        var html = '';
        var totalSum = 0;
        weightGroups.forEach(function(group) {
            var groupSum = 0;
            group.items.forEach(function(item) {
                groupSum += cfg[item.key] || 0;
            });
            totalSum += groupSum;
            var pct = (groupSum * 100).toFixed(1);
            html += '<div class="weight-group">';
            html += '<div class="weight-group-title"><span class="group-indicator ' + group.indicator + '"></span> ' + group.name + ' <span class="weight-group-pct">(' + pct + '%)</span></div>';
            group.items.forEach(function(item) {
                var val = cfg[item.key] || 0;
                var pctWidth = Math.min(val / 0.25 * 100, 100);
                html += '<div class="weight-item">';
                html += '<span class="weight-label">' + item.label + '</span>';
                html += '<div class="weight-slider"><input type="range" min="0" max="0.30" step="0.01" value="' + val + '" data-key="' + item.key + '" oninput="onWeightSlider(this)"></div>';
                html += '<input type="number" class="weight-value-input" id="' + item.key + '" value="' + val + '" min="0" max="1" step="0.01" oninput="onWeightInput(this)">';
                html += '<span class="weight-hint">' + item.hint + '</span>';
                html += '</div>';
            });
            html += '</div>';
        });
        weightListEl.innerHTML = html;
        updateWeightSum(totalSum);
    }

    function updateWeightSum(sum) {
        var sumEl = document.getElementById('weightSum');
        var barEl = document.getElementById('weightSumBar');
        var hintEl = document.getElementById('weightSumHint');
        if (!sumEl) return;
        if (sum === undefined || sum === null) {
            sum = 0;
            document.querySelectorAll('.weight-value-input').forEach(function(el) { sum += parseFloat(el.value) || 0; });
        }
        sumEl.textContent = sum.toFixed(2);
        if (barEl) {
            barEl.className = 'weight-sum-bar';
            if (Math.abs(sum - 1.0) < 0.02) {
                barEl.classList.add('sum-ok');
                if (hintEl) hintEl.textContent = '✓ 总和正常';
            } else if (sum > 1.0) {
                barEl.classList.add('sum-error');
                if (hintEl) hintEl.textContent = '⚠ 总和超过1.0';
            } else {
                barEl.classList.add('sum-warn');
                if (hintEl) hintEl.textContent = '⚠ 总和不足1.0';
            }
        }
    }

    window.onWeightSlider = function(slider) {
        var key = slider.getAttribute('data-key');
        var input = document.getElementById(key);
        if (input) input.value = slider.value;
        updateWeightSum();
    };

    window.onWeightInput = function(input) {
        var slider = document.querySelector('input[type="range"][data-key="' + input.id + '"]');
        if (slider) slider.value = input.value;
        updateWeightSum();
    };

    var toggleLock = false;

    window.toggleEngine = function() {
        if (toggleLock) return;
        toggleLock = true;
        var badge = document.getElementById('statusBadge');
        var currentEnabled = badge && badge.textContent === '已启用';
        var newEnabled = !currentEnabled;
        fetch('/api/smartlimit/config', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({enabled:newEnabled})
        }).then(r=>r.json()).then(d=>{
            if(d.success) loadConfig();
            else showToast('error','操作失败: '+(d.error||''));
        }).catch(()=> showToast('error','操作失败')).finally(function(){ toggleLock = false; });
    };

    window.toggleMode = function() {
        if (toggleLock) return;
        toggleLock = true;
        var modeBtn = document.getElementById('modeBtn');
        var currentMode = modeBtn && modeBtn.textContent === '观察模式' ? 'observe' : 'intercept';
        var newMode = currentMode === 'observe' ? 'intercept' : 'observe';
        fetch('/api/smartlimit/config', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({mode:newMode})
        }).then(r=>r.json()).then(d=>{
            if(d.success) loadConfig();
            else showToast('error','操作失败: '+(d.error||''));
        }).catch(()=> showToast('error','操作失败')).finally(function(){ toggleLock = false; });
    };

    window.toggleCollapse = function(id) {
        var el = document.getElementById(id);
        if (el) el.classList.toggle('collapsed');
    };

    window.switchTab = function(tab) {
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
        var tabEl = document.querySelector('.tab[data-tab="'+tab+'"]');
        var contentEl = document.getElementById('tab-'+tab);
        if (tabEl) tabEl.classList.add('active');
        if (contentEl) {
            contentEl.classList.add('active');
            contentEl.style.opacity = '0';
            requestAnimationFrame(function() {
                contentEl.style.opacity = '1';
            });
        }
        if (tab === 'profiles') loadProfiles();
    };

    window.updateWeightSum = function() {
        updateWeightSum();
    };

    window.saveConfig = function() {
        var data = {};
        var numFieldMap = {
            'ipRequestThreshold':'ip_request_threshold',
            'ipBlockThreshold':'ip_block_threshold',
            'globalQpsThreshold':'global_qps_threshold',
            'blockThreshold':'block_threshold',
            'challengeThreshold':'challenge_threshold',
            'throttleThreshold':'throttle_threshold',
            'errorRatioThreshold':'error_ratio_threshold',
            'pathDivThreshold':'path_div_threshold',
            'uaDivThreshold':'ua_div_threshold',
            'ruleDivThreshold':'rule_div_threshold',
            'intervalVarMin':'interval_var_min',
            'sensitivePathLimit':'sensitive_path_limit',
            'methodDivThreshold':'method_div_threshold',
            'noCookieRatioThreshold':'no_cookie_ratio_threshold',
            'noRefererRatioThreshold':'no_referer_ratio_threshold',
            'bodySizeThreshold':'body_size_threshold',
            'asnChangeThreshold':'asn_change_threshold',
            'weightLearningRate':'weight_learning_rate',
            'dynamicBaselinePct':'dynamic_baseline_pct',
            'fingerprintSuspectThreshold':'fingerprint_suspect_threshold',
            'attackChainWeight':'attack_chain_weight',
            'hourAnomalyWeight':'hour_anomaly_weight',
            'autoBlockDuration':'auto_block_duration_sec'
        };
        Object.keys(numFieldMap).forEach(function(domId) {
            var el = document.getElementById(domId);
            if (el) data[numFieldMap[domId]] = parseFloat(el.value);
        });
        var boolFieldMap = {
            'adaptiveEnabled':'adaptive_enabled',
            'autoWeightEnabled':'auto_weight_enabled',
            'fingerprintEnabled':'fingerprint_enabled',
            'attackChainEnabled':'attack_chain_enabled',
            'falsePositiveRepair':'false_positive_repair',
            'autoPardonEnabled':'auto_pardon_enabled',
            'hourProfileEnabled':'hour_profile_enabled',
            'autoBlockEnabled':'auto_block_enabled'
        };
        Object.keys(boolFieldMap).forEach(function(domId) {
            var el = document.getElementById(domId);
            if (el) data[boolFieldMap[domId]] = el.value === 'true';
        });
        var el = document.getElementById('sensitivity');
        if (el) data.sensitivity = parseFloat(el.value);
        var el2 = document.getElementById('autoBlockThreshold');
        if (el2) data.auto_block_threshold = parseInt(el2.value);
        var weightKeys = ['w_request_rate','w_block_rate','w_error_ratio','w_path_div','w_ua_div',
            'w_rule_div','w_interval_var','w_sensitive_path','w_geo_anomaly','w_cookie_anomaly',
            'w_method_anomaly','w_referer_anomaly','w_body_anomaly'];
        weightKeys.forEach(function(k) {
            var wEl = document.getElementById(k);
            if (wEl) data[k] = parseFloat(wEl.value);
        });
        var wlEl = document.getElementById('whitelistIPs');
        if (wlEl) data.whitelist_ips = wlEl.value.split('\n').filter(function(s){return s.trim();});
        fetch('/api/smartlimit/config', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify(data)
        }).then(r=>r.json()).then(d=>{
            if(d.success) { showToast('success','保存成功'); saveRatelimitKeyConfig(); }
            else showToast('error','保存失败: '+(d.error||''));
        }).catch(()=> showToast('error','保存失败'));
    };

    window.filterProfiles = function() { loadProfiles(); };

    window.filterByRisk = function(risk) {
        currentRiskFilter = risk;
        document.querySelectorAll('.filter-btn').forEach(function(btn) {
            btn.classList.toggle('active', btn.getAttribute('data-risk') === risk);
        });
        loadProfiles();
    };

    function computeRiskLevel(p) {
        var score = 0;
        if (p.block_rate > 5) score += 2;
        else if (p.block_rate > 0) score += 1;
        if (p.error_ratio > 0.3) score += 2;
        else if (p.error_ratio > 0.1) score += 1;
        if (p.trust_score < -5) score += 2;
        else if (p.trust_score < 0) score += 1;
        if (p.path_diversity > 30) score += 1;
        if (p.request_rate > 50) score += 1;
        if (score >= 4) return 'high';
        if (score >= 2) return 'mid';
        return 'low';
    }

    function renderTrustBar(score) {
        var pct = Math.max(0, Math.min(100, (score + 20) / 120 * 100));
        var color;
        if (score >= 20) color = '#27ae60';
        else if (score >= 0) color = '#f39c12';
        else color = '#e74c3c';
        return '<div class="trust-bar">' +
            '<div class="trust-bar-fill"><div class="trust-bar-fill-inner" style="width:' + pct + '%;background:' + color + ';"></div></div>' +
            '<span class="trust-bar-text" style="color:' + color + ';">' + score.toFixed(1) + '</span></div>';
    }

    function renderRiskBadge(level) {
        var labels = {low: '低', mid: '中', high: '高'};
        return '<span class="risk-badge risk-' + level + '">' + labels[level] + '</span>';
    }

    window.loadProfiles = function() {
        fetch('/api/smartlimit/profiles')
            .then(r=>r.json())
            .then(resp => {
                if (!resp.success) { console.error('加载画像失败:', resp.error); return; }
                var data = resp.data || [];
                var searchEl = document.getElementById('searchIP');
                var keyword = searchEl ? searchEl.value.toLowerCase() : '';
                if (keyword) data = data.filter(function(p){return p.ip.toLowerCase().includes(keyword);});
                if (currentRiskFilter !== 'all') {
                    data = data.filter(function(p) { return computeRiskLevel(p) === currentRiskFilter; });
                }
                var tbody = document.getElementById('profileBody');
                if (!tbody) return;
                tbody.innerHTML = '';
                data.forEach(function(p) {
                    var riskLevel = computeRiskLevel(p);
                    var tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-weight:600;">'+escapeHtml(p.ip)+'</td>'+
                        '<td>'+(p.request_rate||0)+'</td>'+
                        '<td>'+(p.block_rate||0)+'</td>'+
                        '<td>'+renderTrustBar(p.trust_score||0)+'</td>'+
                        '<td>'+(p.total_count||0)+'</td>'+
                        '<td>'+(p.last_active?new Date(p.last_active).toLocaleString():'-')+'</td>'+
                        '<td>'+renderRiskBadge(riskLevel)+'</td>'+
                        '<td><button class="btn btn-sm" onclick="showProfileDetail(\''+escapeHtml(p.ip)+'\')">详情</button></td>';
                    tbody.appendChild(tr);
                });
            })
            .catch(err => console.error('加载画像失败:', err));
    };

    window.showProfileDetail = function(ip) {
        fetch('/api/smartlimit/profile?ip=' + encodeURIComponent(ip))
            .then(r => r.json())
            .then(resp => {
                if (!resp.success) { console.error('获取画像详情失败:', resp.error); return; }
                var p = resp.data || {};
                var riskLevel = computeRiskLevel(p);
                var overlay = document.createElement('div');
                overlay.className = 'profile-modal';
                overlay.innerHTML = '<div class="modal-overlay" onclick="this.parentElement.remove()"></div>' +
                    '<div class="modal-content">' +
                    '<span class="modal-close" onclick="this.parentElement.parentElement.remove()">&times;</span>' +
                    '<div class="modal-header">' +
                    '<span class="modal-ip">' + escapeHtml(p.ip) + '</span>' +
                    renderRiskBadge(riskLevel) +
                    '<span class="modal-time">' + (p.last_active ? new Date(p.last_active).toLocaleString() : '-') + '</span>' +
                    '</div>' +
                    '<div class="modal-body-row">' +
                    '<div class="modal-score-area">' +
                    '<div class="score-circle" style="--color:' + (riskLevel==='high'?'#e74c3c':riskLevel==='mid'?'#f39c12':'#27ae60') + ';--pct:' + Math.min(Math.max(((p.trust_score||0)+20)/120*100,0),100) + ';">' +
                    '<span class="score-value">' + (p.trust_score||0).toFixed(1) + '</span>' +
                    '<span class="score-label">信任分</span>' +
                    '</div>' +
                    '</div>' +
                    '<div class="modal-actions-area">' +
                    '<div class="modal-stats-mini">' +
                    '请求速率: ' + (p.request_rate||0) + ' 次/窗口<br>' +
                    '拦截率: ' + (p.block_rate||0) + ' 次<br>' +
                    '错误率: ' + ((p.error_ratio||0)*100).toFixed(1) + '%<br>' +
                    '路径多样性: ' + (p.path_diversity||0) + '<br>' +
                    'UA多样性: ' + (p.ua_diversity||0) + '<br>' +
                    '规则多样性: ' + (p.rule_diversity||0) +
                    '</div></div></div>' +
                    '<div class="modal-section-title">豁免操作</div>' +
                    '<div style="display:flex;gap:10px;">' +
                    '<button class="btn btn-sm btn-success" onclick="pardonIP(\'' + escapeHtml(p.ip) + '\',this)">豁免此IP</button>' +
                    '</div>' +
                    '</div>';
                document.body.appendChild(overlay);
            })
            .catch(err => console.error('获取画像详情失败:', err));
    };

    window.pardonIP = function(ip, btn) {
        fetch('/api/smartlimit/pardon', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ip: ip})
        }).then(r=>r.json()).then(d=>{
            if(d.success) {
                showToast('success','已豁免: ' + ip);
                if (btn) { btn.disabled = true; btn.textContent = '已豁免'; }
                setTimeout(function(){ loadProfiles(); }, 1000);
            } else {
                showToast('error','豁免失败: '+(d.error||''));
            }
        }).catch(()=> showToast('error','豁免失败'));
    };

    loadConfig();
    setInterval(loadConfig, 15000);

    function loadRatelimitKeyConfig() {
        fetch('/api/ratelimit-key').then(function(r){
            if (r.status === 410) return null;
            return r.json();
        }).then(function(resp){
            if (!resp || !resp.success) return;
            var cfg = resp.data || {};
            var el = document.getElementById('ratelimitKeyType');
            if (el && cfg.key_type) el.value = cfg.key_type;
            el = document.getElementById('ratelimitHeaderName');
            if (el && cfg.header_name) el.value = cfg.header_name;
            el = document.getElementById('ratelimitCookieName');
            if (el && cfg.cookie_name) el.value = cfg.cookie_name;
            el = document.getElementById('ratelimitSessionKey');
            if (el && cfg.session_key) el.value = cfg.session_key;
            toggleRatelimitKeyExtra();
        }).catch(function(){});
    }

    function saveRatelimitKeyConfig() {
        var data = {
            key_type: (document.getElementById('ratelimitKeyType') || {}).value || 'ip',
            header_name: (document.getElementById('ratelimitHeaderName') || {}).value || 'X-API-Key',
            cookie_name: (document.getElementById('ratelimitCookieName') || {}).value || 'session_id',
            session_key: (document.getElementById('ratelimitSessionKey') || {}).value || 'SESSIONID'
        };
        fetch('/api/ratelimit-key', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify(data)
        }).then(function(r){
            if (r.status === 410) {
                showToast('warning', '限流键类型配置已迁移至智能限流');
            }
        }).catch(function(){});
    }

    window.toggleRatelimitKeyExtra = function() {
        var sel = document.getElementById('ratelimitKeyType');
        var extra = document.getElementById('ratelimitKeyExtra');
        if (!sel || !extra) return;
        var show = ['cookie','header','combined','session','api_key'].indexOf(sel.value) >= 0;
        extra.style.display = show ? 'flex' : 'none';
    };
})();
