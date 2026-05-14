(function() {
    function escapeHtml(text) {
        if (text == null) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function loadRules() {
        fetch('/api/notify/rules')
            .then(r => r.json())
            .then(resp => {
                var data = resp.data || [];
                var tbody = document.querySelector('#rules-table tbody');
                if (!tbody) return;
                tbody.innerHTML = '';
                data.forEach(function(rule) {
                    var tr = document.createElement('tr');
                    tr.innerHTML = '<td>'+(rule.enabled?'<span style="color:#27ae60">启用</span>':'<span style="color:#95a5a6">禁用</span>')+'</td>'+
                        '<td>'+escapeHtml(rule.name)+'</td>'+
                        '<td>'+escapeHtml(rule.match_type)+' = '+escapeHtml(rule.match_value)+'</td>'+
                        '<td>'+escapeHtml(rule.level)+'</td>'+
                        '<td>≥'+rule.threshold+'次/'+rule.window_secs+'秒</td>'+
                        '<td>'+escapeHtml(rule.notify_type)+'</td>'+
                        '<td><button class="btn btn-sm" onclick="editRule(\''+rule.id+'\')">编辑</button> '+
                        '<button class="btn btn-sm btn-danger" onclick="deleteRule(\''+rule.id+'\')">删除</button></td>';
                    tbody.appendChild(tr);
                });
            })
            .catch(err => console.error('加载规则失败:', err));
    }

    function loadConfig() {
        fetch('/api/notify/config')
            .then(r => r.json())
            .then(resp => {
                var cfg = resp.data || {};
                ['dingtalk','wecom','slack','email'].forEach(function(ch) {
                    var enabledEl = document.getElementById(ch+'_enabled');
                    var descEl = document.getElementById(ch+'-desc');
                    var statusEl = document.getElementById(ch+'-status');
                    if (cfg[ch+'_enabled'] !== undefined && enabledEl) enabledEl.checked = cfg[ch+'_enabled'];
                    if (descEl) descEl.textContent = cfg[ch+'_webhook'] || cfg[ch+'_smtp_host'] ? '已配置' : '点击配置';
                    if (statusEl) statusEl.textContent = cfg[ch+'_enabled'] ? '●' : '○';
                });
            })
            .catch(err => console.error('加载通知配置失败:', err));
    }

    window.onChannelToggle = function(channel) {};

    window.saveChannelToggles = function() {
        var cfg = {};
        ['dingtalk','wecom','slack','email'].forEach(function(ch) {
            var el = document.getElementById(ch+'_enabled');
            if (el) cfg[ch+'_enabled'] = el.checked;
        });
        fetch('/api/notify/config/update', {
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify(cfg)
        }).then(r=>r.json()).then(d=>{
            if(d.success) showToast('success','保存成功');
            else showToast('error','保存失败');
        });
    };

    window.openChannelModal = function(channel) {
        document.getElementById('channel-modal').classList.add('show');
        document.getElementById('channel-modal-title').textContent = '编辑' + ({dingtalk:'钉钉',wecom:'企业微信',slack:'Slack',email:'邮件'}[channel]||channel);
    };

    window.closeChannelModal = function() {
        document.getElementById('channel-modal').classList.remove('show');
    };

    window.channelModalTest = function() {
        showToast('info','测试通知已发送');
    };

    window.saveChannelFromModal = function() {
        closeChannelModal();
        loadConfig();
    };

    window.showRuleModal = function() {
        document.getElementById('rule-modal').classList.add('show');
        document.getElementById('rule-modal-title').textContent = '添加告警规则';
        document.getElementById('rule-id').value = '';
    };

    window.closeRuleModal = function() {
        document.getElementById('rule-modal').classList.remove('show');
    };

    window.editRule = function(id) {
        showRuleModal();
        document.getElementById('rule-modal-title').textContent = '编辑告警规则';
        document.getElementById('rule-id').value = id;
    };

    window.deleteRule = function(id) {
        if (!confirm('确定删除此规则？')) return;
        fetch('/api/notify/rules/delete', {
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify({id:id})
        }).then(r=>r.json()).then(d=>{
            if(d.success) loadRules();
            else showToast('error','删除失败');
        });
    };

    window.saveRule = function() {
        var rule = {
            id: document.getElementById('rule-id').value || undefined,
            name: document.getElementById('rule-name').value,
            match_type: document.getElementById('rule-match-type').value,
            match_value: document.getElementById('rule-match-value').value || document.getElementById('rule-match-value-select').value,
            level: document.getElementById('rule-level').value,
            threshold: parseInt(document.getElementById('rule-threshold').value) || 1,
            window_secs: parseInt(document.getElementById('rule-window-secs').value) || 60,
            notify_type: document.getElementById('rule-notify-type').value,
            cooldown_secs: parseInt(document.getElementById('rule-cooldown-secs').value) || 300,
            enabled: document.getElementById('rule-enabled').checked
        };
        fetch('/api/notify/rules/update', {
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body: JSON.stringify(rule)
        }).then(r=>r.json()).then(d=>{
            if(d.success){ closeRuleModal(); loadRules(); }
            else showToast('error','保存失败');
        });
    };

    window.onMatchTypeChange = function() {
        var type = document.getElementById('rule-match-type').value;
        document.getElementById('match-value-select').style.display = type === 'attack_type' ? '' : 'none';
        document.getElementById('match-value-input').style.display = type === 'attack_type' ? 'none' : '';
        document.getElementById('ip-presets').style.display = type === 'ip' ? '' : 'none';
    };

    window.syncMatchValue = function() {
        document.getElementById('rule-match-value').value = document.getElementById('rule-match-value-select').value;
    };

    window.setMatchValue = function(v) {
        document.getElementById('rule-match-value').value = v;
    };

    window.updatePreview = function() {};

    loadRules();
    loadConfig();
})();
