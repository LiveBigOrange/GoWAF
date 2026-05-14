(function() {
    function escapeHtml(text) {
        if (text == null) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    var categoryLabels = {
        search_engine:'搜索引擎', social_crawler:'社交爬虫', monitor:'监控工具',
        scraper:'爬虫', malicious:'恶意', human:'人类', unknown:'未知'
    };
    var categoryTags = {
        search_engine:'tag-se', social_crawler:'tag-social', monitor:'tag-monitor',
        scraper:'tag-scraper', malicious:'tag-malicious', human:'tag-human', unknown:'tag-unknown'
    };
    var policyActions = ['block','record','allow'];
    var policyLabels = {block:'拦截',record:'记录',allow:'放行'};

    function loadStats() {
        fetch('/api/bot/stats').then(r=>r.json()).then(resp=>{
            var data = resp.data || {};
            var byCategory = data.by_category || {};
            var statMap = {search_engine:'se', social_crawler:'social', monitor:'monitor', scraper:'scraper', malicious:'malicious', human:'human', unknown:'unknown'};
            Object.keys(statMap).forEach(function(cat) {
                var el = document.getElementById('stat-' + statMap[cat]);
                if(el) el.textContent = byCategory[cat] || 0;
            });
        }).catch(()=>{});
    }

    function loadKnownBots() {
        fetch('/api/bot/known-bots').then(r=>r.json()).then(resp=>{
            var data = resp.data || [];
            window._knownBots = data;
            renderKnownBots(data);
        }).catch(()=>{});
    }

    function renderKnownBots(data) {
        var keyword = (document.getElementById('knownSearch')||{}).value||'';
        if(keyword) keyword = keyword.toLowerCase();
        var container = document.getElementById('knownBotList');
        if(!container) return;
        container.innerHTML = '';
        var grouped = {};
        data.forEach(function(b){
            var cat = b.category||'unknown';
            if(!grouped[cat]) grouped[cat]=[];
            grouped[cat].push(b);
        });
        Object.keys(grouped).sort().forEach(function(cat){
            var bots = grouped[cat].filter(function(b){
                if(!keyword) return true;
                return (b.name||'').toLowerCase().includes(keyword) || (b.ua_pattern||'').toLowerCase().includes(keyword);
            });
            if(bots.length===0) return;
            var group = document.createElement('div');
            group.className = 'cat-group';
            group.innerHTML = '<div class="cat-group-header" onclick="toggleGroup(this)"><span class="cg-arrow">▶</span><span class="cg-title">'+(categoryLabels[cat]||cat)+'</span><span class="cg-count">('+bots.length+')</span></div>';
            var body = document.createElement('div');
            body.className = 'cat-group-body';
            body.style.display = 'none';
            var tbl = document.createElement('table');
            tbl.className = 'tbl';
            tbl.innerHTML = '<thead><tr><th>名称</th><th>UA匹配</th><th>白名单</th><th>启用</th><th>操作</th></tr></thead>';
            var tbody = document.createElement('tbody');
            bots.forEach(function(b){
                var tr = document.createElement('tr');
                tr.innerHTML = '<td>'+escapeHtml(b.name)+'</td>'+
                    '<td><code>'+escapeHtml(b.ua_pattern)+'</code></td>'+
                    '<td>'+(b.whitelisted?'<span class="tag tag-human">白名单</span>':'<span class="tag tag-malicious">否</span>')+'</td>'+
                    '<td><label class="toggle"><input type="checkbox" '+(b.enabled?'checked':'')+' onchange="toggleKnownBot(\''+escapeHtml(b.name)+'\',this.checked)"><span class="sw"></span></label></td>'+
                    '<td><button class="lnk" onclick="overrideKnownBot(\''+escapeHtml(b.name)+'\')">覆盖</button></td>';
                tbody.appendChild(tr);
            });
            tbl.appendChild(tbody);
            body.appendChild(tbl);
            group.appendChild(body);
            container.appendChild(group);
        });
    }

    window.toggleGroup = function(header) {
        var arrow = header.querySelector('.cg-arrow');
        var body = header.nextElementSibling;
        if(body.style.display==='none'){
            body.style.display='';
            arrow.classList.add('open');
        } else {
            body.style.display='none';
            arrow.classList.remove('open');
        }
    };

    window.filterKnownBots = function() { renderKnownBots(window._knownBots||[]); };

    window.toggleKnownBot = function(name, enabled) {
        fetch('/api/bot/known-bot-override',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({name:name,enabled:enabled})
        }).then(r=>r.json()).then(d=>{ if(d.success) loadKnownBots(); });
    };

    window.overrideKnownBot = function(name) {
        fetch('/api/bot/known-bot-override',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({name:name,whitelisted:true})
        }).then(r=>r.json()).then(d=>{ if(d.success) loadKnownBots(); });
    };

    function loadCustomRules() {
        fetch('/api/bot/rules').then(r=>r.json()).then(resp=>{
            var data = resp.data || [];
            window._customRules = data;
            renderCustomRules(data);
        }).catch(()=>{});
    }

    function renderCustomRules(data) {
        var keyword = (document.getElementById('customSearch')||{}).value||'';
        if(keyword) keyword = keyword.toLowerCase();
        var tbody = document.getElementById('customBody');
        if(!tbody) return;
        tbody.innerHTML = '';
        data.filter(function(r){
            if(!keyword) return true;
            return (r.name||'').toLowerCase().includes(keyword) || (r.ua_pattern||'').toLowerCase().includes(keyword);
        }).forEach(function(r){
            var tr = document.createElement('tr');
            tr.innerHTML = '<td class="cb-col"><input type="checkbox" class="rule-cb" data-id="'+r.id+'" onchange="updateBatchButtons()"></td>'+
                '<td>'+escapeHtml(r.name)+'</td>'+
                '<td><span class="tag '+(categoryTags[r.category]||'tag-unknown')+'">'+(categoryLabels[r.category]||r.category)+'</span></td>'+
                '<td><code>'+escapeHtml(r.ua_pattern)+'</code></td>'+
                '<td>'+(r.whitelisted?'是':'否')+'</td>'+
                '<td><label class="toggle"><input type="checkbox" '+(r.enabled?'checked':'')+' onchange="toggleRule('+r.id+',this.checked)"><span class="sw"></span></label></td>'+
                '<td class="hit-col">-</td>'+
                '<td><button class="lnk" onclick="editRule('+r.id+')">编辑</button> <button class="lnk danger" onclick="deleteRule('+r.id+')">删除</button></td>';
            tbody.appendChild(tr);
        });
    }

    window.filterCustomRules = function() { renderCustomRules(window._customRules||[]); };

    window.switchTab = function(tab) {
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
        document.querySelector('.tab[data-tab="'+tab+'"]').classList.add('active');
        document.getElementById('tab-'+tab).classList.add('active');
        if(tab==='policy') loadPolicies();
        if(tab==='known') loadKnownBots();
        if(tab==='custom') loadCustomRules();
    };

    var categoryIcons = {
        search_engine:'🔍', social_crawler:'📱', monitor:'📡',
        scraper:'🕷️', malicious:'☠️', human:'👤', unknown:'❓'
    };
    var categoryCssClass = {
        search_engine:'pc-se', social_crawler:'pc-social', monitor:'pc-monitor',
        scraper:'pc-scraper', malicious:'pc-malicious', human:'pc-human', unknown:'pc-unknown'
    };

    function loadPolicies() {
        fetch('/api/bot/policies').then(r=>r.json()).then(resp=>{
            var data = resp.data || [];
            var grid = document.getElementById('policyGrid');
            if(!grid) return;
            grid.innerHTML = '';
            data.forEach(function(item){
                var cat = item.category || 'unknown';
                var card = document.createElement('div');
                card.className = 'policy-card ' + (categoryCssClass[cat]||'pc-unknown');
                var currentAction = item.action || 'record';
                var optClass = 'opt-' + currentAction;
                card.innerHTML = '<div class="pc-header"><span class="pc-icon">'+(categoryIcons[cat]||'❓')+'</span><span class="pc-label">'+(categoryLabels[cat]||cat)+'</span></div>'+
                    '<select class="'+optClass+'" onchange="setPolicy(\''+cat+'\',this.value);updateSelectStyle(this)">'+
                    policyActions.map(function(a){return '<option value="'+a+'"'+(currentAction===a?' selected':'')+'>'+policyLabels[a]+'</option>';}).join('')+
                    '</select>';
                grid.appendChild(card);
            });
        }).catch(()=>{});
    }

    window.updateSelectStyle = function(sel) {
        sel.className = 'opt-' + sel.value;
    };

    window.setPolicy = function(category, action) {
        fetch('/api/bot/policy/set',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({category:category,action:action})
        }).then(r=>r.json()).then(d=>{
            if(!d.success) showToast('error','设置策略失败');
        });
    };

    window.batchSetPolicy = function(action) {
        var categories = Object.keys(categoryLabels);
        var done = 0;
        categories.forEach(function(cat){
            fetch('/api/bot/policy/set',{
                method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
                body:JSON.stringify({category:cat,action:action})
            }).then(r=>r.json()).then(d=>{
                done++;
                if(done===categories.length) {
                    loadPolicies();
                    showToast('success','已全部设为'+policyLabels[action]);
                }
            });
        });
    };

    window.showAddModal = function() {
        document.getElementById('addModal').classList.add('show');
        document.getElementById('editName').value='';
        document.getElementById('editPattern').value='';
        document.getElementById('editCategory').value='scraper';
        document.getElementById('editWhitelisted').checked=false;
        document.getElementById('editEnabled').checked=true;
    };

    window.closeAddModal = function() { document.getElementById('addModal').classList.remove('show'); };

    window.saveRule = function() {
        var data = {
            name: document.getElementById('editName').value,
            category: document.getElementById('editCategory').value,
            ua_pattern: document.getElementById('editPattern').value,
            whitelisted: document.getElementById('editWhitelisted').checked,
            enabled: document.getElementById('editEnabled').checked
        };
        if(!data.name||!data.ua_pattern){ showToast('error','请填写名称和UA匹配'); return; }
        fetch('/api/bot/rule/add',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify(data)
        }).then(r=>r.json()).then(d=>{
            if(d.success){ closeAddModal(); loadCustomRules(); }
            else showToast('error','添加失败');
        });
    };

    window.editRule = function(id) {
        var rule = (window._customRules||[]).find(function(r){return r.id===id;});
        if(!rule) return;
        document.getElementById('editModal').classList.add('show');
        document.getElementById('editId').value=id;
        document.getElementById('editName2').value=rule.name||'';
        document.getElementById('editCategory2').value=rule.category||'scraper';
        document.getElementById('editPattern2').value=rule.ua_pattern||'';
        document.getElementById('editWhitelisted2').checked=!!rule.whitelisted;
        document.getElementById('editEnabled2').checked=!!rule.enabled;
    };

    window.closeEditModal = function() { document.getElementById('editModal').classList.remove('show'); };

    window.updateRule = function() {
        var data = {
            id: parseInt(document.getElementById('editId').value),
            name: document.getElementById('editName2').value,
            category: document.getElementById('editCategory2').value,
            ua_pattern: document.getElementById('editPattern2').value,
            whitelisted: document.getElementById('editWhitelisted2').checked,
            enabled: document.getElementById('editEnabled2').checked
        };
        fetch('/api/bot/rule/update',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify(data)
        }).then(r=>r.json()).then(d=>{
            if(d.success){ closeEditModal(); loadCustomRules(); }
            else showToast('error','更新失败');
        });
    };

    window.deleteRule = function(id) {
        if(!confirm('确定删除此规则？')) return;
        fetch('/api/bot/rule/delete',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({id:id})
        }).then(r=>r.json()).then(d=>{
            if(d.success) loadCustomRules();
        });
    };

    window.toggleRule = function(id, enabled) {
        fetch('/api/bot/rule/toggle-enabled',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({id:id,enabled:enabled})
        }).then(r=>r.json()).then(d=>{
            if(!d.success) loadCustomRules();
        });
    };

    window.toggleSelectAll = function() {
        var checked = document.getElementById('selectAll').checked;
        document.querySelectorAll('.rule-cb').forEach(function(cb){ cb.checked=checked; });
        updateBatchButtons();
    };

    window.updateBatchButtons = function() {
        var cbs = document.querySelectorAll('.rule-cb:checked');
        var n = cbs.length;
        document.getElementById('batchDeleteBtn').disabled = n===0;
        document.getElementById('batchEnableBtn').disabled = n===0;
        document.getElementById('batchDisableBtn').disabled = n===0;
    };

    function getSelectedIds() {
        return Array.from(document.querySelectorAll('.rule-cb:checked')).map(function(cb){return parseInt(cb.dataset.id);});
    }

    window.batchDelete = function() {
        var ids = getSelectedIds();
        if(ids.length===0) return;
        if(!confirm('确定删除选中的'+ids.length+'条规则？')) return;
        fetch('/api/bot/rule/batch-delete',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({ids:ids})
        }).then(r=>r.json()).then(d=>{ if(d.success) loadCustomRules(); });
    };

    window.batchToggle = function(enabled) {
        var ids = getSelectedIds();
        if(ids.length===0) return;
        fetch('/api/bot/rule/batch-toggle-enabled',{
            method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
            body:JSON.stringify({ids:ids,enabled:enabled})
        }).then(r=>r.json()).then(d=>{ if(d.success) loadCustomRules(); });
    };

    window.testClassify = function() {
        var ua = document.getElementById('testUA').value;
        if(!ua){ showToast('error','请输入UA'); return; }
        var params = 'ua='+encodeURIComponent(ua);
        if(document.getElementById('testCookies').checked) params+='&cookies=1';
        if(document.getElementById('testReferer').checked) params+='&referer=1';
        if(document.getElementById('testAcceptLang').checked) params+='&accept_lang=1';
        fetch('/api/bot/classify?'+params).then(r=>r.json()).then(resp=>{
            var d = resp.data || {};
            var result = document.getElementById('testResult');
            result.className = 'test-result show';
            result.innerHTML = '<div class="tr-header"><span class="tr-badge '+(d.is_bot?'bot-'+d.action:'human')+'">'+(d.is_bot?'Bot: '+policyLabels[d.action]||d.action:'人类')+'</span><span class="tr-cat-tag '+(categoryTags[d.category]||'')+'">'+(categoryLabels[d.category]||d.category||'')+'</span></div>'+
                '<div class="tr-body"><div class="tr-item"><div class="tr-label">置信度</div><div class="tr-val">'+((d.confidence||0)*100).toFixed(1)+'%</div></div></div>'+
                (d.reason?'<div class="tr-reason"><strong>原因:</strong> '+escapeHtml(d.reason)+'</div>':'');
        });
    };

    loadStats();
    loadKnownBots();
    loadCustomRules();
    setInterval(loadStats, 15000);
})();
