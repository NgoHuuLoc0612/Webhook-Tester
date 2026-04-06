/* ═══════════════════════════════════════════════════════
   WEBHOOK TESTER v3 — Enterprise JS
   Realtime SSE · Advanced charts · Security · API Keys
═══════════════════════════════════════════════════════ */
'use strict';

// ─── STATE ────────────────────────────────────────────────────────────────────
const S = {
  endpoints: [],
  activeEp: null,
  activeReq: null,
  requests: [],
  sseSource: null,
  charts: {},
  sseCount: 0,
  liveEntries: [],
  liveRpm: [],        // timestamps for rpm calculation
  liveBlocked: 0,
  liveThreats: 0,
  liveActivityData: Array(60).fill(0), // 60s rolling window
  currentView: 'Dashboard',
  modalEpId: null,
  modalReqData: null,
  epTab: 'basic',
  reqTabModal: 'overview',
  filterDebounce: null,
  darkTheme: true,
};

// ─── API ──────────────────────────────────────────────────────────────────────
const Api = {
  async req(method, path, body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json', Accept: 'application/json' } };
    if (body !== null) opts.body = JSON.stringify(body);
    const res = await fetch('/api' + path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  get:  p       => Api.req('GET', p),
  post: (p, b)  => Api.req('POST', p, b),
  put:  (p, b)  => Api.req('PUT', p, b),
  del:  p       => Api.req('DELETE', p),
};

// ─── TOAST ────────────────────────────────────────────────────────────────────
const Toast = {
  show(msg, type = 'info', dur = 3200) {
    const el = Object.assign(document.createElement('div'), { className: `toast ${type}`, textContent: msg });
    document.getElementById('toasts').prepend(el);
    setTimeout(() => el.remove(), dur);
  },
  ok:   m => Toast.show(m, 'ok'),
  err:  m => Toast.show(m, 'err', 5000),
  info: m => Toast.show(m, 'info'),
  warn: m => Toast.show(m, 'warn'),
};

// ─── UTILS ────────────────────────────────────────────────────────────────────
const U = {
  bytes(n) {
    if (!n) return '0 B';
    const u = ['B','KB','MB','GB'], i = Math.floor(Math.log(n) / Math.log(1024));
    return (n / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
  },
  time(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  },
  timeFull(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString('en', { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },
  rel(iso) {
    if (!iso) return '—';
    const d = Date.now() - new Date(iso).getTime();
    if (d < 5000) return 'just now';
    if (d < 60000) return Math.round(d/1000) + 's ago';
    if (d < 3600000) return Math.round(d/60000) + 'm ago';
    if (d < 86400000) return Math.round(d/3600000) + 'h ago';
    return Math.round(d/86400000) + 'd ago';
  },
  mBadge(m) {
    return `<span class="method-badge m-${m || 'GET'}">${m || 'GET'}</span>`;
  },
  copy(text, msg = 'Copied!') {
    const fallback = () => {
      try {
        const ta = document.createElement('textarea');
        ta.value = String(text);
        ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;pointer-events:none';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? Toast.ok(msg) : Toast.warn('Press Ctrl+C to copy manually');
      } catch (e) {
        Toast.warn('Press Ctrl+C to copy manually');
      }
    };
    try {
      if (navigator && navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
        navigator.clipboard.writeText(String(text)).then(() => Toast.ok(msg)).catch(fallback);
      } else {
        fallback();
      }
    } catch (e) {
      fallback();
    }
  },
  esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); },
  json(obj) {
    const s = JSON.stringify(obj, null, 2);
    return s
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")\s*:/g, '<span class="json-key">$1</span>:')
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")/g, '<span class="json-string">$1</span>')
      .replace(/\b(\d+\.?\d*)\b/g, '<span class="json-number">$1</span>')
      .replace(/\b(true|false)\b/g, '<span class="json-bool">$1</span>')
      .replace(/\bnull\b/g, '<span class="json-null">null</span>');
  },
  threatColor(score) {
    if (score === 0) return '#10b981';
    if (score < 25) return '#38bdf8';
    if (score < 50) return '#f59e0b';
    if (score < 75) return '#f97316';
    return '#ef4444';
  },
  threatLabel(score) {
    if (score === 0) return 'Clean';
    if (score < 25) return 'Low';
    if (score < 50) return 'Medium';
    if (score < 75) return 'High';
    return 'Critical';
  },
  statusClass(code) {
    if (code >= 500) return 's5xx';
    if (code >= 400) return 's4xx';
    if (code >= 300) return 's3xx';
    return 's2xx';
  },
};

// ─── CHART ENGINE ─────────────────────────────────────────────────────────────
const CH = {
  pal: ['#6366f1','#10b981','#f59e0b','#ef4444','#38bdf8','#a855f7','#f97316','#ec4899','#14b8a6'],
  base: {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor:'#1a2030', titleColor:'#94a3b8', bodyColor:'#f1f5f9', borderColor:'#2a3450', borderWidth:1 },
    },
  },
  scaleOpts: {
    x: { ticks: { color:'#475569', font: { family:"'JetBrains Mono'", size:10 }, maxRotation:0 }, grid: { color:'#1f2535' } },
    y: { ticks: { color:'#475569', font: { family:"'JetBrains Mono'", size:10 } }, grid: { color:'#1f2535' } },
  },

  make(id, type, data, extra = {}) {
    const el = document.getElementById(id);
    if (!el) return;
    if (S.charts[id]) { S.charts[id].destroy(); delete S.charts[id]; }
    S.charts[id] = new Chart(el, { type, data, options: { ...CH.base, ...extra } });
    return S.charts[id];
  },

  hourly(rows) {
    const hrs = Array.from({length:24}, (_,i) => String(i).padStart(2,'0'));
    const map = {}; rows.forEach(r => { map[r.hour] = +r.count; });
    CH.make('chartHourly','bar',{
      labels: hrs.map(h=>h+':00'),
      datasets: [{ data: hrs.map(h=>map[h]||0), backgroundColor:'#6366f135', borderColor:'#6366f1', borderWidth:1, borderRadius:3 }],
    },{ scales: CH.scaleOpts });
  },

  methods(rows) {
    CH.make('chartMethods','doughnut',{
      labels: rows.map(r=>r.method),
      datasets: [{ data: rows.map(r=>+r.count), backgroundColor: CH.pal.map(c=>c+'99'), borderColor: CH.pal, borderWidth:1 }],
    },{ cutout:'65%', plugins:{ legend:{ display:true, position:'right', labels:{ color:'#94a3b8', font:{family:"'JetBrains Mono'",size:10}, boxWidth:10, padding:6 }}, tooltip: CH.base.plugins.tooltip }});
  },

  weekly(rows) {
    CH.make('chartWeekly','bar',{
      labels: rows.map(r=>r.day),
      datasets: [
        { label:'Requests', data: rows.map(r=>+r.total||0), backgroundColor:'#6366f135', borderColor:'#6366f1', borderWidth:1, borderRadius:3 },
        { label:'Blocked',  data: rows.map(r=>+r.blocked||0), backgroundColor:'#ef444430', borderColor:'#ef4444', borderWidth:1, borderRadius:3 },
      ],
    },{ scales: CH.scaleOpts, plugins:{ legend:{ display:false }, tooltip: CH.base.plugins.tooltip }});
  },

  content(rows) {
    CH.make('chartContent','bar',{
      labels: rows.map(r=>r.content_type.split('/').pop().split(';')[0]),
      datasets: [{ data: rows.map(r=>+r.count), backgroundColor: CH.pal.map(c=>c+'80'), borderColor: CH.pal, borderWidth:1, borderRadius:3 }],
    },{ indexAxis:'y', scales: CH.scaleOpts });
  },

  sizes(rows) {
    CH.make('chartSizes','polarArea',{
      labels: rows.map(r=>r.range),
      datasets: [{ data: rows.map(r=>+r.count), backgroundColor: CH.pal.map(c=>c+'70'), borderColor: CH.pal, borderWidth:1 }],
    },{ plugins:{ legend:{ display:true, position:'right', labels:{ color:'#94a3b8', font:{family:"'JetBrains Mono'",size:10}, boxWidth:10 }}, tooltip: CH.base.plugins.tooltip }});
  },

  duration(rows) {
    CH.make('chartDuration','line',{
      labels: rows.map(r=>r.day),
      datasets: [{ data: rows.map(r=>+r.avg_ms||0), borderColor:'#10b981', backgroundColor:'#10b98118', fill:true, tension:.4, pointRadius:3, pointBackgroundColor:'#10b981' }],
    },{ scales: CH.scaleOpts });
  },

  secTypes(rows) {
    CH.make('chartSecTypes','doughnut',{
      labels: rows.map(r=>r.event_type.replace(/_/g,' ')),
      datasets: [{ data: rows.map(r=>+r.count), backgroundColor:['#ef444499','#f59e0b99','#a855f799','#38bdf899','#f9731699','#10b98199'], borderColor:['#ef4444','#f59e0b','#a855f7','#38bdf8','#f97316','#10b981'], borderWidth:1 }],
    },{ cutout:'60%', plugins:{ legend:{ display:true, position:'right', labels:{ color:'#94a3b8', font:{family:"'JetBrains Mono'",size:10}, boxWidth:10 }}, tooltip: CH.base.plugins.tooltip }});
  },

  secTimeline(rows) {
    CH.make('chartSecTimeline','line',{
      labels: rows.map(r=>r.hour+':00'),
      datasets: [{ data: rows.map(r=>+r.count), borderColor:'#ef4444', backgroundColor:'#ef444418', fill:true, tension:.4, pointRadius:3, pointBackgroundColor:'#ef4444' }],
    },{ scales: CH.scaleOpts });
  },

  liveActivity() {
    const el = document.getElementById('chartLiveActivity');
    if (!el) return;
    if (S.charts['liveAct']) { S.charts['liveAct'].destroy(); }
    S.charts['liveAct'] = new Chart(el, {
      type:'bar',
      data:{ labels: Array.from({length:60},(_,i)=>i), datasets:[{
        data: S.liveActivityData,
        backgroundColor:'#6366f135', borderColor:'#6366f155', borderWidth:1, borderRadius:2,
      }]},
      options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{display:false}, tooltip:{enabled:false} }, scales:{ x:{display:false}, y:{display:false} }, animation:{duration:200} },
    });
  },

  updateLiveActivity() {
    const chart = S.charts['liveAct'];
    if (!chart) return;
    chart.data.datasets[0].data = [...S.liveActivityData];
    chart.update('none');
  },
};

// ─── SSE ──────────────────────────────────────────────────────────────────────
const Sse = {
  connect(epId = null) {
    Sse.disconnect();
    const url = '/api/stream' + (epId ? `?endpoint_id=${epId}` : '');
    const es = new EventSource(url);
    S.sseSource = es;

    es.addEventListener('connected', () => {
      document.getElementById('sseDot').className = 'sse-dot online';
      document.getElementById('sseLabel').textContent = 'Live';
    });

    es.addEventListener('request', e => {
      const req = JSON.parse(e.data);
      S.sseCount++;
      document.getElementById('sseCount').textContent = S.sseCount;
      Sse.handleIncoming(req);
    });

    es.onerror = () => {
      document.getElementById('sseDot').className = 'sse-dot connecting';
      document.getElementById('sseLabel').textContent = 'Reconnecting…';
      setTimeout(() => Sse.connect(epId), 3500);
    };
  },

  disconnect() {
    if (S.sseSource) { S.sseSource.close(); S.sseSource = null; }
    document.getElementById('sseDot').className = 'sse-dot offline';
    document.getElementById('sseLabel').textContent = 'Disconnected';
  },

  handleIncoming(req) {
    // Update endpoint counter in sidebar
    const ep = S.endpoints.find(e => e.id === req.endpoint_id);
    if (ep) {
      ep.request_count = (ep.request_count || 0) + 1;
      ep.last_hit_at = req.created_at;
      if (req.is_blocked) ep.blocked_count = (ep.blocked_count || 0) + 1;
    }
    UI.renderEpList();

    // Update active endpoint request list
    if (S.activeEp?.id === req.endpoint_id) {
      req.headers = typeof req.headers === 'string' ? JSON.parse(req.headers) : req.headers;
      req.tags    = typeof req.tags === 'string' ? JSON.parse(req.tags) : (req.tags || []);
      S.requests.unshift(req);
      UI.renderReqList();

      // Update ep kpis
      S.activeEp.request_count++;
      if (req.is_blocked) S.activeEp.blocked_count++;
      UI.renderEpKpis(S.activeEp);
    }

    // Live feed
    LiveFeed.append(req);

    // Activity chart
    S.liveActivityData.shift();
    S.liveActivityData.push((S.liveActivityData[S.liveActivityData.length-1]||0) + 1);
    // Actually, increment the last bucket
    S.liveActivityData[S.liveActivityData.length - 1] = (S.liveActivityData[S.liveActivityData.length - 1] || 0) + 1;
    CH.updateLiveActivity();

    // RPM tracking
    const now = Date.now();
    S.liveRpm.push(now);
    S.liveRpm = S.liveRpm.filter(t => now - t < 60000);
    document.getElementById('lsRpm').textContent = S.liveRpm.length;
    document.getElementById('lsTotal').textContent = S.sseCount;
    if (req.is_blocked) { S.liveBlocked++; document.getElementById('lsBlocked').textContent = S.liveBlocked; }
    if (req.threat_score > 0) { S.liveThreats++; document.getElementById('lsThreats').textContent = S.liveThreats; }
  },
};

// ─── LIVE FEED ────────────────────────────────────────────────────────────────
const LiveFeed = {
  append(req) {
    S.liveEntries.unshift(req);
    if (S.liveEntries.length > 300) S.liveEntries.pop();

    if (S.currentView !== 'Live') return;
    LiveFeed.renderEntry(req, true);
  },

  renderEntry(req, prepend = false) {
    const epFilter = document.getElementById('liveFilter').value;
    if (epFilter && req.endpoint_id !== epFilter) return;

    const ep = S.endpoints.find(e => e.id === req.endpoint_id) || {};
    const color = req.endpoint_color || ep.color || '#6366f1';
    const name  = req.endpoint_name  || ep.name  || 'Endpoint';

    const el = document.createElement('div');
    el.className = `live-entry ${req.is_blocked ? 'blocked' : ''} ${req.threat_score > 0 ? 'threat' : ''}`;
    el.dataset.id = req.id;
    el.innerHTML = `
      <div>${U.mBadge(req.method)}</div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:3px">
          <span class="live-ep-tag" style="border-color:${color}">${name}</span>
          <span class="live-path">${U.esc(req.path || '/')}</span>
        </div>
        <div class="live-meta">
          <span>${req.ip || '—'}</span>
          <span>${U.bytes(req.body_size)}</span>
          ${req.duration_ms ? `<span>${req.duration_ms.toFixed(1)}ms</span>` : ''}
          ${req.threat_score > 0 ? `<span style="color:#f59e0b">⚠ score:${req.threat_score}</span>` : ''}
          ${req.is_blocked ? `<span style="color:#ef4444">🚫 ${req.block_reason}</span>` : ''}
        </div>
      </div>
      <span class="live-time">${U.time(req.created_at)}</span>
    `;
    el.addEventListener('click', () => Modal.openReq(req.id));

    const feed = document.getElementById('liveFeed');
    if (prepend) {
      feed.insertBefore(el, feed.firstChild);
      if (document.getElementById('chkScroll').checked) feed.scrollTop = 0;
    } else {
      feed.appendChild(el);
    }
  },

  render() {
    document.getElementById('liveFeed').innerHTML = '';
    S.liveEntries.forEach(r => LiveFeed.renderEntry(r, false));
  },
};

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
const Dash = {
  async load() {
    try {
      const { data } = await Api.get('/endpoints/stats');
      Dash.renderKpis(data.totals);
      CH.hourly(data.requests_last_24h || []);
      CH.methods(data.method_distribution || []);
      CH.weekly(data.requests_last_7_days || []);
      CH.content(data.content_types || []);
      CH.sizes(data.size_distribution || []);
      CH.duration(data.duration_trend || []);
      Dash.renderTopEps(data.top_endpoints || []);
      document.getElementById('reqRateLabel').textContent = `${(data.requests_last_24h||[]).reduce((a,r)=>a+(+r.count||0),0)} in 24h`;
    } catch(e) { Toast.err('Dashboard load failed: ' + e.message); }
  },

  renderKpis(t = {}) {
    const kpis = [
      { label:'Endpoints', value: t.endpoints ?? 0, sub:'Active listeners', icon:'📡', stripe:'linear-gradient(90deg,#6366f1,#818cf8)' },
      { label:'Total Requests', value: (t.requests ?? 0).toLocaleString(), sub:'All time', icon:'📨', stripe:'linear-gradient(90deg,#10b981,#34d399)' },
      { label:'Blocked', value: (t.blocked ?? 0).toLocaleString(), sub:'Security blocks', icon:'🚫', stripe:'linear-gradient(90deg,#ef4444,#f87171)' },
      { label:'Block Rate', value: (t.block_rate ?? 0) + '%', sub:'Of total requests', icon:'🛡', stripe:'linear-gradient(90deg,#f97316,#fb923c)' },
      { label:'Data Captured', value: U.bytes(t.bytes ?? 0), sub:'Total payload', icon:'💾', stripe:'linear-gradient(90deg,#38bdf8,#7dd3fc)' },
      { label:'Avg Duration', value: t.avg_duration_ms ? t.avg_duration_ms.toFixed(1)+'ms' : '—', sub:'Processing time', icon:'⏱', stripe:'linear-gradient(90deg,#a855f7,#c084fc)' },
    ];
    document.getElementById('kpiRow').innerHTML = kpis.map(k => `
      <div class="kpi" style="--stripe:${k.stripe}">
        <div class="kpi-label">${k.label}</div>
        <div class="kpi-value">${k.value}</div>
        <div class="kpi-sub">${k.sub}</div>
        <div class="kpi-icon">${k.icon}</div>
      </div>
    `).join('');
  },

  renderTopEps(rows) {
    const tbody = document.querySelector('#topEpTable tbody');
    if (!rows.length) { tbody.innerHTML = '<tr><td colspan="6" style="color:var(--txt3);text-align:center;padding:20px">No data</td></tr>'; return; }
    tbody.innerHTML = rows.map(r => {
      const rate = r.request_count > 0 ? Math.round(r.blocked_count / r.request_count * 100) : 0;
      return `<tr style="cursor:pointer" onclick="App.selectEp('${r.id}')">
        <td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${r.color};margin-right:7px"></span>${U.esc(r.name)}</td>
        <td class="mono">${(r.request_count||0).toLocaleString()}</td>
        <td class="mono">${(r.blocked_count||0).toLocaleString()}</td>
        <td><div class="progress-bar" style="width:80px"><div class="progress-fill" style="width:${rate}%;background:${rate>20?'#ef4444':rate>5?'#f59e0b':'#10b981'}"></div></div> <span class="mono" style="font-size:10px">${rate}%</span></td>
        <td class="mono">${U.bytes(r.byte_count||0)}</td>
        <td class="mono">${U.rel(r.last_hit_at)}</td>
      </tr>`;
    }).join('');
  },
};

// ─── SECURITY VIEW ────────────────────────────────────────────────────────────
const SecView = {
  async load() {
    try {
      const { data } = await Api.get('/security/stats');
      SecView.renderKpis(data);
      CH.secTypes(data.byType || []);
      CH.secTimeline(data.timeline || []);
      SecView.renderTopAttackers(data.topAttackers || []);
      // Recent events from global — load from first endpoint or global
      SecView.renderRecentEvents([]);
    } catch(e) { Toast.err('Security load failed: ' + e.message); }
  },

  renderKpis(data) {
    const kpis = [
      { label:'Events (24h)', value: data.total24h || 0, stripe:'linear-gradient(90deg,#ef4444,#f87171)', icon:'🔴' },
      { label:'Events (7d)',   value: data.total7d  || 0, stripe:'linear-gradient(90deg,#f97316,#fb923c)', icon:'🟠' },
      { label:'Top Type',     value: data.byType?.[0]?.event_type?.replace(/_/g,' ') || '—', stripe:'linear-gradient(90deg,#a855f7,#c084fc)', icon:'⚠' },
      { label:'Top Attacker', value: data.topAttackers?.[0]?.ip || '—', stripe:'linear-gradient(90deg,#38bdf8,#7dd3fc)', icon:'🎯' },
    ];
    document.getElementById('secKpiRow').innerHTML = kpis.map(k => `
      <div class="kpi" style="--stripe:${k.stripe};grid-column:span 1">
        <div class="kpi-label">${k.label}</div>
        <div class="kpi-value" style="font-size:18px">${k.value}</div>
        <div class="kpi-icon">${k.icon}</div>
      </div>
    `).join('');
    // Adjust grid
    document.getElementById('secKpiRow').style.gridTemplateColumns = 'repeat(4,1fr)';
  },

  renderTopAttackers(rows) {
    const tb = document.querySelector('#topAttackersTable tbody');
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="3" style="color:var(--txt3);text-align:center;padding:16px">No threats detected</td></tr>'; return; }
    tb.innerHTML = rows.map(r => {
      const risk = r.count > 50 ? 'Critical' : r.count > 20 ? 'High' : r.count > 5 ? 'Medium' : 'Low';
      const color = r.count > 50 ? '#ef4444' : r.count > 20 ? '#f97316' : r.count > 5 ? '#f59e0b' : '#38bdf8';
      return `<tr><td class="mono">${r.ip}</td><td class="mono">${r.count}</td><td><span style="font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:3px;background:${color}20;color:${color};border:1px solid ${color}40">${risk}</span></td></tr>`;
    }).join('');
  },

  renderRecentEvents(events) {
    const el = document.getElementById('secEventFeed');
    if (!events.length) { el.innerHTML = '<div style="padding:20px;color:var(--txt3);text-align:center;font-size:12px">No recent events</div>'; return; }
    el.innerHTML = events.map(e => `
      <div class="sec-event-item">
        <span class="sec-event-type evt-${e.event_type}">${e.event_type.replace(/_/g,' ')}</span>
        <div class="sec-event-body">
          <span class="sec-event-ip">${e.ip || '—'}</span>
          <span style="color:var(--txt3);font-size:10px;font-family:var(--mono)"> · ${JSON.stringify(JSON.parse(e.details||'{}'))}</span>
        </div>
        <span class="sec-event-time">${U.time(e.created_at)}</span>
      </div>
    `).join('');
  },
};

// ─── API KEYS VIEW ────────────────────────────────────────────────────────────
const KeysView = {
  async load() {
    try {
      const { data } = await Api.get('/keys');
      KeysView.render(data || []);
    } catch(e) { Toast.err('Failed to load keys: ' + e.message); }
  },

  render(keys) {
    const tb = document.querySelector('#apiKeysTable tbody');
    if (!keys.length) { tb.innerHTML = '<tr><td colspan="6" style="color:var(--txt3);text-align:center;padding:20px">No API keys. Create one to get started.</td></tr>'; return; }
    tb.innerHTML = keys.map(k => `
      <tr>
        <td>${U.esc(k.name)}</td>
        <td class="mono">${k.key_prefix}…</td>
        <td class="mono">${(JSON.parse(k.permissions||'[]')).join(', ')}</td>
        <td class="mono">${U.rel(k.created_at)}</td>
        <td class="mono">${k.last_used_at ? U.rel(k.last_used_at) : 'Never'}</td>
        <td><button class="btn btn-xs btn-danger" onclick="KeysView.delete('${k.id}')">Delete</button></td>
      </tr>
    `).join('');
  },

  async delete(id) {
    if (!confirm('Delete this API key?')) return;
    try { await Api.del('/keys/' + id); Toast.ok('Key deleted'); KeysView.load(); } catch(e) { Toast.err(e.message); }
  },
};

// ─── ENDPOINT MODAL ────────────────────────────────────────────────────────────
const EpModal = {
  currentTab: 'basic',
  data: {},

  open(ep = null) {
    S.modalEpId = ep?.id || null;
    EpModal.data = ep ? { ...ep } : {
      name:'', description:'', color:'#6366f1',
      response_status:200, response_body:'', response_headers:{}, response_delay_ms:0, response_mode:'static', forward_url:'',
      secret_key:'', allowed_ips:[], blocked_ips:[], require_signature:0, signature_header:'X-Hub-Signature-256', signature_algo:'sha256',
      allowed_methods:[], require_auth:0, auth_type:'bearer', auth_value:'',
      expires_at:'', max_requests:0,
    };
    document.getElementById('modalEpTitle').textContent = ep ? 'Edit Endpoint' : 'New Endpoint';
    EpModal.switchTab('basic');
    Modal.open('modalEp');
  },

  switchTab(tab) {
    EpModal.currentTab = tab;
    document.querySelectorAll('.mtab').forEach(t => t.classList.toggle('active', t.dataset.mtab === tab));
    const d = EpModal.data;

    const tabs = {
      basic: () => `
        <div class="fg"><label>Name *</label><input class="fi" id="fName" value="${U.esc(d.name||'')}"></div>
        <div class="fg"><label>Description</label><input class="fi" id="fDesc" value="${U.esc(d.description||'')}"></div>
        <div class="fg-row">
          <div class="fg"><label>Color</label><input type="color" class="fi" id="fColor" value="${d.color||'#6366f1'}"></div>
        </div>
      `,
      response: () => `
        <div class="fg-row">
          <div class="fg"><label>Response Status</label>
            <select class="fi" id="fStatus">
              ${[200,201,204,400,401,403,404,422,500,502,503].map(s=>`<option value="${s}" ${d.response_status==s?'selected':''}>${s}</option>`).join('')}
            </select>
          </div>
          <div class="fg"><label>Delay (ms)</label><input type="number" class="fi" id="fDelay" value="${d.response_delay_ms||0}" min="0" max="30000"></div>
        </div>
        <div class="fg"><label>Response Mode</label>
          <select class="fi" id="fMode">
            <option value="static" ${d.response_mode==='static'?'selected':''}>Static — return custom body</option>
            <option value="forward" ${d.response_mode==='forward'?'selected':''}>Forward — proxy to URL</option>
          </select>
        </div>
        <div class="fg" id="fgFwd" ${d.response_mode!=='forward'?'style="display:none"':''}>
          <label>Forward URL</label><input class="fi" id="fFwd" value="${U.esc(d.forward_url||'')}">
        </div>
        <div class="fg"><label>Response Body (JSON / text)</label><textarea class="fi fi-mono" id="fBody" rows="4">${U.esc(d.response_body||'')}</textarea></div>
        <div class="fg"><label>Response Headers (JSON object)</label><textarea class="fi fi-mono" id="fHeaders" rows="3">${U.esc(JSON.stringify(d.response_headers||{},null,2))}</textarea></div>
      `,
      security: () => `
        <div class="sec-section">
          <span class="sec-section-title">🔐 Authentication</span>
          <div class="fg"><label><input type="checkbox" id="fAuth" ${d.require_auth?'checked':''}> Require Authentication</label></div>
          <div class="fg-row">
            <div class="fg"><label>Auth Type</label>
              <select class="fi" id="fAuthType">
                <option value="bearer" ${d.auth_type==='bearer'?'selected':''}>Bearer Token</option>
                <option value="api-key" ${d.auth_type==='api-key'?'selected':''}>API Key Header</option>
                <option value="basic" ${d.auth_type==='basic'?'selected':''}>Basic (user:pass)</option>
              </select>
            </div>
            <div class="fg"><label>Auth Value</label><input class="fi fi-mono" id="fAuthVal" value="${U.esc(d.auth_value||'')}" placeholder="Token / key / user:pass"></div>
          </div>
        </div>
        <div class="sec-section">
          <span class="sec-section-title">✍ Signature Verification</span>
          <div class="fg"><label><input type="checkbox" id="fSig" ${d.require_signature?'checked':''}> Require HMAC Signature</label></div>
          <div class="fg-row">
            <div class="fg"><label>Secret Key</label><input class="fi fi-mono" id="fSecret" value="${U.esc(d.secret_key||'')}" placeholder="your-webhook-secret"></div>
            <div class="fg"><label>Algorithm</label>
              <select class="fi" id="fSigAlgo">
                <option value="sha256" ${d.signature_algo==='sha256'?'selected':''}>SHA-256</option>
                <option value="sha1" ${d.signature_algo==='sha1'?'selected':''}>SHA-1</option>
                <option value="sha512" ${d.signature_algo==='sha512'?'selected':''}>SHA-512</option>
              </select>
            </div>
          </div>
          <div class="fg"><label>Signature Header</label><input class="fi fi-mono" id="fSigHdr" value="${U.esc(d.signature_header||'X-Hub-Signature-256')}"></div>
        </div>
        <div class="sec-section">
          <span class="sec-section-title">🌐 IP Filtering</span>
          <div class="fg"><label>Allowed IPs / CIDRs (one per line, empty = allow all)</label>
            <textarea class="fi fi-mono" id="fAllowedIps" rows="3" placeholder="192.168.1.0/24&#10;10.0.0.1">${(d.allowed_ips||[]).join('\n')}</textarea>
          </div>
          <div class="fg"><label>Blocked IPs / CIDRs (one per line)</label>
            <textarea class="fi fi-mono" id="fBlockedIps" rows="3" placeholder="1.2.3.4&#10;5.6.7.0/24">${(d.blocked_ips||[]).join('\n')}</textarea>
          </div>
        </div>
        <div class="sec-section">
          <span class="sec-section-title">📋 Method Filter</span>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            ${['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(m=>`
              <label class="toggle"><input type="checkbox" name="methods" value="${m}" ${(d.allowed_methods||[]).includes(m)?'checked':''}> ${m}</label>
            `).join('')}
          </div>
          <div class="fg-help" style="margin-top:6px">Leave all unchecked to allow all methods</div>
        </div>
      `,
      limits: () => `
        <div class="fg"><label>Max Requests (0 = unlimited)</label><input type="number" class="fi" id="fMaxReq" value="${d.max_requests||0}" min="0"></div>
        <div class="fg"><label>Expires At (leave empty = never)</label><input type="datetime-local" class="fi" id="fExpires" value="${d.expires_at ? d.expires_at.replace('Z','') : ''}"></div>
        <div class="fg-help">After expiry or max requests reached, the endpoint returns 410 Gone.</div>
      `,
    };

    document.getElementById('modalEpContent').innerHTML = tabs[tab]?.() || '';

    // Mode toggle
    const modeEl = document.getElementById('fMode');
    if (modeEl) modeEl.addEventListener('change', () => {
      const fg = document.getElementById('fgFwd');
      if (fg) fg.style.display = modeEl.value === 'forward' ? '' : 'none';
    });
  },

  collect() {
    const get = id => document.getElementById(id);
    const vals = () => ({
      name: get('fName')?.value.trim() || '',
      description: get('fDesc')?.value.trim() || '',
      color: get('fColor')?.value || '#6366f1',
      response_status: +(get('fStatus')?.value || 200),
      response_delay_ms: +(get('fDelay')?.value || 0),
      response_mode: get('fMode')?.value || 'static',
      forward_url: get('fFwd')?.value.trim() || '',
      response_body: get('fBody')?.value || '',
      response_headers: (() => { try { return JSON.parse(get('fHeaders')?.value || '{}'); } catch { return {}; }})(),
      secret_key: get('fSecret')?.value || '',
      require_signature: get('fSig')?.checked ? 1 : 0,
      signature_algo: get('fSigAlgo')?.value || 'sha256',
      signature_header: get('fSigHdr')?.value || 'X-Hub-Signature-256',
      require_auth: get('fAuth')?.checked ? 1 : 0,
      auth_type: get('fAuthType')?.value || 'bearer',
      auth_value: get('fAuthVal')?.value || '',
      allowed_ips: (get('fAllowedIps')?.value || '').split('\n').map(s=>s.trim()).filter(Boolean),
      blocked_ips: (get('fBlockedIps')?.value || '').split('\n').map(s=>s.trim()).filter(Boolean),
      allowed_methods: [...(document.querySelectorAll('input[name="methods"]:checked') || [])].map(el=>el.value),
      max_requests: +(get('fMaxReq')?.value || 0),
      expires_at: get('fExpires')?.value ? get('fExpires').value + ':00Z' : '',
    });
    return { ...EpModal.data, ...vals() };
  },

  async save() {
    const payload = EpModal.collect();
    if (!payload.name) { Toast.err('Name is required'); return; }
    try {
      if (S.modalEpId) {
        const { data } = await Api.put('/endpoints/' + S.modalEpId, payload);
        const i = S.endpoints.findIndex(e => e.id === data.id);
        if (i >= 0) S.endpoints[i] = data;
        if (S.activeEp?.id === data.id) { S.activeEp = data; UI.renderEpHeader(data); }
        Toast.ok('Endpoint updated');
      } else {
        const { data } = await Api.post('/endpoints', payload);
        S.endpoints.unshift(data);
        Toast.ok('Endpoint created');
        App.selectEp(data.id);
      }
      UI.renderEpList();
      Modal.close('modalEp');
    } catch(e) { Toast.err('Save failed: ' + e.message); }
  },
};

// ─── REQUEST MODAL ─────────────────────────────────────────────────────────────
const Modal = {
  open(id) {
    document.getElementById('overlay').classList.remove('hidden');
    document.getElementById(id).classList.remove('hidden');
  },
  close(id) {
    document.getElementById(id)?.classList.add('hidden');
    const open = document.querySelectorAll('.modal:not(.hidden)');
    if (!open.length) document.getElementById('overlay').classList.add('hidden');
  },
  closeAll() {
    document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    document.getElementById('overlay').classList.add('hidden');
  },

  async openReq(id) {
    try {
      const { data, replay_history } = await Api.get('/requests/' + id);
      S.modalReqData = data;
      S.modalReqData._replays = replay_history || [];

      document.getElementById('rmMethod').className = `method-badge m-${data.method}`;
      document.getElementById('rmMethod').textContent = data.method;
      document.getElementById('rmPath').textContent = (data.path || '/') + (data.query_string ? '?' + data.query_string : '');

      const tp = document.getElementById('rmThreat');
      if (data.threat_score > 0) {
        tp.className = `threat-pill ${data.threat_score >= 50 ? 'threat-high-pill' : 'threat-low-pill'}`;
        tp.textContent = `⚠ Threat: ${U.threatLabel(data.threat_score)} (${data.threat_score})`;
        tp.classList.remove('hidden');
      } else { tp.classList.add('hidden'); }

      document.getElementById('btnRmStar').textContent = (data.is_starred ? '★' : '☆') + ' Star';
      Modal.switchReqTab('overview');
      Modal.open('modalReq');
    } catch(e) { Toast.err('Failed to load request: ' + e.message); }
  },

  switchReqTab(tab) {
    document.querySelectorAll('#modalReq .req-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    const r = S.modalReqData;
    if (!r) return;
    const el = document.getElementById('rmContent');

    switch (tab) {
      case 'overview': el.innerHTML = `
        <div class="ov-grid">
          <div class="ov-item"><div class="ov-lbl">Method</div><div class="ov-val">${r.method}</div></div>
          <div class="ov-item"><div class="ov-lbl">IP Address</div><div class="ov-val">${r.ip || '—'}</div></div>
          <div class="ov-item"><div class="ov-lbl">Duration</div><div class="ov-val">${r.duration_ms ? r.duration_ms.toFixed(2)+'ms' : '—'}</div></div>
          <div class="ov-item"><div class="ov-lbl">Body Size</div><div class="ov-val">${U.bytes(r.body_size)}</div></div>
          <div class="ov-item"><div class="ov-lbl">Content-Type</div><div class="ov-val">${r.content_type || 'none'}</div></div>
          <div class="ov-item"><div class="ov-lbl">Timestamp</div><div class="ov-val">${U.timeFull(r.created_at)}</div></div>
          <div class="ov-item"><div class="ov-lbl">Response</div><div class="ov-val ${U.statusClass(r.response_status)}">${r.response_status || '—'}</div></div>
          <div class="ov-item"><div class="ov-lbl">User Agent</div><div class="ov-val" style="font-size:10px;color:var(--txt3)">${U.esc(r.user_agent || '—')}</div></div>
        </div>
        ${r.query_string ? `<span class="stitle">Query Params</span><pre class="code-block">${U.esc(decodeURIComponent(r.query_string).replace(/&/g,'\n'))}</pre>` : ''}
        <div class="divider"></div>
        <span class="stitle">Tags</span>
        <div class="tags-row" id="tagsRow">
          ${(r.tags||[]).map(t=>`<span class="tag-pill" title="Click to remove" onclick="Modal.removeTag('${t}')">${U.esc(t)} ×</span>`).join('')}
          <span class="tag-pill tag-add" onclick="Modal.addTag()">+ Add tag</span>
        </div>
        <div class="divider"></div>
        <span class="stitle">Note</span>
        <textarea class="note-area" id="rmNote" rows="3" placeholder="Add a note…">${U.esc(r.note||'')}</textarea>
        <button class="btn btn-sm" style="margin-top:6px" onclick="Modal.saveNote()">Save Note</button>
      `; break;

      case 'headers': el.innerHTML = `
        <table class="kv-table">
          <thead><tr><th>Header</th><th>Value</th></tr></thead>
          <tbody>${Object.entries(r.headers||{}).map(([k,v])=>`<tr><td class="kv-k">${U.esc(k)}</td><td class="kv-v">${U.esc(v)}</td></tr>`).join('') || '<tr><td colspan="2" style="color:var(--txt3)">No headers</td></tr>'}</tbody>
        </table>
      `; break;

      case 'body':
        if (!r.body && !r.body_size) { el.innerHTML = '<div style="color:var(--txt3);padding:20px;text-align:center">No body</div>'; break; }
        let bodyHtml = '';
        if (r.body_format === 'json' && r.body_parsed) {
          bodyHtml = `<div style="display:flex;gap:6px;margin-bottom:8px"><span class="size-tag">JSON</span><span class="size-tag">${U.bytes(r.body_size)}</span><button class="btn btn-xs" data-copy-body="1">Copy</button></div><pre class="code-block json-tree" id="rawBodyText">${U.json(r.body_parsed)}</pre>`;
        } else if (r.body_format === 'form' && r.body_parsed) {
          bodyHtml = `<span class="size-tag">FORM</span><table class="kv-table" style="margin-top:8px"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${Object.entries(r.body_parsed).map(([k,v])=>`<tr><td class="kv-k">${U.esc(k)}</td><td class="kv-v">${U.esc(v)}</td></tr>`).join('')}</tbody></table>`;
        } else {
          bodyHtml = `<div style="display:flex;gap:6px;margin-bottom:8px"><span class="size-tag">${r.body_format?.toUpperCase()}</span><span class="size-tag">${U.bytes(r.body_size)}</span><button class="btn btn-xs" data-copy-body="1">Copy</button></div><pre class="code-block" id="rawBodyText">${U.esc((r.body||'').substring(0,20000))}</pre>`;
        }
        el.innerHTML = bodyHtml;
        // Attach copy handler after render
        const copyBtn = el.querySelector('[data-copy-body]');
        if (copyBtn) copyBtn.addEventListener('click', () => U.copy(r.body || '', 'Body copied'));
        break;

      case 'security': el.innerHTML = `
        <div class="threat-gauge">
          <span class="tg-label">${U.threatLabel(r.threat_score)}</span>
          <div class="tg-bar-wrap"><div class="tg-bar" style="width:${r.threat_score}%;background:${U.threatColor(r.threat_score)}"></div></div>
          <span class="tg-score" style="color:${U.threatColor(r.threat_score)}">${r.threat_score}</span>
        </div>
        <div class="ov-grid" style="margin-bottom:14px">
          <div class="ov-item"><div class="ov-lbl">Blocked</div><div class="ov-val" style="color:${r.is_blocked?'var(--red)':'var(--green)'}">${r.is_blocked ? '🚫 Yes' : '✅ No'}</div></div>
          <div class="ov-item"><div class="ov-lbl">Block Reason</div><div class="ov-val">${r.block_reason || '—'}</div></div>
          <div class="ov-item"><div class="ov-lbl">Signature</div><div class="ov-val">
            ${r.signature_valid===1 ? '<span class="sig-badge sig-valid">✓ Valid</span>' : r.signature_valid===0 ? '<span class="sig-badge sig-invalid">✗ Invalid</span>' : '<span class="sig-badge sig-unknown">— Not checked</span>'}
          </div></div>
          <div class="ov-item"><div class="ov-lbl">IP</div><div class="ov-val">${r.ip || '—'}</div></div>
        </div>
        <span class="stitle">Threat Analysis</span>
        <div class="code-block" style="font-size:11px">
Threat Score: ${r.threat_score}/100 — ${U.threatLabel(r.threat_score)}
IP Address:   ${r.ip || 'unknown'}
Method:       ${r.method}
Body Size:    ${U.bytes(r.body_size)}

${r.threat_score > 0 ? 'Suspicious patterns were detected in this request.' : 'No suspicious patterns detected.'}
${r.is_blocked ? `\n⛔ REQUEST WAS BLOCKED: ${r.block_reason}` : ''}
        </div>
      `; break;

      case 'replay': el.innerHTML = `
        <div style="margin-bottom:14px">
          <span class="stitle">Replay to custom URL</span>
          <div style="display:flex;gap:8px">
            <input class="fi fi-mono" id="replayUrl" placeholder="${U.esc(r.url)}" style="flex:1">
            <button class="btn btn-sm btn-primary" onclick="Modal.doReplay()">↺ Replay</button>
          </div>
          <div class="fg-help" style="margin-top:4px">Leave empty to replay to original URL</div>
        </div>
        <span class="stitle">History (${(r._replays||[]).length})</span>
        <div>
          ${(r._replays||[]).length ? r._replays.map(rp => `
            <div class="replay-item">
              <span class="replay-status rs-${rp.status_code >= 500 ? '5xx' : rp.status_code >= 400 ? '4xx' : rp.status_code >= 200 ? '2xx' : 'err'}">${rp.status_code || 'ERR'}</span>
              <span class="mono" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${U.esc(rp.target_url)}">${U.esc(rp.target_url)}</span>
              <span class="mono" style="color:var(--txt3)">${rp.duration_ms}ms</span>
              <span class="mono" style="color:var(--txt3);font-size:10px">${U.time(rp.created_at)}</span>
            </div>
          `).join('') : '<div style="color:var(--txt3);font-size:12px;padding:12px 0">No replay history yet</div>'}
        </div>
      `; break;

      case 'raw': el.innerHTML = `
        <pre class="code-block">${U.esc(r.method + ' ' + r.url + '\n\n' + Object.entries(r.headers||{}).map(([k,v])=>k+': '+v).join('\n') + '\n\n' + (r.body||''))}</pre>
      `; break;

      case 'code': el.innerHTML = `
        <span class="stitle">Select language to generate code</span>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
          ${['curl','httpie','python','node','php','go','json'].map(f=>`<button class="btn btn-sm btn-outline" onclick="window.open('/api/export/${r.id}?format=${f}','_blank')">${f}</button>`).join('')}
        </div>
        <span class="stitle">Quick preview — cURL</span>
        <pre class="code-block">curl -X ${r.method} \\
  '${U.esc(r.url)}' \\
${Object.entries(r.headers||{}).slice(0,6).map(([k,v])=>`  -H '${U.esc(k)}: ${U.esc(v)}' \\`).join('\n')}
  --data-raw '${U.esc((r.body||'').substring(0,500))}'</pre>
      `; break;
    }
  },

  async doReplay() {
    const url = document.getElementById('replayUrl')?.value.trim() || '';
    try {
      Toast.info('Replaying…');
      const result = await Api.post('/requests/' + S.modalReqData.id + '/replay', { target_url: url });
      Toast[result.success ? 'ok' : 'err'](`Replay: ${result.status_code || 'Error'} in ${result.duration_ms}ms`);
      Modal.switchReqTab('replay');
    } catch(e) { Toast.err('Replay failed: ' + e.message); }
  },

  async saveNote() {
    const note = document.getElementById('rmNote')?.value || '';
    try {
      await Api.post('/requests/' + S.modalReqData.id + '/note', { note });
      S.modalReqData.note = note;
      const req = S.requests.find(r => r.id === S.modalReqData.id);
      if (req) req.note = note;
      Toast.ok('Note saved');
    } catch(e) { Toast.err(e.message); }
  },

  async addTag() {
    const tag = prompt('New tag:');
    if (!tag?.trim()) return;
    const tags = [...(S.modalReqData.tags || []), tag.trim()];
    try {
      await Api.post('/requests/' + S.modalReqData.id + '/tags', { tags });
      S.modalReqData.tags = tags;
      Modal.switchReqTab('overview');
    } catch(e) { Toast.err(e.message); }
  },

  async removeTag(tag) {
    const tags = (S.modalReqData.tags || []).filter(t => t !== tag);
    try {
      await Api.post('/requests/' + S.modalReqData.id + '/tags', { tags });
      S.modalReqData.tags = tags;
      Modal.switchReqTab('overview');
    } catch(e) { Toast.err(e.message); }
  },
};

// ─── UI ───────────────────────────────────────────────────────────────────────
const UI = {
  renderEpList() {
    const search = document.getElementById('epSearch').value.toLowerCase();
    const list   = document.getElementById('epList');
    const eps    = S.endpoints.filter(e => e.name.toLowerCase().includes(search));

    if (!eps.length) {
      list.innerHTML = `<div style="padding:20px;text-align:center;color:var(--txt3);font-size:12px">No endpoints<br><button class="btn btn-sm btn-primary" style="margin-top:8px" onclick="EpModal.open()">+ Create one</button></div>`;
      return;
    }

    list.innerHTML = eps.map(ep => `
      <div class="ep-item ${S.activeEp?.id === ep.id ? 'active' : ''} ${ep.request_count > 0 ? 'has-hit' : ''}"
           data-id="${ep.id}" role="button" tabindex="0">
        <div class="ep-idot ${ep.is_paused ? '' : 'pulse'}" style="background:${ep.color};color:${ep.color}"></div>
        <div class="ep-ibody">
          <div class="ep-iname">${U.esc(ep.name)}</div>
          <div class="ep-imeta">${ep.token.slice(0,10)}… ${ep.is_paused ? '⏸' : ''}</div>
        </div>
        <span class="ep-icount">${ep.request_count.toLocaleString()}</span>
      </div>
    `).join('');

    list.querySelectorAll('.ep-item').forEach(el => {
      el.addEventListener('click', () => App.selectEp(el.dataset.id));
      el.addEventListener('keydown', e => { if (e.key === 'Enter') App.selectEp(el.dataset.id); });
    });
  },

  renderReqList() {
    const list = document.getElementById('reqList');
    document.getElementById('reqTotal').textContent = S.requests.length;
    if (!S.requests.length) {
      list.innerHTML = `<div class="empty-state" style="height:160px"><div class="empty-icon" style="font-size:28px">📭</div><p>No requests yet</p></div>`;
      return;
    }
    list.innerHTML = S.requests.map(r => {
      const classes = [
        'req-item',
        S.activeReq?.id === r.id ? 'active' : '',
        r.is_blocked ? 'blocked' : '',
        r.threat_score > 0 && !r.is_blocked ? 'threatened' : '',
      ].filter(Boolean).join(' ');
      return `
        <div class="${classes}" data-id="${r.id}">
          <div class="req-item-left">
            ${U.mBadge(r.method)}
            ${r.is_starred ? '<span style="font-size:11px;color:#f59e0b">★</span>' : ''}
          </div>
          <div class="req-item-body">
            <div class="req-item-path" title="${U.esc(r.url)}">${U.esc(r.path || '/')}</div>
            <div class="req-item-meta">
              <span>${U.time(r.created_at)}</span>
              <span>${U.bytes(r.body_size)}</span>
              ${r.threat_score > 0 ? `<span class="req-item-threat ${r.threat_score >= 50 ? 'threat-high' : 'threat-low'}">⚠${r.threat_score}</span>` : ''}
              ${r.is_blocked ? '<span style="color:var(--red);font-size:9px">🚫</span>' : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');

    list.querySelectorAll('.req-item').forEach(el => {
      el.addEventListener('click', () => App.selectReq(el.dataset.id));
    });
  },

  renderReqDetail(req) {
    const panel = document.getElementById('reqDetail');
    panel.innerHTML = `
      <div class="inline-detail">
        <div class="inline-hdr">
          <div class="inline-hdr-left">
            ${U.mBadge(req.method)}
            <span class="inline-path" title="${U.esc(req.url)}">${U.esc(req.path || '/')}</span>
            ${req.is_blocked ? '<span style="font-size:10px;color:var(--red)">🚫 BLOCKED</span>' : ''}
            ${req.threat_score > 0 ? `<span style="font-size:10px;color:var(--yellow)">⚠ ${req.threat_score}</span>` : ''}
          </div>
          <div style="display:flex;gap:5px">
            <button class="btn btn-sm" onclick="Modal.openReq('${req.id}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg> Expand
            </button>
          </div>
        </div>
        <div class="req-tabs" id="inlineTabs">
          <button class="req-tab active" data-tab="overview">Overview</button>
          <button class="req-tab" data-tab="headers">Headers <span class="size-tag">${Object.keys(req.headers||{}).length}</span></button>
          <button class="req-tab" data-tab="body">Body ${req.body_size > 0 ? `<span class="size-tag">${U.bytes(req.body_size)}</span>` : ''}</button>
          <button class="req-tab" data-tab="security">Security</button>
        </div>
        <div class="tab-content" id="inlineContent"></div>
      </div>
    `;

    // Reuse modal tabs renderer
    const renderInline = (tab) => {
      S.modalReqData = req;
      const tmp = document.createElement('div');
      tmp.id = 'rmContent';
      document.body.appendChild(tmp);
      Modal.switchReqTab(tab);
      const html = tmp.innerHTML;
      document.body.removeChild(tmp);
      document.getElementById('inlineContent').innerHTML = html;
    };

    renderInline('overview');

    panel.querySelectorAll('.req-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        panel.querySelectorAll('.req-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        renderInline(tab.dataset.tab);
      });
    });
  },

  renderEpHeader(ep) {
    document.getElementById('epTitle').textContent = ep.name;
    document.getElementById('epDot').style.background = ep.color;
    document.getElementById('epUrl').textContent = ep.webhook_url;

    const badge = document.getElementById('epBadge');
    badge.textContent = ep.is_paused ? '⏸ PAUSED' : '● ACTIVE';
    badge.className = `ep-badge${ep.is_paused ? ' paused' : ''}${ep.is_expired ? ' expired' : ''}`;

    document.getElementById('btnPause').textContent = ep.is_paused ? '▶ Resume' : '⏸ Pause';
  },

  renderEpKpis(ep) {
    document.getElementById('epKpis').innerHTML = [
      { l:'Requests',  v: ep.request_count.toLocaleString(), cls:'accent' },
      { l:'Blocked',   v: ep.blocked_count.toLocaleString(), cls: ep.blocked_count > 0 ? 'danger' : '' },
      { l:'Block Rate',v: ep.request_count > 0 ? Math.round(ep.blocked_count/ep.request_count*100)+'%' : '0%', cls:'' },
      { l:'Data',      v: U.bytes(ep.byte_count), cls:'' },
      { l:'Last Hit',  v: U.rel(ep.last_hit_at), cls:'' },
      { l:'Response',  v: ep.response_status.toString(), cls:'' },
      { l:'Delay',     v: ep.response_delay_ms ? ep.response_delay_ms+'ms' : 'None', cls:'' },
      { l:'Status',    v: ep.is_paused ? 'Paused' : ep.is_expired ? 'Expired' : 'Active', cls:'' },
    ].map(k => `
      <div class="ep-kpi">
        <div class="ep-kpi-lbl">${k.l}</div>
        <div class="ep-kpi-val ${k.cls}">${k.v}</div>
      </div>
    `).join('');
  },

  showView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById('view' + name)?.classList.add('active');
    document.querySelectorAll('.snav').forEach(b => b.classList.toggle('active', b.dataset.view === name));
    S.currentView = name;
    if (name === 'Live') { CH.liveActivity(); LiveFeed.render(); }
  },
};

// ─── APP ──────────────────────────────────────────────────────────────────────
const App = {
  async init() {
    await App.loadEps();
    UI.renderEpList();
    Dash.load();
    Sse.connect();
    App.bindEvents();
    if (S.endpoints.length) App.selectEp(S.endpoints[0].id);
    else UI.showView('Dashboard');
  },

  async loadEps() {
    try {
      const { data } = await Api.get('/endpoints');
      S.endpoints = data || [];
      // Populate live filter
      const lf = document.getElementById('liveFilter');
      lf.innerHTML = '<option value="">All Endpoints</option>' + S.endpoints.map(e => `<option value="${e.id}">${U.esc(e.name)}</option>`).join('');
    } catch(e) { Toast.err('Failed to load endpoints'); }
  },

  async selectEp(id) {
    try {
      const { data, requests } = await Api.get('/requests/' + id);
      S.activeEp  = data;
      S.requests  = requests || [];
      S.activeReq = null;

      UI.showView('Endpoint');
      UI.renderEpList();
      UI.renderReqList();
      UI.renderEpHeader(data);
      UI.renderEpKpis(data);
      Sse.connect(id);

      document.getElementById('reqDetail').innerHTML = `<div class="empty-state"><div class="empty-icon">⚡</div><p>Select a request to inspect</p></div>`;
    } catch(e) { Toast.err('Failed to load endpoint: ' + e.message); }
  },

  selectReq(id) {
    const req = S.requests.find(r => r.id === id);
    if (!req) return;
    S.activeReq = req;
    UI.renderReqList();
    UI.renderReqDetail(req);
  },

  bindEvents() {
    // Sidebar nav
    document.querySelectorAll('.snav').forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        UI.showView(view);
        if (view === 'Dashboard') { S.activeEp = null; UI.renderEpList(); Sse.connect(); Dash.load(); }
        if (view === 'Security') SecView.load();
        if (view === 'Keys') KeysView.load();
        if (view === 'Live') { CH.liveActivity(); LiveFeed.render(); }
      });
    });

    // New endpoint
    document.getElementById('btnNew').addEventListener('click', () => EpModal.open());

    // Ep search
    document.getElementById('epSearch').addEventListener('input', UI.renderEpList);

    // Refresh
    document.getElementById('btnRefresh').addEventListener('click', Dash.load);

    // EP actions
    document.getElementById('btnCopyUrl').addEventListener('click', () => { if (S.activeEp) U.copy(S.activeEp.webhook_url, 'URL copied!'); });
    document.getElementById('btnCopyUrl2').addEventListener('click', () => { if (S.activeEp) U.copy(S.activeEp.webhook_url, 'URL copied!'); });
    document.getElementById('btnRegenToken').addEventListener('click', async () => {
      if (!S.activeEp || !confirm('Regenerate token? Old URL will stop working.')) return;
      try {
        const { data } = await Api.post('/endpoints/' + S.activeEp.id + '/regenerate', {});
        S.activeEp = data;
        const i = S.endpoints.findIndex(e => e.id === data.id);
        if (i >= 0) S.endpoints[i] = data;
        UI.renderEpHeader(data);
        Sse.connect(data.id);
        Toast.ok('Token regenerated!');
      } catch(e) { Toast.err(e.message); }
    });

    document.getElementById('btnPause').addEventListener('click', async () => {
      if (!S.activeEp) return;
      try {
        const { data } = await Api.post('/endpoints/' + S.activeEp.id + '/pause', {});
        S.activeEp = data;
        const i = S.endpoints.findIndex(e => e.id === data.id);
        if (i >= 0) S.endpoints[i] = data;
        UI.renderEpHeader(data); UI.renderEpList();
        Toast.info(data.is_paused ? 'Endpoint paused' : 'Endpoint resumed');
      } catch(e) { Toast.err(e.message); }
    });

    document.getElementById('btnClear').addEventListener('click', async () => {
      if (!S.activeEp || !confirm(`Clear all requests for "${S.activeEp.name}"?`)) return;
      try {
        const { deleted } = await Api.post('/endpoints/' + S.activeEp.id + '/clear', {});
        S.requests = [];
        S.activeEp.request_count = 0;
        S.activeEp.blocked_count = 0;
        UI.renderReqList();
        UI.renderEpKpis(S.activeEp);
        document.getElementById('reqDetail').innerHTML = `<div class="empty-state"><div class="empty-icon">📭</div><p>Cleared ${deleted} requests</p></div>`;
        Toast.ok(`Cleared ${deleted} requests`);
      } catch(e) { Toast.err(e.message); }
    });

    document.getElementById('btnEdit').addEventListener('click', () => { if (S.activeEp) EpModal.open(S.activeEp); });

    // Filters (debounced)
    ['reqSearch','reqMethod','reqFilter'].forEach(id => {
      document.getElementById(id).addEventListener('input', () => {
        clearTimeout(S.filterDebounce);
        S.filterDebounce = setTimeout(() => App.applyFilters(), 300);
      });
      document.getElementById(id).addEventListener('change', () => App.applyFilters());
    });

    // Modal tabs for EP
    document.querySelectorAll('.mtab').forEach(t => t.addEventListener('click', () => EpModal.switchTab(t.dataset.mtab)));

    // Save EP
    document.getElementById('btnSaveEp').addEventListener('click', EpModal.save);

    // Modal close
    document.querySelectorAll('[data-close]').forEach(btn => btn.addEventListener('click', () => Modal.close(btn.dataset.close)));
    document.getElementById('overlay').addEventListener('click', e => { if (e.target === e.currentTarget) Modal.closeAll(); });

    // Req modal tabs
    document.querySelectorAll('#modalReq .req-tab').forEach(t => t.addEventListener('click', () => Modal.switchReqTab(t.dataset.tab)));

    // Req modal actions
    document.getElementById('btnRmStar').addEventListener('click', async () => {
      if (!S.modalReqData) return;
      try {
        const { data } = await Api.post('/requests/' + S.modalReqData.id + '/star', {});
        S.modalReqData.is_starred = data.is_starred;
        document.getElementById('btnRmStar').textContent = (data.is_starred ? '★' : '☆') + ' Star';
        const req = S.requests.find(r => r.id === data.id);
        if (req) { req.is_starred = data.is_starred; UI.renderReqList(); }
        Toast.ok(data.is_starred ? 'Starred!' : 'Unstarred');
      } catch(e) { Toast.err(e.message); }
    });

    document.getElementById('btnRmReplay').addEventListener('click', () => Modal.switchReqTab('replay'));

    document.getElementById('btnRmDelete').addEventListener('click', async () => {
      if (!S.modalReqData || !confirm('Delete this request?')) return;
      try {
        await Api.del('/requests/' + S.modalReqData.id);
        S.requests = S.requests.filter(r => r.id !== S.modalReqData.id);
        UI.renderReqList();
        Modal.close('modalReq');
        document.getElementById('reqDetail').innerHTML = `<div class="empty-state"><div class="empty-icon">🗑</div><p>Request deleted</p></div>`;
        Toast.ok('Deleted');
      } catch(e) { Toast.err(e.message); }
    });

    // Export
    document.querySelectorAll('[data-export]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!S.modalReqData) return;
        window.open('/api/export/' + S.modalReqData.id + '?format=' + btn.dataset.export, '_blank');
      });
    });

    // Live filter
    document.getElementById('liveFilter').addEventListener('change', () => LiveFeed.render());
    document.getElementById('btnClearFeed').addEventListener('click', () => {
      S.liveEntries = []; S.liveBlocked = 0; S.liveThreats = 0; S.liveRpm = [];
      document.getElementById('liveFeed').innerHTML = '';
      ['lsTotal','lsRpm','lsBlocked','lsThreats'].forEach(id => document.getElementById(id).textContent = '0');
    });

    // Security refresh
    document.getElementById('btnRefreshSec').addEventListener('click', SecView.load);

    // API Keys
    document.getElementById('btnCreateKey').addEventListener('click', () => {
      document.getElementById('keyResult').classList.add('hidden');
      document.getElementById('keyName').value = '';
      Modal.open('modalKey');
    });
    document.getElementById('btnDoCreateKey').addEventListener('click', async () => {
      const name = document.getElementById('keyName').value.trim();
      if (!name) { Toast.err('Name required'); return; }
      const perms = [...document.querySelectorAll('#modalKey input[type=checkbox]:checked')].map(el => el.value);
      try {
        const { data } = await Api.post('/keys', { name, permissions: perms });
        const kr = document.getElementById('keyResult');
        kr.innerHTML = `<div class="key-value">${data.key}</div><div class="key-warn">⚠ Copy this key now — it won't be shown again!</div>`;
        kr.classList.remove('hidden');
        document.getElementById('btnDoCreateKey').style.display = 'none';
        KeysView.load();
      } catch(e) { Toast.err(e.message); }
    });

    // Time range picker
    document.querySelectorAll('.trp-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.trp-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        Dash.load();
      });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') Modal.closeAll();
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); document.getElementById('epSearch').focus(); }
      if (e.key === 'n' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') EpModal.open();
    });

    // Periodic dashboard refresh
    setInterval(() => { if (S.currentView === 'Dashboard') Dash.load(); }, 30000);
  },

  async applyFilters() {
    if (!S.activeEp) return;
    try {
      const method  = document.getElementById('reqMethod').value;
      const search  = document.getElementById('reqSearch').value;
      const filter  = document.getElementById('reqFilter').value;
      const params  = new URLSearchParams({ method, search, [filter]: filter ? '1' : '' });
      const { requests } = await Api.get('/requests/' + S.activeEp.id + '?' + params);
      S.requests = requests || [];
      UI.renderReqList();
    } catch {}
  },
};

// Boot
document.addEventListener('DOMContentLoaded', () => App.init());
