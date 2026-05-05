const TACTIC_ORDER = ['reconnaissance','resource-development','initial-access','execution',
  'persistence','privilege-escalation','defense-evasion','credential-access',
  'discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
const TACTIC_NAMES = {
  'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
  'initial-access':'Initial Access','execution':'Execution',
  'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
  'defense-evasion':'Defense Evasion','credential-access':'Credential Access',
  'discovery':'Discovery','lateral-movement':'Lateral Movement',
  'collection':'Collection','command-and-control':'Command and Control',
  'exfiltration':'Exfiltration','impact':'Impact'
};
const SEV_COLORS = {critical:'#ff4444',high:'#ff8800',medium:'#e3b341',low:'#58a6ff',informational:'#8b949e'};
const SEV_ORDER = ['critical','high','medium','low','informational'];
const TS_FIELDS = ['SystemTime','timestamp','@timestamp','TimeCreated','UtcTime','date','_time','time','datetime','EventTime','ts'];

function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setHtml(el, value) { if (el) el.innerHTML = value; }
function getTimestamp(event) { for (const f of TS_FIELDS) if (event[f]) return event[f]; return null; }
function fmtCount(n) { return Number(n).toLocaleString(); }
function parseTags(tags) {
  const tactics = [], techniques = [];
  (tags||[]).forEach(t => {
    const low = t.toLowerCase().replace('attack.','');
    if (TACTIC_ORDER.includes(low)) tactics.push(low);
    else if (/^t\d{4}/.test(low)) techniques.push(low.toUpperCase());
  });
  return { tactics, techniques };
}

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    tab.classList.add('active');
    const id = tab.dataset.tab;
    const sec = document.getElementById('sec-' + id);
    if (sec) sec.classList.add('active');
    if (id === 'timeline' && !window._tlInit) initTimeline();
    if (id === 'mitre' && !window._mitreInit) initMitre();
    if (id === 'hosts' && !window._hostsInit) initHosts();
    if (id === 'eids' && !window._eidsInit) initEids();
    if (id === 'login' && !window._loginInit) initLogin();
    if (id === 'anomalies' && !window._anomInit) initAnomalies();
    if (id === 'hunt' && !window._huntInit) initHunt();
    if (id === 'iocs' && !window._iocsInit) initIocs();
    if (id === 'chains' && !window._chainsInit) initChains();
  });
});

// Curated list of rule-title fragments that are common false-positive
// sources on healthy workstations. We DO NOT hide them from the report —
// they still appear in the Detections tab — but we exclude them from the
// "Key Findings" auto-curated panel so an analyst sees signal first.
const NOISY_TITLE_FRAGMENTS = [
  'network connection to public ip',
  'failed dns zone transfer',
  'suspicious sql query',
  'java payload strings',
  'applocker prevented',
  'sysmon configuration change',
  'real-time protection failure',
  'pwsh engine started',
  'wmi provider started',
];
function isNoisy(d) {
  const t = (d.title || '').toLowerCase();
  return NOISY_TITLE_FRAGMENTS.some(f => t.includes(f));
}
// Curated list of high-signal title fragments that are ALWAYS surfaced
// regardless of count: AV verdict, RAT installation, persistence, BYOVD.
const KEY_TITLE_FRAGMENTS = [
  'restored quarantine',
  'defender threat',
  'kaspersky',
  'anydesk',
  'teamviewer',
  'screenconnect',
  'rustdesk',
  'netsupport',
  'remote access tool',
  'unsigned kernel',
  'revoked kernel',
  'wmi event subscription',
  'cve-',
  'service installation in suspicious',
];
function isKeySignal(d) {
  const t = (d.title || '').toLowerCase();
  return KEY_TITLE_FRAGMENTS.some(f => t.includes(f));
}

// "Key Findings" auto-curation: prefer high-signal detections over high-volume.
// Returns up to N detections that an analyst should look at FIRST. Logic:
//   1. Always include CRITICAL severity, regardless of count.
//   2. Include HIGH severity unless title is on the curated noisy list.
//   3. Always include rules whose title hints at AV / RAT / persistence,
//      regardless of severity (they are the load-bearing IOCs in DFIR).
function pickKeyFindings(dets, max) {
  if (max === undefined) max = 15;
  const sevRank = {critical:5, high:4, medium:3, low:2, informational:1};
  const ranked = dets.slice().sort((a, b) => {
    const sa = sevRank[(a.level||'').toLowerCase()] || 0;
    const sb = sevRank[(b.level||'').toLowerCase()] || 0;
    if (sa !== sb) return sb - sa;
    return a.count - b.count;  // low-count first within a severity (often more specific)
  });
  const picks = [];
  for (const d of ranked) {
    const lvl = (d.level||'').toLowerCase();
    if (lvl === 'critical') { picks.push(d); }
    else if (lvl === 'high' && !isNoisy(d)) { picks.push(d); }
    else if (isKeySignal(d) && !isNoisy(d)) { picks.push(d); }
    if (picks.length >= max) break;
  }
  return picks;
}

// Auto-narrative: generate plain-language summary of what the report shows.
function buildNarrative() {
  const dets = DATA.detections || [];
  const lines = [];
  const sev = DATA.severity_rollup || {};
  const crit = (sev.critical||{}).unique || 0;
  const high = (sev.high||{}).unique || 0;
  const totalEvts = (DATA.scan||{}).total_events || 0;
  const hits = (DATA.scan||{}).events_with_hits || 0;
  const verdict = (DATA.summary||{}).verdict;
  const computers = DATA.computer_metrics || [];

  if (verdict) lines.push('<b>Verdict:</b> ' + escHtml(verdict) + ' (risk score ' + ((DATA.summary||{}).risk_score||0).toFixed(0) + '/100).');
  lines.push('Scanned ' + fmtCount(totalEvts) + ' events, ' + fmtCount(hits) + ' carry detections (data reduction ' + ((DATA.scan||{}).reduction_pct||0).toFixed(2) + '%).');
  if (crit + high > 0) {
    lines.push('Found <b>' + crit + ' critical</b> and <b>' + high + ' high-severity</b> unique rules across ' + computers.length + ' host(s).');
  }
  // Identify AnyDesk-style RAT signals
  const ratHit = dets.find(d => /AnyDesk|TeamViewer|Atera|ScreenConnect|RustDesk|NetSupport/i.test(d.title));
  if (ratHit) {
    lines.push('<b>Remote-access tool indicator:</b> ' + escHtml(ratHit.title) + '. Investigate the host immediately — RAT in user-writable directory is a high-fidelity intrusion signal.');
  }
  // Defender quarantine restore — operator re-arming malware
  const restore = dets.find(d => /Restored Quarantine|Quarantine.*Restor/i.test(d.title));
  if (restore && restore.count >= 5) {
    lines.push('<b>Quarantine restoration burst:</b> ' + restore.count + ' restored items. This pattern indicates an operator (or user) bypassing AV verdicts — follow up on what files were re-armed.');
  }
  // AV detection — Defender or Kaspersky
  const avHits = dets.filter(d => /Windows Defender Threat|Kaspersky.*Threat|Kaspersky.*Neutralized/i.test(d.title));
  if (avHits.length) {
    const total = avHits.reduce((s, d) => s + d.count, 0);
    lines.push('<b>Anti-virus engagement:</b> ' + total + ' AV detections across ' + avHits.length + ' rule(s). Pair the timestamps with process and network telemetry for those events.');
  }
  // Firewall manipulation
  const fwAdd = dets.find(d => /Uncommon New Firewall Rule/i.test(d.title));
  const fwDel = dets.find(d => /Has Been Deleted From The Windows Firewall/i.test(d.title));
  if (fwAdd && fwDel) {
    lines.push('<b>Firewall tampering:</b> ' + fwAdd.count + ' rule additions and ' + fwDel.count + ' deletions. Review which application paths created the rules — attackers commonly carve exceptions for their RAT/C2 binary.');
  }
  return lines.map(l => '<p>' + l + '</p>').join('');
}

(function initDashboard() {
  const dets = DATA.detections || [];
  const sev = DATA.severity_rollup || {};
  const sevTotal = SEV_ORDER.reduce((s,l) => s + ((sev[l]||{}).total||0), 0);

  // Inject the auto-narrative under the verdict banner if Investigation panel exists.
  const narrEl = document.getElementById('investigationNarrative');
  if (narrEl) setHtml(narrEl, buildNarrative());

  // Key Findings panel — analyst-curated selection, separate from Top Detections
  const keyFindings = pickKeyFindings(dets, 10);
  const kfEl = document.getElementById('keyFindings');
  if (kfEl) {
    if (keyFindings.length === 0) {
      setHtml(kfEl, '<p class="empty">No high-signal indicators — only routine / low-confidence detections.</p>');
    } else {
      setHtml(kfEl, keyFindings.map(d => {
        const idx = dets.indexOf(d);
        const techBadges = (d.mitre_techniques||[]).slice(0,3).map(t => '<span class="tag mitre">' + t + '</span>').join('');
        return '<div class="rowitem keyfinding" onclick="showEvents(' + idx + ')">' +
          '<span class="badge badge-' + (d.level||'').toLowerCase() + '">' + (d.level||'').toUpperCase() + '</span>' +
          '<span class="ri-title"><b>' + escHtml(d.title) + '</b></span>' +
          techBadges +
          '<span class="ri-count">' + d.count + ' ev</span></div>';
      }).join(''));
    }
  }

  const cards = [
    ['Files', DATA.scan.files_scanned, ''],
    ['Total Events', fmtCount(DATA.scan.total_events), ''],
    ['With Hits', fmtCount(DATA.scan.events_with_hits), ''],
    ['Reduction', DATA.scan.reduction_pct.toFixed(2) + '%', ''],
    ['Rules Matched', dets.length, ''],
  ];
  for (const lvl of SEV_ORDER) {
    const r = sev[lvl] || { total: 0, unique: 0 };
    if (r.total === 0 && r.unique === 0) continue;
    cards.push([lvl[0].toUpperCase()+lvl.slice(1), r.total + ' | ' + r.unique, lvl]);
  }
  setHtml(document.getElementById('summaryCards'), cards.map(c =>
    '<div class="card ' + c[2] + '"><div class="value">' + c[1] + '</div><div class="label">' + c[0] + '</div></div>'
  ).join(''));

  const sevBar = document.getElementById('sevBar');
  if (sevTotal > 0) {
    setHtml(sevBar, SEV_ORDER.map(l => {
      const t = (sev[l]||{}).total || 0;
      const pct = (t/sevTotal*100);
      return pct > 0 ? '<span style="width:' + pct + '%;background:' + SEV_COLORS[l] + '" title="' + l + ': ' + t + '"></span>' : '';
    }).join(''));
  }

  const topDets = dets.slice().sort((a,b) => {
    const oi = l => SEV_ORDER.indexOf((l||'informational').toLowerCase());
    return oi(a.level) - oi(b.level) || b.count - a.count;
  }).slice(0, 8);
  setHtml(document.getElementById('topDetections'), topDets.map((d, idx) => {
    const techBadges = (d.mitre_techniques||[]).slice(0,3).map(t => '<span class="tag mitre">' + t + '</span>').join('');
    const realIdx = dets.indexOf(d);
    return '<div class="rowitem" onclick="showEvents(' + realIdx + ')">' +
      '<span class="badge badge-' + (d.level||'').toLowerCase() + '">' + (d.level||'').toUpperCase() + '</span>' +
      '<span class="ri-title">' + escHtml(d.title) + '</span>' +
      techBadges +
      '<span class="ri-count">' + d.count + '</span></div>';
  }).join('') || '<p class="empty">No detections.</p>');

  const topHosts = (DATA.computer_metrics||[]).slice(0, 8);
  setHtml(document.getElementById('topHosts'), topHosts.map(h =>
    '<div class="rowitem"><span class="ri-title">' + escHtml(h.computer) + '</span>' +
    '<span class="hb crit" title="critical">' + h.critical + '</span>' +
    '<span class="hb hi" title="high">' + h.high + '</span>' +
    '<span class="hb md" title="medium">' + h.medium + '</span>' +
    '<span class="hb lo" title="low">' + h.low + '</span>' +
    '<span class="ri-count">' + h.unique_detections + '</span></div>'
  ).join('') || '<p class="empty">No host data.</p>');

  const topEids = (DATA.eid_metrics||[]).slice(0, 8);
  setHtml(document.getElementById('topEids'), topEids.map(e =>
    '<div class="rowitem"><span class="ri-title">EID <b>' + escHtml(e.event_id) + '</b> &middot; ' + escHtml(e.channel) + '</span>' +
    '<span class="ri-count">' + e.total + '</span></div>'
  ).join('') || '<p class="empty">No EID data.</p>');

  if (DATA.summary && DATA.summary.recommendations && DATA.summary.recommendations.length) {
    document.getElementById('recCard').style.display = '';
    setHtml(document.getElementById('recList'),
      '<ul class="recs">' + DATA.summary.recommendations.map(r => '<li>' + escHtml(r) + '</li>').join('') + '</ul>');
  }

  // Top Rule Authors — credits + signal: who contributed the rules that fired.
  const authorTally = {};
  dets.forEach(d => {
    const a = (d.author||'').trim();
    if (!a) return;
    // Authors can be a comma- or "/"-separated list; split on common delimiters.
    const names = a.split(/\s*[,;\/]\s*/).filter(Boolean);
    names.forEach(n => {
      // Strip trailing parenthesized affiliations like "Foo (Acme)" → "Foo"
      const clean = n.replace(/\s*\(.*\)$/, '').trim();
      if (!clean) return;
      authorTally[clean] = (authorTally[clean] || 0) + d.count;
    });
  });
  const topAuthors = Object.entries(authorTally).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topAuthors.length === 0) {
    setHtml(document.getElementById('topAuthors'), '<p class="empty">No author metadata available.</p>');
  } else {
    setHtml(document.getElementById('topAuthors'),
      topAuthors.map(([n, c]) =>
        '<div class="rowitem"><span class="ri-title">' + escHtml(n) + '</span><span class="ri-count">' + fmtCount(c) + '</span></div>'
      ).join(''));
  }
})();

let dtTable;
(function initDetectionsTable() {
  const dets = DATA.detections || [];
  if (dets.length === 0) return;
  const tbody = document.querySelector('#detectionsTable tbody');
  if (!tbody) return;
  const tacticSet = new Set();
  let html = '';
  dets.forEach((det, idx) => {
    (det.mitre_tactics||[]).forEach(t => tacticSet.add(t));
    const techBadges = (det.mitre_techniques||[]).map(t => '<span class="tag mitre">' + t + '</span>').join(' ');
    const tagBadges = (det.tags||[]).filter(t => !t.toLowerCase().startsWith('attack.'))
      .map(t => '<span class="tag">' + escHtml(t) + '</span>').join(' ');
    const confBadge = det.confidence === 'low' ? '<span class="badge badge-lowconf">LOW CONF</span>' : '';
    html += '<tr data-level="' + (det.level||'').toLowerCase() + '">' +
      '<td><span class="badge badge-' + (det.level||'').toLowerCase() + '">' + (det.level||'').toUpperCase() + '</span>' + confBadge + '</td>' +
      '<td>' + escHtml(det.title) + '</td>' +
      '<td class="cell-desc">' + escHtml(det.description||'') + '</td>' +
      '<td>' + det.count + '</td>' +
      '<td class="cell-author">' + escHtml(det.author||'') + '</td>' +
      '<td>' + (techBadges || '-') + '</td>' +
      '<td>' + (tagBadges || '-') + '</td>' +
      '<td><button class="btn" onclick="showEvents(' + idx + ')">View ' + det.count + '</button></td>' +
      '</tr>';
  });
  setHtml(tbody, html);
  const tacticSel = document.getElementById('tacticFilter');
  Array.from(tacticSet).sort().forEach(t => {
    const opt = document.createElement('option');
    opt.value = t; opt.textContent = TACTIC_NAMES[t] || t;
    tacticSel.appendChild(opt);
  });
  dtTable = $('#detectionsTable').DataTable({
    pageLength: 25, order: [[3, 'desc']], deferRender: true,
    columnDefs: [{ orderable: false, targets: [6, 7] }]
  });
})();
function filterDetections() {
  const sev = document.getElementById('sevFilter').value;
  const tactic = document.getElementById('tacticFilter').value;
  if (!dtTable) return;
  dtTable.column(0).search(sev).draw();
  if (tactic) dtTable.column(6).search(tactic).draw();
  else dtTable.column(6).search('').draw();
}

let timeline;
function initTimeline() {
  window._tlInit = true;
  const groups = new vis.DataSet();
  const items = new vis.DataSet();
  TACTIC_ORDER.forEach((tactic, i) => groups.add({ id: tactic, content: TACTIC_NAMES[tactic], order: i }));
  groups.add({ id: 'other', content: 'Other', order: TACTIC_ORDER.length });
  let itemId = 0;
  (DATA.detections||[]).forEach((det, detIdx) => {
    const tactics = (det.mitre_tactics||[]).length > 0 ? det.mitre_tactics : ['other'];
    const times = [];
    (det.events||[]).forEach(ev => {
      const ts = getTimestamp(ev);
      if (ts) { const d = new Date(ts); if (!isNaN(d.getTime())) times.push(d); }
    });
    if (times.length === 0) return;
    times.sort((a,b) => a-b);
    const start = times[0];
    const end = times.length > 1 ? times[times.length-1] : new Date(start.getTime() + 60000);
    tactics.forEach(tactic => {
      const techStr = (det.mitre_techniques||[]).length > 0 ? ' [' + det.mitre_techniques.join(',') + ']' : '';
      items.add({
        id: itemId++, group: tactic,
        content: escHtml(det.title) + techStr + ' (' + det.count + ')',
        start: start,
        end: end.getTime() > start.getTime() ? end : new Date(start.getTime() + 60000),
        className: 'sev-' + (det.level||'').toLowerCase(),
        title: det.title + '\nSeverity: ' + (det.level||'').toUpperCase() + '\nCount: ' + det.count,
        _detIdx: detIdx
      });
    });
  });
  const container = document.getElementById('timeline');
  timeline = new vis.Timeline(container, items, groups, {
    stack: true, showCurrentTime: false, orientation: 'top',
    margin: { item: { horizontal: 2, vertical: 4 } },
    zoomMin: 60000, tooltip: { followMouse: true }, height: '600px'
  });
  timeline.on('select', function(props) {
    if (props.items.length > 0) {
      const item = items.get(props.items[0]);
      if (item && item._detIdx !== undefined) showEvents(item._detIdx);
    }
  });
}
function tlFit() { if (timeline) timeline.fit(); }
function tlZoomIn() { if (timeline) timeline.zoomIn(0.3); }
function tlZoomOut() { if (timeline) timeline.zoomOut(0.3); }

function initMitre() {
  window._mitreInit = true;
  const matrix = {};
  TACTIC_ORDER.forEach(t => matrix[t] = {});
  (DATA.detections||[]).forEach(det => {
    const tactics = det.mitre_tactics||[];
    const techniques = det.mitre_techniques||[];
    tactics.forEach(tactic => {
      techniques.forEach(tech => {
        if (!matrix[tactic][tech]) matrix[tactic][tech] = { count: 0, rules: [] };
        matrix[tactic][tech].count += det.count;
        matrix[tactic][tech].rules.push(det.title);
      });
    });
  });
  let maxCount = 1;
  Object.values(matrix).forEach(techs => {
    Object.values(techs).forEach(t => { if (t.count > maxCount) maxCount = t.count; });
  });
  const container = document.getElementById('mitreMatrix');
  setHtml(container, TACTIC_ORDER.map(tactic => {
    const techs = matrix[tactic] || {};
    const techIds = Object.keys(techs).sort();
    const techHtml = techIds.map(tech => {
      const info = techs[tech];
      const intensity = Math.max(0.2, info.count / maxCount);
      const color = 'rgba(14,165,233,' + intensity + ')';
      const rules = info.rules.map(escHtml).join('\n');
      return '<div class="mitre-tech" style="background:' + color + '" title="' + tech + ' (' + info.count + ' events)\n' + rules + '">' +
        '<span class="tech-id">' + tech + '</span><span class="tech-count">' + info.count + '</span></div>';
    }).join('');
    return '<div class="mitre-col"><div class="mitre-col-header">' + (TACTIC_NAMES[tactic]||tactic) + '</div>' +
      (techHtml || '<div class="mitre-empty">-</div>') + '</div>';
  }).join(''));
}

function initHosts() {
  window._hostsInit = true;
  const tbody = document.querySelector('#hostsTable tbody');
  if (!tbody) return;
  setHtml(tbody, (DATA.computer_metrics||[]).map(h =>
    '<tr><td>' + escHtml(h.computer) + '</td>' +
    '<td>' + fmtCount(h.total_events_seen) + '</td>' +
    '<td>' + h.unique_detections + '</td>' +
    '<td class="sev-cell critical">' + h.critical + '</td>' +
    '<td class="sev-cell high">' + h.high + '</td>' +
    '<td class="sev-cell medium">' + h.medium + '</td>' +
    '<td class="sev-cell low">' + h.low + '</td>' +
    '<td class="sev-cell info">' + h.informational + '</td></tr>'
  ).join(''));
  $('#hostsTable').DataTable({ pageLength: 25, order: [[3,'desc'],[4,'desc']] });
}

function initEids() {
  window._eidsInit = true;
  const tbody = document.querySelector('#eidsTable tbody');
  if (!tbody) return;
  setHtml(tbody, (DATA.eid_metrics||[]).map(e =>
    '<tr><td>' + escHtml(e.event_id) + '</td><td>' + escHtml(e.channel) + '</td><td>' + fmtCount(e.total) + '</td><td>' + fmtCount(e.with_detection) + '</td></tr>'
  ).join(''));
  $('#eidsTable').DataTable({ pageLength: 25, order: [[2,'desc']] });
}

function initLogin() {
  window._loginInit = true;
  if (!DATA.login) return;
  const L = DATA.login;
  setHtml(document.getElementById('loginCards'), [
    ['Successful logons', fmtCount(L.total_success||0), 'low'],
    ['Failed logons', fmtCount(L.total_failure||0), 'high'],
    ['Unique users', (L.by_user||[]).length, ''],
    ['Unique sources', (L.by_source_ip||[]).length, ''],
  ].map(c => '<div class="card ' + c[2] + '"><div class="value">' + c[1] + '</div><div class="label">' + c[0] + '</div></div>').join(''));
  const list = function(arr, render, empty) {
    return arr && arr.length ? arr.map(render).join('') : '<p class="empty">' + empty + '</p>';
  };
  setHtml(document.getElementById('loginBrute'), list(L.brute_force_candidates,
    b => '<div class="rowitem"><span class="ri-title">' + escHtml(b.username) + ' from ' + escHtml(b.source_ip) + '</span><span class="ri-count">' + b.failure_count + ' failures</span></div>',
    'No brute-force candidates.'));
  setHtml(document.getElementById('loginLateral'), list(L.lateral_movement,
    l => '<div class="rowitem"><span class="ri-title">' + escHtml(l.username) + ' from ' + escHtml(l.source_ip) + '</span><span class="ri-count">type ' + escHtml(String(l.logon_type)) + '</span></div>',
    'No lateral movement signals.'));
  setHtml(document.getElementById('loginPriv'), list(L.privilege_escalation,
    p => '<div class="rowitem"><span class="ri-title">' + escHtml(p.username) + '</span><span class="ri-count">' + p.token_count + ' tokens</span></div>',
    'No privilege escalations.'));
  setHtml(document.getElementById('loginUnusual'), list(L.unusual_hours,
    u => '<div class="rowitem"><span class="ri-title">' + escHtml(u.username) + ' @ ' + u.hour + ':00</span><span class="ri-count">' + escHtml(u.source_ip||'') + '</span></div>',
    'No unusual-hour logons.'));
  setHtml(document.getElementById('loginSrc'), list((L.by_source_ip||[]).slice(0,15),
    s => '<div class="rowitem"><span class="ri-title">' + escHtml(s.ip_address) + '</span>' +
      '<span class="hb hi" title="failure">' + s.failure_count + '</span>' +
      '<span class="hb lo" title="success">' + s.success_count + '</span></div>',
    'No source IPs.'));
  setHtml(document.getElementById('loginUsers'), list((L.by_user||[]).slice(0,15),
    u => '<div class="rowitem"><span class="ri-title">' + escHtml(u.username) + '</span>' +
      '<span class="hb hi" title="failure">' + u.failure_count + '</span>' +
      '<span class="hb lo" title="success">' + u.success_count + '</span></div>',
    'No users.'));
}

function initAnomalies() {
  window._anomInit = true;
  const tbody = document.querySelector('#anomaliesTable tbody');
  if (!tbody) return;
  setHtml(tbody, (DATA.anomalies||[]).map((a, i) =>
    '<tr><td><span class="badge badge-' + (a.severity||'').toLowerCase() + '">' + (a.severity||'').toUpperCase() + '</span></td>' +
    '<td>' + escHtml(a.category) + '</td>' +
    '<td>' + escHtml(a.description) + '</td>' +
    '<td>' + (a.score||0).toFixed(2) + '</td>' +
    '<td>' + (a.evidence||[]).length + ' item(s) <button class="btn btn-sm" onclick="showAnomalyEvidence(' + i + ')">View</button></td></tr>'
  ).join(''));
  $('#anomaliesTable').DataTable({ pageLength: 25, order: [[3,'desc']] });
}

function showAnomalyEvidence(i) {
  const a = (DATA.anomalies||[])[i];
  if (!a) return;
  setHtml(document.getElementById('modalTitle'),
    '<span class="badge badge-' + (a.severity||'').toLowerCase() + '">' + (a.severity||'').toUpperCase() + '</span> ' + escHtml(a.category));
  const ev = a.evidence || [];
  const body = document.getElementById('modalBody');
  if (ev.length === 0) {
    setHtml(body, '<p class="empty">No evidence.</p>');
  } else {
    setHtml(body, ev.map((e, idx) => {
      const fields = Object.entries(e).map(kv =>
        '<div class="event-field"><span class="fname">' + escHtml(kv[0]) + '</span><span class="fval">' + escHtml(kv[1]) + '</span></div>'
      ).join('');
      return '<div class="event-card"><div class="event-card-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">' +
        '<span>Evidence #' + (idx+1) + '</span><span class="caret">&#9660;</span></div>' +
        '<div class="event-card-body">' + fields + '</div></div>';
    }).join(''));
  }
  document.getElementById('eventModal').classList.add('show');
}

function initHunt() {
  window._huntInit = true;
  const tbody = document.querySelector('#huntTable tbody');
  if (!tbody) return;
  setHtml(tbody, (DATA.hunt_findings||[]).map(h =>
    '<tr><td><span class="badge badge-' + String(h.severity||'').toLowerCase() + '">' + String(h.severity||'').toUpperCase() + '</span></td>' +
    '<td>' + escHtml(h.transform) + '</td>' +
    '<td>' + escHtml(h.description) + '</td>' +
    '<td>' + fmtCount(h.count) + '</td>' +
    '<td>' + escHtml(h.mitre_tactic||'') + '</td>' +
    '<td>' + escHtml(h.mitre_technique||'') + '</td></tr>'
  ).join(''));
  $('#huntTable').DataTable({ pageLength: 25, order: [[3,'desc']] });
}

function initIocs() {
  window._iocsInit = true;
  const iocs = DATA.iocs || [];
  if (iocs.length === 0) return;
  const byType = {};
  iocs.forEach(i => {
    const t = String(i.ioc_type||'unknown');
    (byType[t] = byType[t] || []).push(i);
  });
  const types = Object.keys(byType).sort();
  setHtml(document.getElementById('iocCards'),
    [['Total IOCs', fmtCount(iocs.length), '']].concat(
      types.slice(0,8).map(t => [t, fmtCount(byType[t].length), ''])
    ).map(c => '<div class="card ' + c[2] + '"><div class="value">' + c[1] + '</div><div class="label">' + c[0] + '</div></div>').join('')
  );
  const opentip = DATA.opentip || [];
  const otByValue = {};
  opentip.forEach(o => { otByValue[o.value] = o; });
  const panels = types.map(t => {
    const rows = byType[t].slice(0, 1000).map(i => {
      const ot = otByValue[i.value];
      const zoneBadge = ot ? '<span class="zone zone-' + String(ot.zone).toLowerCase() + '">' + String(ot.zone).toUpperCase() + '</span>' : '';
      return '<tr><td>' + escHtml(i.value) + '</td><td>' + i.count + '</td><td>' + zoneBadge + '</td><td>' + escHtml((i.source_fields||[]).slice(0,3).join(', ')) + '</td></tr>';
    }).join('');
    const moreNote = byType[t].length > 1000 ? '<p class="empty">Showing first 1000 of ' + byType[t].length + '; full list in muninn_iocs_*.csv.</p>' : '';
    return '<div class="dash-card"><h3>' + escHtml(t) + ' <span class="muted">(' + byType[t].length + ')</span></h3>' +
      '<table class="ioc-table"><thead><tr><th>Value</th><th>Count</th><th>Verdict</th><th>Sources</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' + moreNote + '</div>';
  }).join('');
  setHtml(document.getElementById('iocPanels'), panels);
}

function initChains() {
  window._chainsInit = true;
  const chains = DATA.chains || [];
  const list = document.getElementById('chainsList');
  if (chains.length === 0) { setHtml(list, '<p class="empty">No correlation chains.</p>'); return; }
  setHtml(list, chains.map((c, i) => {
    const events = (c.events||[]).map(e =>
      '<div class="chain-event"><span class="chain-ts">' + escHtml(e.timestamp||'') + '</span>' +
      '<span class="badge badge-' + String(e.level||'').toLowerCase() + '">' + String(e.level||'').toUpperCase() + '</span>' +
      '<span>' + escHtml(e.rule_title) + '</span></div>'
    ).join('');
    const tactics = (c.tactics||[]).map(t => '<span class="tag mitre">' + escHtml(t) + '</span>').join(' ');
    return '<details class="chain-card" id="chain-' + i + '"><summary><b>' + escHtml(c.entity) + '</b> &mdash; ' +
      (c.events||[]).length + ' events &middot; ' + c.duration_sec.toFixed(1) + 's &middot; ' + tactics + '</summary>' +
      '<div class="chain-body">' + events + '</div></details>';
  }).join(''));
}

function showEvents(detIdxOrKey) {
  const dets = DATA.detections || [];
  let det;
  if (typeof detIdxOrKey === 'string' && detIdxOrKey.startsWith('det:')) {
    const id = detIdxOrKey.slice(4);
    det = dets.find(d => d.id === id);
  } else {
    det = dets[detIdxOrKey];
  }
  if (!det) return;
  setHtml(document.getElementById('modalTitle'),
    '<span class="badge badge-' + (det.level||'').toLowerCase() + '">' + (det.level||'').toUpperCase() + '</span> ' +
    escHtml(det.title) + ' &mdash; ' + det.count + ' events');
  const body = document.getElementById('modalBody');
  let descHtml = '';
  if (det.description) descHtml = '<div class="modal-desc">' + escHtml(det.description) + '</div>';
  if (det.id) descHtml += '<div class="modal-meta">Rule ID: ' + escHtml(det.id) + (det.author ? ' &middot; Author: ' + escHtml(det.author) : '') + '</div>';
  if (!det.events || det.events.length === 0) {
    setHtml(body, descHtml + '<p class="empty">No event details available.</p>');
  } else {
    const total = det.events.length;
    const note = '<p class="muted">All ' + total + ' matched events. Click any card to expand fields.</p>';
    const cards = det.events.map((ev, i) => {
      const ts = getTimestamp(ev) || '';
      const preview = ts ? ts : Object.values(ev).filter(Boolean).slice(0,2).join(' | ');
      const fields = Object.entries(ev).filter(kv => kv[1]).map(kv =>
        '<div class="event-field"><span class="fname">' + escHtml(kv[0]) + '</span><span class="fval">' + escHtml(kv[1]) + '</span></div>'
      ).join('');
      return '<div class="event-card"><div class="event-card-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">' +
        '<span>Event #' + (i+1) + ' &mdash; ' + escHtml(preview.substring(0,80)) + '</span><span class="caret">&#9660;</span></div>' +
        '<div class="event-card-body">' + fields + '</div></div>';
    }).join('');
    setHtml(body, descHtml + note + cards);
  }
  document.getElementById('eventModal').classList.add('show');
}
function closeModal() { document.getElementById('eventModal').classList.remove('show'); }
document.getElementById('eventModal').addEventListener('click', function(e) { if (e.target === this) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
