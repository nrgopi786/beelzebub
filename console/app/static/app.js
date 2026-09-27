'use strict';
/*
 * Xpods Console frontend. Dependency-free.
 * SECURITY: every string shown here may be attacker-controlled (usernames, commands,
 * URIs, user agents...). Build DOM only through h(), which uses text nodes; never
 * assign innerHTML with data.
 */

// ------------------------------------------------------------------ helpers

function h(tag, attrs, ...children) {
  const el = document.createElementNS(
    ['svg', 'rect', 'line', 'text', 'g', 'title', 'path', 'polygon'].includes(tag) ? 'http://www.w3.org/2000/svg' : 'http://www.w3.org/1999/xhtml',
    tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') el.style.cssText = v; // CSSOM: allowed under style-src 'self'
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const $app = () => document.getElementById('app');
const fmtN = (n) => (n ?? 0).toLocaleString();
const pad = (n) => String(n).padStart(2, '0');
function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function ago(ts) {
  if (!ts) return 'never';
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function duration(a, b) {
  const s = Math.max(0, (new Date(b) - new Date(a)) / 1000);
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
const PROTOS = ['SSH', 'TELNET', 'HTTP', 'TCP', 'MCP', 'WEB'];
const protoClass = (p) => 'badge proto p-' + (PROTOS.includes(p) ? p : 'other');
const protoBadge = (p) => h('span', { class: protoClass(p) }, p || '?');
const protoColor = (p) => p === 'events' ? getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() : getComputedStyle(document.documentElement).getPropertyValue('--c-' + (PROTOS.includes(p) ? p.toLowerCase() : 'other')).trim();
function stateBadge(state) {
  const cls = ['running', 'exited', 'dead', 'failed'].includes(state) ? state : 'other';
  return h('span', { class: `badge state-${cls}` }, state);
}
function qs(obj) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== '' && v !== null && v !== undefined) p.set(k, v);
  const s = p.toString();
  return s ? '?' + s : '';
}
function isPublicIp(ip) {
  return ip && !/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);
}

// ------------------------------------------------------------------ api

class AuthError extends Error {}
async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    method: opts.method || 'GET',
    credentials: 'same-origin',
    headers: { 'X-Requested-With': 'console', ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && path !== '/login') { state.user = null; render(); throw new AuthError(); }
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join('; ') : `HTTP ${res.status}`);
  }
  return data;
}

// ------------------------------------------------------------------ state + router

const state = {
  user: undefined,
  since: localStorage.getItem('since') || '24h',
  source: localStorage.getItem('source') || '',
  client: localStorage.getItem('client') || '',
  clients: [],
  timers: [],
};

// Pre-rename links (bookmarks, history) -> current routes.
const LEGACY_ROUTES = { honeypots: 'xpods', honeypot: 'xpod' };

function route() {
  const hash = location.hash.replace(/^#/, '') || '/overview';
  const [path, query] = hash.split('?');
  const parts = path.split('/').filter(Boolean).map(decodeURIComponent);
  if (LEGACY_ROUTES[parts[0]]) {
    parts[0] = LEGACY_ROUTES[parts[0]];
    history.replaceState(null, '', '#/' + parts.map(encodeURIComponent).join('/') + (query ? '?' + query : ''));
  }
  return { parts, params: Object.fromEntries(new URLSearchParams(query || '')) };
}
function go(path, params) { location.hash = path + (params ? qs(params) : ''); }
function clearTimers() { state.timers.forEach(clearInterval); state.timers = []; }
function globalFilters(extra = {}) { return { since: state.since, client: state.client, source: state.source, ...extra }; }

window.addEventListener('hashchange', render);

async function boot() {
  try { state.user = (await api('/me')).user; } catch { state.user = null; }
  render();
}

function render() {
  clearTimers();
  if (!state.user) return renderLogin();
  const { parts, params } = route();
  const views = {
    overview: viewOverview, events: viewEvents, sessions: viewSessions, session: viewSession,
    attackers: viewAttackers, ip: viewIp, xpods: viewXpods, xpod: viewXpod, telemetry: viewTelemetry, audit: viewAudit, assistant: viewAssistant,
  };
  const view = views[parts[0]] || viewOverview;
  const main = h('main', { class: 'main' });
  $app().replaceChildren(h('div', { class: 'shell' }, sidebar(parts[0] || 'overview'), main));
  view(main, parts.slice(1), params).catch((e) => {
    if (!(e instanceof AuthError)) main.append(h('div', { class: 'msg err' }, e.message));
  });
}

const LOGO = () => h('svg', { viewBox: '0 0 32 32' },
  h('polygon', { points: '16,2 29,9.5 29,22.5 16,30 3,22.5 3,9.5', style: 'fill:var(--accent)' }),
  h('polygon', { points: '16,9 22,12.5 22,19.5 16,23 10,19.5 10,12.5', style: 'fill:var(--panel)' }));

function sidebar(active) {
  const item = (id, label) => h('a', { href: '#/' + id, class: active === id || (active === 'session' && id === 'sessions') || (active === 'ip' && id === 'attackers') || (active === 'xpod' && id === 'xpods') ? 'active' : '' }, label);
  return h('aside', { class: 'side' },
    h('div', { class: 'brand' }, LOGO(), 'Xpods Console'),
    h('nav', { class: 'nav' },
      item('overview', 'Overview'), item('events', 'Events'), item('sessions', 'Sessions'),
      item('attackers', 'Attackers'), item('xpods', 'Xpods'), item('assistant', 'Assistant'), item('telemetry', 'Telemetry'), item('audit', 'Audit log')),
    h('div', { class: 'spacer' }),
    h('div', { class: 'who' }, h('span', {}, state.user),
      h('button', { class: 'btn small', onclick: async () => { await api('/logout', { method: 'POST' }); state.user = null; render(); } }, 'Sign out')));
}

function topbar(title, ...right) {
  return h('div', { class: 'topbar' }, h('h1', {}, title), h('div', { class: 'grow' }), ...right);
}

async function loadClients() {
  if (!state.clients.length) {
    try { state.clients = await api('/clients'); } catch (e) { if (e instanceof AuthError) throw e; }
  }
  return state.clients;
}

function globalControls(onChange) {
  const ranges = ['1h', '24h', '7d', '30d', '90d', 'all'];
  const seg = h('div', { class: 'seg' }, ranges.map((r) => h('button', {
    class: r === state.since ? 'on' : '',
    onclick: () => { state.since = r; localStorage.setItem('since', r); onChange(); },
  }, r)));
  const sel = h('select', { onchange: (e) => { state.client = e.target.value; localStorage.setItem('client', state.client); onChange(); } },
    h('option', { value: '' }, 'All Xpods'),
    state.clients.map((c) => h('option', { value: c.name, selected: c.name === state.client }, c.name)));
  return [sel, seg];
}

// ------------------------------------------------------------------ widgets

function bars(rows, onClick, fmt = (k) => k) {
  if (!rows || !rows.length) return h('div', { class: 'empty' }, 'No data');
  const max = Math.max(...rows.map((r) => r.count));
  return h('div', { class: 'bars' }, rows.map((r) => h('div', {
    class: 'bar', title: r.key, onclick: onClick ? () => onClick(r.key) : null,
  }, h('div', { class: 'fill', style: `width:${(100 * r.count / max).toFixed(1)}%` }),
     h('span', { class: 'k' }, fmt(r.key)), h('span', { class: 'n' }, fmtN(r.count)))));
}

function panel(title, ...body) { return h('section', { class: 'panel' }, h('h2', {}, title), ...body); }

const RANGE_HOURS = { '1h': 1, '24h': 24, '7d': 168, '30d': 720, '90d': 2160 };

// Continuous bucket keys ('YYYY-MM-DDTHH' or 'YYYY-MM-DD', UTC) so gaps show as time.
function bucketRange(keys, bucket, since) {
  if (!keys.length) return keys;
  const step = bucket === 'hour' ? 3600e3 : 86400e3;
  const parse = (k) => Date.parse(bucket === 'hour' ? k + ':00:00Z' : k + 'T00:00:00Z');
  const fmt = (t) => new Date(t).toISOString().slice(0, bucket === 'hour' ? 13 : 10);
  let start = parse(keys[0]);
  if (RANGE_HOURS[since]) start = Math.min(start, parse(fmt(Date.now() - RANGE_HOURS[since] * 3600e3)));
  const end = Math.max(parse(keys[keys.length - 1]), parse(fmt(Date.now())));
  if ((end - start) / step > 400) return keys;
  const out = [];
  for (let t = start; t <= end; t += step) out.push(fmt(t));
  return out;
}

function timelineChart(rows, bucket, since) {
  const buckets = bucketRange([...new Set(rows.map((r) => r.bucket))].sort(), bucket, since);
  const protos = [...new Set(rows.map((r) => r.protocol || 'other'))];
  if (!buckets.length) return h('div', { class: 'empty' }, 'No events in this period');
  const byBucket = Object.fromEntries(buckets.map((b) => [b, {}]));
  rows.forEach((r) => { byBucket[r.bucket][r.protocol || 'other'] = r.count; });
  const totals = buckets.map((b) => Object.values(byBucket[b]).reduce((a, c) => a + c, 0));
  const max = Math.max(...totals, 1);
  const W = 1000, H = 190, L = 40, B = 22, T = 8;
  const bw = (W - L) / buckets.length;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const svg = h('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Events over time' });
  [0, 0.5, 1].forEach((f) => {
    const v = Math.round(max * f);
    svg.append(h('line', { class: 'gridline', x1: L, x2: W, y1: y(v), y2: y(v) }),
      h('text', { class: 'axis', x: L - 6, y: y(v) + 3, 'text-anchor': 'end' }, fmtN(v)));
  });
  const colors = Object.fromEntries(protos.map((p) => [p, protoColor(p)]));
  buckets.forEach((b, i) => {
    let acc = 0;
    const g = h('g', {}, h('title', {}, `${bucket === 'hour' ? b.replace('T', ' ') + ':00 UTC' : b}: ${fmtN(totals[i])} events`));
    protos.forEach((p) => {
      const v = byBucket[b][p] || 0;
      if (!v) return;
      g.append(h('rect', { x: L + i * bw + bw * 0.12, width: Math.max(1, bw * 0.76), y: y(acc + v), height: y(acc) - y(acc + v), fill: colors[p], rx: 1.5 }));
      acc += v;
    });
    svg.append(g);
    const every = Math.ceil(buckets.length / 8);
    if (i % every === 0) {
      const label = bucket === 'hour' ? b.slice(11, 13) + 'h' : b.slice(5);
      svg.append(h('text', { class: 'axis', x: L + i * bw + bw / 2, y: H - 6, 'text-anchor': 'middle' }, label));
    }
  });
  return h('div', { class: 'chart' }, svg,
    h('div', { class: 'legend' }, protos.map((p) => h('span', {}, h('i', { style: `background:${colors[p]}` }), p)),
      h('span', {}, `per ${bucket} (UTC)`)));
}

function eventSummary(e) {
  if (e.source === 'browser' || e.protocol === 'WEB') return (e.title ? e.title + ' — ' : '') + (e.url || '');
  if (e.protocol === 'HTTP') return `${e.method} ${e.uri}`;
  if (e.password || (e.user && !e.command)) return `login ${e.user}:${e.password}`;
  if (e.command) return e.command;
  return e.msg;
}

// ------------------------------------------------------------------ overview

async function viewOverview(main) {
  await loadClients();
  const refresh = () => render();
  main.append(topbar('Overview', h('button', { class: 'btn', onclick: () => askAssistant(`Summarize attack activity for the last ${state.since}${state.client ? ' on Xpod ' + state.client : ''} and highlight anything that needs attention.`) }, 'Ask assistant'), ...globalControls(refresh)));
  const s = await api('/stats' + qs(globalFilters()));
  const k = s.kpi;
  const toEvents = (extra) => () => go('/events', globalFilters(extra));
  main.append(
    h('div', { class: 'kpis' },
      [['Events', k.events], ['Unique source IPs', k.ips], ['Sessions', k.sessions], ['Login attempts', k.logins], ['Shell commands', k.commands]]
        .map(([l, v]) => h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(v)), h('div', { class: 'l' }, l))),
      h('div', { class: 'kpi' }, h('div', { class: 'v', style: 'font-size:16px;padding-top:8px' }, ago(k.last)), h('div', { class: 'l' }, 'Last activity'))),
    h('div', { class: 'stack' },
      panel('Activity', timelineChart(s.timeline, s.bucket, state.since)),
      h('div', { class: 'grid g3' },
        panel('Top source IPs', bars(s.ips, (ip) => go('/ip/' + encodeURIComponent(ip)))),
        panel('By protocol', bars(s.protocols, (p) => toEvents({ protocol: p })())),
        panel('By Xpod', bars(s.clients, (c) => { state.client = c; localStorage.setItem('client', c); refresh(); }))),
      h('div', { class: 'grid g3' },
        panel('Credentials tried', bars(s.credentials, (c) => toEvents({ q: c.split(' : ')[1] || c })())),
        panel('Usernames', bars(s.users, (u) => toEvents({ q: u })())),
        panel('Passwords', bars(s.passwords, (p) => toEvents({ q: p })()))),
      h('div', { class: 'grid g2' },
        panel('Shell commands', bars(s.commands, (c) => toEvents({ q: c })())),
        panel('HTTP requests', bars(s.uris, (u) => toEvents({ protocol: 'HTTP', q: u.split(' ').slice(1).join(' ') })()))),
      h('div', { class: 'grid g2' },
        panel('User agents', bars(s.agents, (a) => toEvents({ q: a })())),
        panel('TCP service payloads', bars(s.tcp_payloads, null))),
      s.urls && s.urls.length ? h('div', { class: 'grid g2' },
        panel('Top browsed URLs', bars(s.urls, (u) => toEvents({ source: 'browser', q: u })())),
        panel('', h('div', { class: 'crumb', style: 'padding:8px' }, 'Browser telemetry from enrolled devices. Manage devices under ',
          h('a', { href: '#/telemetry' }, 'Telemetry'), '.'))) : null));
}

// ------------------------------------------------------------------ events

async function viewEvents(main, _parts, params) {
  await loadClients();
  const f = { protocol: params.protocol || '', status: params.status || '', ip: params.ip || '', q: params.q || '', session: params.session || '' };
  if (params.since) state.since = params.since;
  if (params.client !== undefined) state.client = params.client;
  if (params.source !== undefined) { state.source = params.source; localStorage.setItem("source", state.source); }
  const apply = () => go('/events', globalFilters({ ...f, q: search.value.trim(), ip: ipIn.value.trim() }));
  const search = h('input', { type: 'search', placeholder: 'Search commands, URIs, credentials, payloads…', value: f.q, onkeydown: (e) => e.key === 'Enter' && apply() });
  const ipIn = h('input', { type: 'text', placeholder: 'Source IP', value: f.ip, size: 16, onkeydown: (e) => e.key === 'Enter' && apply() });
  const proto = h('select', { onchange: (e) => { f.protocol = e.target.value; apply(); } },
    h('option', { value: '' }, 'All protocols'), PROTOS.map((p) => h('option', { value: p, selected: p === f.protocol }, p)));
  const status = h('select', { onchange: (e) => { f.status = e.target.value; apply(); } },
    h('option', { value: '' }, 'Any status'), ['Start', 'Interaction', 'End', 'Stateless'].map((p) => h('option', { value: p, selected: p === f.status }, p)));
  const exportLink = (fmt, label) => h('a', { class: 'btn small', href: '/api/export' + qs({ ...globalFilters(f), format: fmt }) }, label);

  main.append(
    topbar('Events', ...globalControls(apply)),
    h('div', { class: 'filters' }, search, ipIn, proto, status,
      h('button', { class: 'btn primary', onclick: apply }, 'Search'),
      f.session ? h('span', { class: 'chip' }, 'session ' + f.session.slice(0, 8), ' ', h('a', { href: '#', onclick: (e) => { e.preventDefault(); f.session = ''; apply(); } }, '×')) : null,
      h('div', { style: 'flex:1' }),
      exportLink('csv', 'Export CSV'), exportLink('json', 'Export JSON'), exportLink('ioc', 'IP list')));

  const tbody = h('tbody');
  const detail = h('div', { class: 'panel drawer' }, h('div', { class: 'empty' }, 'Select an event to inspect it.'));
  const moreBox = h('div', { class: 'more' });
  main.append(h('div', { class: 'split' },
    h('div', { class: 'panel', style: 'padding:0' }, h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Time', 'Xpod', 'Protocol', 'Source', 'Activity'].map((t) => h('th', {}, t)))), tbody)), moreBox),
    detail));

  let selected = null;
  async function load(before) {
    const data = await api('/events' + qs({ ...globalFilters(f), limit: 100, before }));
    if (!before && !data.events.length) tbody.append(h('tr', {}, h('td', { colspan: 5, class: 'empty' }, 'No events match these filters.')));
    data.events.forEach((e) => {
      const tr = h('tr', { class: 'click', onclick: () => { selected?.classList.remove('sel'); tr.classList.add('sel'); selected = tr; showEvent(detail, e.id); } },
        h('td', { class: 'nowrap mono' }, fmtTs(e.ts)),
        h('td', {}, e.client),
        h('td', {}, protoBadge(e.protocol)),
        h('td', { class: 'nowrap mono' }, e.src_ip || '—'),
        h('td', { class: 'trunc', title: eventSummary(e) }, eventSummary(e)));
      tbody.append(tr);
    });
    moreBox.replaceChildren(data.next ? h('button', { class: 'btn', onclick: () => load(data.next) }, 'Load older events') : '');
  }
  await load();
}

async function showEvent(box, id) {
  const e = await api('/events/' + id);
  let raw = e.raw;
  try { raw = JSON.stringify(JSON.parse(e.raw), null, 2); } catch { /* keep raw */ }
  const browser = e.source === 'browser';
  const fields = [['Time', fmtTs(e.ts)], [browser ? 'Device group' : 'Xpod', e.client],
    ['URL', e.url], ['Page title', e.title], ['Device', e.device],
    ['Service', e.description], ['Status', `${e.status} — ${e.msg}`],
    ['Source', e.src_ip ? (e.src_port ? `${e.src_ip}:${e.src_port}` : e.src_ip) : ''],
    ['User', e.user], ['Password', e.password], ['Command', e.command],
    ['Output', e.output], ['HTTP', e.method ? `${e.method} ${e.uri}` : ''], ['Host', e.host], ['User agent', e.user_agent],
    ['Body', e.body], ['Client', e.client_ver], ['TLS SNI', e.tls_sni], ['Handler', e.handler]].filter(([, v]) => v);
  box.replaceChildren(
    h('h3', {}, protoBadge(e.protocol), ' Event #', e.id),
    h('div', { class: 'actions', style: 'margin:10px 0 14px' },
      e.src_ip ? h('a', { class: 'btn small', href: '#/ip/' + encodeURIComponent(e.src_ip) }, 'Investigate IP') : null,
      e.session && e.status !== 'Stateless' ? h('a', { class: 'btn small', href: '#/session/' + encodeURIComponent(e.session) }, 'Open session') : null),
    h('dl', { class: 'kv' }, fields.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
    raw ? h('h2', { style: 'margin-top:16px' }, 'Raw event') : null,
    raw ? h('pre', { class: 'raw' }, raw) : null);
}

// ------------------------------------------------------------------ sessions

async function viewSessions(main, _parts, params) {
  await loadClients();
  const f = { protocol: params.protocol || '', ip: params.ip || '' };
  const reload = () => go('/sessions', { ...f });
  const proto = h('select', { onchange: (e) => { f.protocol = e.target.value; reload(); } },
    h('option', { value: '' }, 'All protocols'), PROTOS.filter((p) => p !== 'HTTP').map((p) => h('option', { value: p, selected: p === f.protocol }, p)));
  main.append(topbar('Sessions', ...globalControls(render)), h('div', { class: 'filters' }, proto));
  const rows = await api('/sessions' + qs({ ...globalFilters(f), limit: 300 }));
  main.append(h('div', { class: 'panel', style: 'padding:0' }, h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Started', 'Duration', 'Xpod', 'Protocol', 'Source', 'User', 'Service', 'Interactions'].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.length ? rows.map((s) => h('tr', { class: 'click', onclick: () => go('/session/' + encodeURIComponent(s.session)) },
      h('td', { class: 'nowrap mono' }, fmtTs(s.start)), h('td', { class: 'nowrap' }, duration(s.start, s.end)),
      h('td', {}, s.client), h('td', {}, protoBadge(s.protocol)), h('td', { class: 'mono' }, s.src_ip || '—'),
      h('td', { class: 'mono' }, s.user || ''), h('td', {}, s.description || ''), h('td', {}, fmtN(s.interactions))))
      : h('tr', {}, h('td', { colspan: 8, class: 'empty' }, 'No interactive sessions in this period.')))))));
}

async function viewSession(main, parts) {
  const id = parts[0];
  const rows = await api('/sessions/' + encodeURIComponent(id));
  const first = rows[0];
  const ip = rows.find((r) => r.src_ip)?.src_ip;
  const user = rows.find((r) => r.user)?.user || 'user';
  const interactive = ['SSH', 'TELNET'].includes(first.protocol);
  main.append(
    h('div', { class: 'crumb' }, h('a', { href: '#/sessions' }, 'Sessions'), ' / ', id),
    topbar(`${first.protocol} session`, h('button', { class: 'btn primary', onclick: () => askAssistant(`Explain session ${id}: what did the attacker try to do?`) }, 'Explain with assistant'), ip ? h('a', { class: 'btn', href: '#/ip/' + encodeURIComponent(ip) }, 'Investigate ' + ip) : null,
      h('a', { class: 'btn', href: '#/events' + qs({ session: id, since: 'all' }) }, 'Show as events')),
    h('div', { class: 'kpis' },
      [['Xpod', first.client], ['Service', first.description || first.protocol], ['Source', ip || '—'],
        ['Started', fmtTs(first.ts)], ['Duration', duration(first.ts, rows[rows.length - 1].ts)],
        ['Interactions', rows.filter((r) => r.status === 'Interaction').length]]
        .map(([l, v]) => h('div', { class: 'kpi' }, h('div', { class: 'v', style: 'font-size:15px' }, v), h('div', { class: 'l' }, l)))));
  const term = h('div', { class: 'term' });
  rows.forEach((r) => {
    const ts = h('span', { class: 'ts' }, fmtTs(r.ts).slice(11));
    if (r.status === 'Interaction') {
      if (interactive) term.append(h('div', { class: 'line' }, ts, h('span', { class: 'prompt' }, `${user}@${first.client}:~$ `), h('span', { class: 'cmd' }, r.command)));
      else term.append(h('div', { class: 'line' }, ts, h('span', { class: 'prompt' }, '>> '), h('span', { class: 'cmd' }, r.command)));
      if (r.output) term.append(h('div', { class: 'line out' }, r.output));
    } else {
      const extra = r.password ? ` (${r.user}:${r.password})` : r.user ? ` (user ${r.user})` : '';
      term.append(h('div', { class: 'line sys' }, ts, `# ${r.msg}${extra}`));
    }
  });
  main.append(panel('Transcript', term));
}

// ------------------------------------------------------------------ attackers + IP profile

async function viewAttackers(main) {
  await loadClients();
  main.append(topbar('Attackers', ...globalControls(render)));
  const rows = await api('/attackers' + qs(globalFilters({ limit: 500 })));
  main.append(h('div', { class: 'panel', style: 'padding:0' }, h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Source IP', 'Events', 'Protocols', 'Xpods', 'Logins', 'First seen', 'Last seen', 'Tags'].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.length ? rows.map((r) => h('tr', { class: 'click', onclick: () => go('/ip/' + encodeURIComponent(r.ip)) },
      h('td', { class: 'mono' }, r.ip), h('td', {}, fmtN(r.events)),
      h('td', {}, (r.protocol_list || '').split(',').filter(Boolean).map(protoBadge).flatMap((b) => [b, ' '])),
      h('td', {}, r.clients), h('td', {}, fmtN(r.logins)),
      h('td', { class: 'nowrap mono' }, fmtTs(r.first)), h('td', { class: 'nowrap mono' }, fmtTs(r.last)),
      h('td', {}, (r.tags || '').split(' ').filter(Boolean).map((t) => h('span', { class: 'badge tag' }, t)))))
      : h('tr', {}, h('td', { colspan: 8, class: 'empty' }, 'No attackers seen in this period.')))))));
}

async function viewIp(main, parts) {
  const ip = parts[0];
  const p = await api('/ips/' + encodeURIComponent(ip));
  const enc = encodeURIComponent(ip);
  const intel = isPublicIp(ip) ? [
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${enc}`], ['GreyNoise', `https://viz.greynoise.io/ip/${enc}`],
    ['Shodan', `https://www.shodan.io/host/${enc}`], ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${enc}`],
  ].map(([l, u]) => h('a', { class: 'btn small', href: u, target: '_blank', rel: 'noopener noreferrer' }, l + ' ↗')) : [h('span', { class: 'crumb' }, 'private address: no external intel')];

  const tags = h('input', { type: 'text', style: 'width:100%', value: p.note.tags, placeholder: 'scanner botnet mirai …' });
  const note = h('textarea', { rows: 6, placeholder: 'Investigation notes…' }, p.note.note);
  const saveMsg = h('span', { class: 'crumb' }, p.note.updated ? `saved ${ago(p.note.updated)} by ${p.note.updated_by}` : '');
  const save = async () => {
    await api(`/ips/${enc}/note`, { method: 'PUT', body: { tags: tags.value, note: note.value } });
    saveMsg.textContent = 'saved just now';
  };
  const s = p.summary;
  const toEvents = (extra) => () => go('/events', { since: 'all', ip, ...extra });
  main.append(
    h('div', { class: 'crumb' }, h('a', { href: '#/attackers' }, 'Attackers'), ' / ', ip),
    topbar(ip, h('button', { class: 'btn primary', onclick: () => askAssistant(`Investigate ${ip}: what did it do, what is its likely intent, and what should we do about it?`) }, 'Ask assistant'),
      h('a', { class: 'btn', href: '#/events' + qs({ ip, since: 'all' }) }, 'All events'),
      h('a', { class: 'btn', href: '/api/export' + qs({ ip, since: 'all', format: 'csv' }) }, 'Export CSV')),
    h('div', { class: 'kpis' },
      [['Events', fmtN(s.events)], ['Sessions', fmtN(s.sessions)], ['Login attempts', fmtN(s.logins)], ['First seen', fmtTs(s.first)], ['Last seen', fmtTs(s.last)]]
        .map(([l, v]) => h('div', { class: 'kpi' }, h('div', { class: 'v', style: 'font-size:17px' }, v), h('div', { class: 'l' }, l)))),
    h('div', { class: 'stack' },
      h('div', { class: 'grid g2' },
        panel('Threat intel', h('div', { class: 'actions' }, intel),
          h('h2', { style: 'margin-top:16px' }, 'Tags & notes'),
          h('div', { class: 'stack' }, tags, note, h('div', { class: 'actions', style: 'align-items:center' }, h('button', { class: 'btn primary', onclick: save }, 'Save'), saveMsg))),
        panel('Activity by day', timelineChart(p.activity.map((a) => ({ ...a, protocol: 'events' })), 'day'))),
      h('div', { class: 'grid g3' },
        panel('Protocols', bars(p.protocols, (x) => toEvents({ protocol: x })())),
        panel('Xpods targeted', bars(p.clients)),
        panel('Client software', bars([...p.clients_ver, ...p.agents]))),
      h('div', { class: 'grid g3' },
        panel('Credentials', bars(p.credentials)),
        panel('Commands', bars(p.commands, (c) => toEvents({ q: c })())),
        panel('HTTP requests', bars(p.uris))),
      panel('Sessions', p.sessions.length ? h('div', { class: 'tablewrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Started', 'Duration', 'Xpod', 'Protocol', 'User', 'Interactions'].map((t) => h('th', {}, t)))),
        h('tbody', {}, p.sessions.map((x) => h('tr', { class: 'click', onclick: () => go('/session/' + encodeURIComponent(x.session)) },
          h('td', { class: 'mono nowrap' }, fmtTs(x.start)), h('td', {}, duration(x.start, x.end)), h('td', {}, x.client),
          h('td', {}, protoBadge(x.protocol)), h('td', { class: 'mono' }, x.user), h('td', {}, fmtN(x.interactions)))))))
        : h('div', { class: 'empty' }, 'No interactive sessions.'))));
}

// ------------------------------------------------------------------ Xpods

function confirmButton(label, onConfirm, cls = 'btn small danger') {
  const b = h('button', { class: cls }, label);
  let armed = false;
  b.addEventListener('click', () => {
    if (!armed) {
      armed = true; b.classList.add('armed'); b.textContent = `Confirm ${label.toLowerCase()}?`;
      setTimeout(() => { armed = false; b.classList.remove('armed'); b.textContent = label; }, 4000);
      return;
    }
    onConfirm();
  });
  return b;
}

async function runAction(client, action, consoleBox, onDone) {
  consoleBox.hidden = false;
  consoleBox.textContent = `$ deploy.sh ${action} ${client}\n`;
  let job;
  try { job = await api(`/clients/${encodeURIComponent(client)}/actions/${action}`, { method: 'POST' }); } catch (e) {
    consoleBox.textContent += `error: ${e.message}\n`; return;
  }
  followJob(job.id, consoleBox, onDone);
}

function followJob(jobId, consoleBox, onDone) {
  consoleBox.hidden = false;
  const timer = setInterval(async () => {
    let j;
    try { j = await api('/jobs/' + jobId); } catch { clearInterval(timer); return; }
    const stick = consoleBox.scrollTop + consoleBox.clientHeight >= consoleBox.scrollHeight - 20;
    consoleBox.textContent = `$ deploy.sh ${j.action} ${j.client}\n` + j.output + (j.state === 'running' ? '' : `\n[${j.state}, exit ${j.returncode}]`);
    if (stick) consoleBox.scrollTop = consoleBox.scrollHeight;
    if (j.state !== 'running') { clearInterval(timer); state.clients = []; onDone && onDone(j); }
  }, 1000);
  state.timers.push(timer);
}

async function viewXpods(main) {
  state.clients = [];
  const clients = await loadClients();
  const msg = h('div');
  const name = h('input', { type: 'text', placeholder: 'acme', required: true });
  const domain = h('input', { type: 'text', placeholder: 'portal.acme.com', required: true });
  const host = h('input', { type: 'text', placeholder: 'web01', value: 'web01' });
  const newForm = h('form', { class: 'panel', hidden: true, onsubmit: async (e) => {
    e.preventDefault();
    try {
      await api('/clients', { method: 'POST', body: { name: name.value.trim(), domain: domain.value.trim(), hostname: host.value.trim() } });
      go('/xpod/' + encodeURIComponent(name.value.trim()));
    } catch (err) { msg.replaceChildren(h('div', { class: 'msg err' }, err.message)); }
  } },
  h('h3', {}, 'New Xpod'), msg,
  h('div', { class: 'form' },
    h('label', {}, 'Client name'), name, h('div', { class: 'hint' }, 'lowercase letters, digits, dashes'),
    h('label', {}, 'Domain (A record)'), domain,
    h('label', {}, 'Fake hostname'), host, h('div', { class: 'hint' }, 'shown in SSH/Telnet prompts'),
    h('span'), h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Create'),
      h('button', { class: 'btn', type: 'button', onclick: () => { newForm.hidden = true; } }, 'Cancel'))));

  main.append(topbar('Xpods', h('button', { class: 'btn primary', onclick: () => { newForm.hidden = false; name.focus(); } }, '+ New Xpod')), newForm);
  if (!clients.length) {
    main.append(h('div', { class: 'panel empty' }, 'No Xpods configured yet. Create one to get started.'));
    return;
  }
  const cards = h('div', { class: 'cards', style: 'margin-top:16px' });
  clients.forEach((c) => {
    const out = h('pre', { class: 'console', hidden: true });
    const act = (a) => runAction(c.name, a, out, () => render());
    const running = c.state === 'running';
    cards.append(h('div', { class: 'panel card' },
      h('h3', {}, h('a', { href: '#/xpod/' + encodeURIComponent(c.name) }, c.name), stateBadge(c.job ? 'busy' : c.state)),
      h('div', { class: 'meta' }, c.domain, ' · ', c.hostname, ' · bind ', c.bind_ip),
      h('div', {}, c.services.map((s) => h('span', { class: 'chip' }, s))),
      h('div', { class: 'stats' },
        h('div', {}, h('b', {}, fmtN(c.stats.last24h)), h('span', {}, 'events 24h')),
        h('div', {}, h('b', {}, fmtN(c.stats.events)), h('span', {}, 'events total')),
        h('div', {}, h('b', { style: 'font-size:14px;padding-top:4px' }, ago(c.stats.last)), h('span', {}, 'last activity'))),
      h('div', { class: 'actions' },
        h('button', { class: 'btn small primary', disabled: !!c.job, onclick: () => act('up') }, running ? 'Redeploy' : 'Deploy'),
        running ? h('button', { class: 'btn small', disabled: !!c.job, onclick: () => act('restart') }, 'Restart') : null,
        running ? confirmButton('Stop', () => act('down')) : null,
        h('a', { class: 'btn small', href: '#/xpod/' + encodeURIComponent(c.name) }, 'Configure'),
        h('a', { class: 'btn small', href: '#/events' + qs({ client: c.name, since: '24h' }) }, 'Events')),
      out));
    if (c.job) followJob(c.job, out, () => render());
  });
  main.append(cards);
  state.timers.push(setInterval(async () => {
    // Refresh counters quietly while nothing is running.
    if (!document.querySelector('.console:not([hidden])')) render();
  }, 30000));
}

async function viewXpod(main, parts) {
  const name = parts[0];
  const c = await api('/clients/' + encodeURIComponent(name));
  const env = c.env;
  const msg = h('div');
  const out = h('pre', { class: 'console', hidden: true });
  const reload = () => render();
  const act = (a) => runAction(name, a, out, reload);
  const running = c.containers.some((x) => x.service === 'beelzebub' && x.state === 'running');

  // settings form
  const inputs = {};
  const text = (key, attrs = {}) => (inputs[key] = h('input', { type: c.secrets.includes(key) ? 'password' : 'text', value: env[key] ?? '', autocomplete: 'off', ...attrs }));
  const select = (key, opts) => (inputs[key] = h('select', {}, opts.map((o) => h('option', { value: o, selected: env[key] === o }, o))));
  const enabled = new Set((env.HP_SERVICES || '').split(/\s+/).filter(Boolean));
  const checks = c.services.map((s) => {
    const cb = h('input', { type: 'checkbox', value: s, checked: enabled.has(s) });
    return { s, cb, el: h('label', {}, cb, s) };
  });
  const row = (label, input, hint) => [h('label', {}, label), input, hint ? h('div', { class: 'hint' }, hint) : null];

  const save = async () => {
    const body = { HP_SERVICES: checks.filter((x) => x.cb.checked).map((x) => x.s).join(' ') };
    for (const [k, el] of Object.entries(inputs)) body[k] = el.value;
    try {
      const r = await api(`/clients/${encodeURIComponent(name)}/settings`, { method: 'PUT', body });
      msg.replaceChildren(h('div', { class: 'msg ok' }, r.changed.length ? `Saved: ${r.changed.join(', ')}. Redeploy to apply.` : 'No changes.'));
    } catch (e) { msg.replaceChildren(h('div', { class: 'msg err' }, e.message)); }
  };

  main.append(
    h('div', { class: 'crumb' }, h('a', { href: '#/xpods' }, 'Xpods'), ' / ', name),
    topbar(name, stateBadge(c.job ? 'busy' : running ? 'running' : (c.containers[0]?.state || 'not deployed')),
      h('button', { class: 'btn primary', onclick: () => act('up') }, running ? 'Redeploy' : 'Deploy'),
      h('button', { class: 'btn', onclick: () => act('validate') }, 'Validate'),
      running ? h('button', { class: 'btn', onclick: () => act('restart') }, 'Restart') : null,
      env.HP_TLS === 'letsencrypt' ? h('button', { class: 'btn', onclick: () => act('cert') }, 'Issue certificate') : null,
      running ? confirmButton('Stop', () => act('down'), 'btn danger') : null),
    out,
    h('div', { class: 'grid g2', style: 'margin-top:16px;align-items:start' },
      h('div', { class: 'stack' },
        panel('Settings', msg, h('div', { class: 'form' },
          row('Domain', text('HP_DOMAIN'), 'the A record pointing at this Xpod'),
          row('Fake hostname', text('HP_HOSTNAME')),
          row('Bind IP', text('HP_BIND_IP'), '0.0.0.0 = all interfaces; use a dedicated public IP per client'),
          row('TLS', select('HP_TLS', ['selfsigned', 'letsencrypt'])),
          row('Let\'s Encrypt email', text('HP_LETSENCRYPT_EMAIL')),
          row('Metrics port', text('HP_METRICS_PORT'), 'published on 127.0.0.1 only'),
          row('Container memory', text('HP_CONTAINER_MEM')),
          row('CPUs', text('HP_CPUS')),
          row('Log rotate (MB)', text('HP_LOG_MAX_MB')),
          row('Log retention (days)', text('HP_LOG_KEEP_DAYS')),
          row('Ship to URL', text('HP_SHIP_URL'), 'optional central collector (enables Vector sidecar)'),
          row('Ship auth header', text('HP_SHIP_AUTH_HEADER'))),
        h('h2', { style: 'margin-top:18px' }, 'Services'),
        h('div', { class: 'checks' }, checks.map((x) => x.el)),
        h('div', { class: 'actions', style: 'margin-top:16px' }, h('button', { class: 'btn primary', onclick: save }, 'Save settings')))),
      h('div', { class: 'stack' },
        panel('Containers', c.containers.length ? h('table', {}, h('tbody', {}, c.containers.map((x) => h('tr', {},
          h('td', {}, x.service), h('td', {}, stateBadge(x.state)), h('td', { class: 'crumb' }, x.status)))))
          : h('div', { class: 'empty' }, 'Not deployed.')),
        customLures(name, c.custom),
        firewallPanel(name))));
  if (c.job) followJob(c.job, out, reload);
}

function customLures(client, files) {
  const box = h('div');
  const editor = h('textarea', { rows: 16, spellcheck: 'false' });
  const fname = h('input', { type: 'text', placeholder: 'http-8443-vpn.yaml' });
  const msg = h('div');
  const editorBox = h('div', { class: 'stack', hidden: true }, fname, editor, msg,
    h('div', { class: 'actions' },
      h('button', { class: 'btn primary', onclick: async () => {
        try {
          await api(`/clients/${encodeURIComponent(client)}/custom/${encodeURIComponent(fname.value.trim())}`, { method: 'PUT', body: { content: editor.value } });
          render();
        } catch (e) { msg.replaceChildren(h('div', { class: 'msg err' }, e.message)); }
      } }, 'Save lure'),
      h('button', { class: 'btn', onclick: () => { editorBox.hidden = true; } }, 'Close')),
    h('div', { class: 'crumb' }, 'Applied on next deploy. Run Validate to check it against the beelzebub schema.'));
  const open = async (name) => {
    fname.value = name || '';
    editor.value = name ? (await api(`/clients/${encodeURIComponent(client)}/custom/${encodeURIComponent(name)}`)).content
      : 'apiVersion: "v1"\nprotocol: "http"\naddress: ":8443"\ndescription: "Custom lure"\ncommands:\n  - regex: "^(/)$"\n    handler: "<html><title>Login</title></html>"\n    headers:\n      - "Content-Type: text/html"\n    statusCode: 200\n';
    editorBox.hidden = false;
  };
  box.append(files.length ? h('table', {}, h('tbody', {}, files.map((f) => h('tr', {},
    h('td', { class: 'mono' }, h('a', { href: '#', onclick: (e) => { e.preventDefault(); open(f.name); } }, f.name)),
    h('td', { class: 'crumb' }, `${f.size} B`),
    h('td', { style: 'text-align:right' }, confirmButton('Delete', async () => {
      await api(`/clients/${encodeURIComponent(client)}/custom/${encodeURIComponent(f.name)}`, { method: 'DELETE' }); render();
    }))))))
    : h('div', { class: 'empty' }, 'No custom lures. Generated services come from the Services list.'));
  return panel('Custom lures', box, h('div', { class: 'actions', style: 'margin:10px 0' }, h('button', { class: 'btn small', onclick: () => open(null) }, '+ New lure')), editorBox);
}

function firewallPanel(client) {
  const pre = h('pre', { class: 'console', hidden: true });
  return panel('Egress lockdown',
    h('div', { class: 'crumb', style: 'margin-bottom:10px' }, 'iptables rules that stop the Xpod from opening outbound connections. Review and apply them on the host as root.'),
    h('button', { class: 'btn small', onclick: async () => {
      const r = await api(`/clients/${encodeURIComponent(client)}/firewall`);
      pre.hidden = false; pre.textContent = r.output;
    } }, 'Show rules'), pre);
}

// ------------------------------------------------------------------ assistant

function askAssistant(prompt) { go('/assistant', { ask: prompt }); }

// Minimal, safe markdown: code fences, lists, headings, **bold**, `code`; IPs become links.
function mdInline(text) {
  const out = [];
  const re = /(\*\*[^*\n]+\*\*|`[^`\n]+`|\b(?:\d{1,3}\.){3}\d{1,3}\b)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith('**')) out.push(h('strong', {}, t.slice(2, -2)));
    else if (t.startsWith('`')) out.push(h('code', {}, t.slice(1, -1)));
    else out.push(h('a', { href: '#/ip/' + encodeURIComponent(t) }, t));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function renderMd(text) {
  const root = h('div', { class: 'md' });
  const parts = text.split(/```[\w-]*\n?/);
  parts.forEach((part, i) => {
    if (i % 2 === 1) { root.append(h('pre', { class: 'raw' }, part.replace(/\n$/, ''))); return; }
    let list = null, para = [];
    const flush = () => { if (para.length) { root.append(h('p', {}, para.flatMap((l, j) => j ? [h('br'), ...mdInline(l)] : mdInline(l)))); para = []; } };
    for (const line of part.split('\n')) {
      const li = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
      const hd = line.match(/^#{1,4}\s+(.*)$/);
      if (li) {
        flush();
        if (!list) { list = h(/^\s*\d/.test(line) ? 'ol' : 'ul'); root.append(list); }
        list.append(h('li', {}, mdInline(li[1])));
      } else if (hd) { flush(); list = null; root.append(h('h4', {}, mdInline(hd[1]))); }
      else if (!line.trim()) { flush(); list = null; }
      else { list = null; para.push(line); }
    }
    flush();
  });
  return root;
}

function toolLabel(name, args) {
  const a = Object.entries(args || {}).filter(([k, v]) => k !== 'diff' && v !== '' && v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' ');
  return `${name}${a ? ' · ' + a : ''}`;
}

function toolChip(name, args, content, done = true) {
  const chip = h('details', { class: 'toolchip' + (done ? ' done' : '') },
    h('summary', {}, h('span', { class: 'dot' }), toolLabel(name, args)));
  if (content !== undefined) {
    let pretty = content;
    try { pretty = JSON.stringify(JSON.parse(content).untrusted_data, null, 2); } catch { /* raw */ }
    chip.append(h('pre', { class: 'raw' }, pretty));
  }
  return chip;
}

function confirmCard(meta) {
  const body = h('div');
  const out = h('pre', { class: 'console', hidden: true });
  const status = h('span', { class: 'badge state-other' }, meta.status);
  const setStatus = (s) => {
    status.textContent = s;
    status.className = 'badge ' + (s === 'approved' ? 'state-running' : s === 'pending' ? 'state-other' : 'state-failed');
  };
  setStatus(meta.status);
  const decide = async (approve) => {
    buttons.replaceChildren(h('span', { class: 'crumb' }, approve ? 'Running…' : 'Rejecting…'));
    try {
      const r = await api('/assistant/actions/' + meta.id, { method: 'POST', body: { approve } });
      setStatus(r.status);
      buttons.replaceChildren();
      if (r.error) body.append(h('div', { class: 'msg err' }, r.error));
      if (r.changed) body.append(h('div', { class: 'msg ok' }, r.changed.length ? `Changed: ${r.changed.join(', ')}. Redeploy to apply.` : 'No changes were needed.'));
      if (r.job) followJob(r.job, out, () => {});
      state.clients = [];
    } catch (e) { buttons.replaceChildren(h('div', { class: 'msg err' }, e.message)); }
  };
  const buttons = h('div', { class: 'actions' });
  if (meta.status === 'pending') {
    buttons.append(meta.suspicious ? confirmButton('Approve', () => decide(true), 'btn small danger')
      : h('button', { class: 'btn small primary', onclick: () => decide(true) }, 'Approve'),
    h('button', { class: 'btn small', onclick: () => decide(false) }, 'Reject'));
  }
  if (meta.result?.error) body.append(h('div', { class: 'msg err' }, meta.result.error));
  return h('div', { class: 'confirm' },
    h('div', { class: 'confirm-head' }, h('strong', {}, 'Action proposed by the assistant'), status),
    h('div', { class: 'confirm-desc' }, meta.description),
    meta.suspicious ? h('div', { class: 'msg err' }, 'Possible prompt injection: this conversation read attacker data containing instructions aimed at the assistant. Only approve if you asked for this yourself.') : null,
    h('div', { class: 'crumb' }, 'Review before approving: the assistant reads attacker-controlled data and can be manipulated.'),
    buttons, body, out);
}

async function modelPanel() {
  const box = h('div', { class: 'modelbar' });
  let st;
  try { st = await api('/assistant/status'); } catch (e) { if (e instanceof AuthError) throw e; st = { reachable: false }; }
  const dot = (ok) => h('span', { class: 'dot ' + (ok ? 'ok' : 'bad') });
  if (!st.reachable) {
    box.append(dot(false), h('span', {}, 'Local LLM unreachable. Start it with ', h('code', {}, 'cd console && ./console.sh up'), '.'));
  } else if (!st.installed) {
    const prog = h('span', { class: 'crumb' });
    const btn = h('button', { class: 'btn small primary', onclick: async () => {
      btn.disabled = true;
      const res = await fetch('/api/assistant/pull', { method: 'POST', credentials: 'same-origin', headers: { 'X-Requested-With': 'console' } });
      const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        for (const l of lines) {
          try {
            const j = JSON.parse(l);
            prog.textContent = j.error ? 'error: ' + j.error : j.total ? `${j.status} ${Math.round(100 * (j.completed || 0) / j.total)}%` : j.status;
          } catch { /* partial */ }
        }
      }
      render();
    } }, `Download ${st.model}`);
    box.append(dot(false), h('span', {}, `Model ${st.model} is not installed.`), btn, prog);
  } else {
    box.append(dot(true), h('span', {}, 'Local model ', h('code', {}, st.model), ' ready — runs on this host, no data leaves it.'));
  }
  return box;
}

const SUGGESTIONS = [
  'Summarize attack activity in the last 24 hours',
  'Which credentials are attackers trying most?',
  'Investigate the most active attacker',
  'Did anyone try to download malware in a shell?',
  'Are all Xpods healthy?',
];

async function viewAssistant(main, parts, params) {
  if (params.ask) {
    const { id } = await api('/assistant/conversations', { method: 'POST', body: { title: params.ask } });
    state.pendingAsk = params.ask;
    history.replaceState(null, '', '#/assistant/' + id);
    parts = [id];
  }
  const convId = parts[0];
  const convs = await api('/assistant/conversations');
  const list = h('div', { class: 'convlist' },
    h('button', { class: 'btn primary', style: 'width:100%', onclick: async () => {
      const { id } = await api('/assistant/conversations', { method: 'POST', body: {} }); go('/assistant/' + id);
    } }, '+ New chat'),
    convs.map((c) => h('div', { class: 'conv' + (c.id === convId ? ' active' : '') },
      h('a', { href: '#/assistant/' + c.id, title: c.title }, c.title),
      h('button', { class: 'x', title: 'Delete', onclick: async () => {
        await api('/assistant/conversations/' + c.id, { method: 'DELETE' });
        go('/assistant' + (c.id === convId ? '' : '/' + convId));
        if (c.id !== convId) render();
      } }, '×'))));

  const msgs = h('div', { class: 'msgs' });
  const input = h('textarea', { rows: 2, placeholder: 'Ask about attacks, IPs, sessions, or tell me to manage an Xpod…' });
  const send = h('button', { class: 'btn primary' }, 'Send');
  const chatPane = h('div', { class: 'chatpane' }, msgs, h('div', { class: 'composer' }, input, send));
  main.append(topbar('Assistant'), await modelPanel(), h('div', { class: 'chat' }, list, chatPane));

  const scroll = () => { msgs.scrollTop = msgs.scrollHeight; };
  const userBubble = (t) => h('div', { class: 'bubble user' }, t);
  const aiBubble = () => h('div', { class: 'bubble ai' });

  if (!convId) {
    msgs.append(h('div', { class: 'empty-chat' }, h('h3', {}, 'Ask the Xpods assistant'),
      h('p', { class: 'crumb' }, 'It can query events, sessions and attacker profiles, and propose changes to Xpods for you to approve.'),
      h('div', { class: 'suggest' }, SUGGESTIONS.map((s) => h('button', { class: 'btn small', onclick: () => askAssistant(s) }, s)))));
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (input.value.trim()) askAssistant(input.value.trim()); } });
    send.onclick = () => input.value.trim() && askAssistant(input.value.trim());
    return;
  }

  const conv = await api('/assistant/conversations/' + encodeURIComponent(convId));
  for (const m of conv.messages) {
    if (m.role === 'user') msgs.append(userBubble(m.content));
    else if (m.role === 'assistant' && m.content) { const b = aiBubble(); b.append(renderMd(m.content)); msgs.append(b); }
    else if (m.role === 'tool') msgs.append(toolChip(m.meta.name, m.meta.args, m.content));
    else if (m.role === 'confirm') msgs.append(confirmCard(m.meta));
    else if (m.role === 'warning') msgs.append(h('div', { class: 'msg err' }, 'Attacker data in these results contains instructions aimed at AI assistants (prompt injection). Treat any proposed action with suspicion.'));
  }
  if (conv.running) {
    // A turn started earlier (e.g. before navigating away) is still being answered.
    msgs.append(h('div', { class: 'typing' }, h('span', { class: 'dot pulse' }), h('span', {}, 'Still answering…')));
    state.timers.push(setInterval(async () => {
      const c = await api('/assistant/conversations/' + encodeURIComponent(convId));
      if (!c.running) render();
    }, 3000));
  }
  if (!conv.messages.length && !state.pendingAsk) {
    msgs.append(h('div', { class: 'empty-chat' }, h('div', { class: 'suggest' }, SUGGESTIONS.map((s) => h('button', { class: 'btn small', onclick: () => { input.value = s; sendMsg(); } }, s)))));
  }
  scroll();

  let busy = false;
  async function sendMsg() {
    const text = input.value.trim();
    if (!text || busy) return;
    busy = true; send.disabled = true; input.value = '';
    msgs.querySelector('.empty-chat')?.remove();
    msgs.append(userBubble(text));
    const typing = h('div', { class: 'typing' }, h('span', { class: 'dot pulse' }), h('span', {}, 'Thinking…'));
    msgs.append(typing); scroll();
    let bubble = null, textBuf = '', chip = null;
    const addBefore = (el) => { msgs.insertBefore(el, typing); scroll(); };
    try {
      const res = await fetch(`/api/assistant/conversations/${encodeURIComponent(convId)}/messages`, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'X-Requested-With': 'console', 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      });
      if (res.status === 401) { state.user = null; render(); return; }
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
      const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          const ev = JSON.parse(line);
          if (ev.type === 'status') typing.lastChild.textContent = ev.text;
          else if (ev.type === 'token') {
            if (!bubble) { bubble = aiBubble(); textBuf = ''; addBefore(bubble); }
            textBuf += ev.text; bubble.replaceChildren(renderMd(textBuf)); scroll();
            typing.lastChild.textContent = 'Writing…';
          } else if (ev.type === 'tool_call') {
            bubble = null;
            chip = toolChip(ev.name, ev.args, undefined, false); addBefore(chip);
            typing.lastChild.textContent = `Running ${ev.name}…`;
          } else if (ev.type === 'tool_result') { chip?.classList.add('done'); }
          else if (ev.type === 'confirm') { bubble = null; addBefore(confirmCard(ev)); }
          else if (ev.type === 'error') addBefore(h('div', { class: 'msg err' }, ev.text));
          else if (ev.type === 'warning') addBefore(h('div', { class: 'msg err' }, ev.text));
        }
      }
    } catch (e) {
      if (!(e instanceof AuthError)) msgs.insertBefore(h('div', { class: 'msg err' }, e.message), typing);
    } finally {
      typing.remove(); busy = false; send.disabled = false; input.focus();
      // Refresh stored tool payloads and titles.
      if (location.hash.startsWith('#/assistant/' + convId)) {
        const title = list.querySelector('.conv.active a');
        if (title && title.textContent === 'New chat') render();
      }
    }
  }
  send.onclick = sendMsg;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); } });
  if (state.pendingAsk) { input.value = state.pendingAsk; state.pendingAsk = null; sendMsg(); } else input.focus();
}

// ------------------------------------------------------------------ telemetry / enrollments

async function viewTelemetry(main) {
  let health = {};
  try { health = await api('/store/status'); } catch (e) { if (e instanceof AuthError) throw e; }
  const rows = await api('/enrollments');
  const msg = h('div');
  const tokenBox = h('div');

  const label = h('input', { type: 'text', placeholder: 'Field Laptop 1', maxlength: 49 });
  const create = async () => {
    msg.replaceChildren();
    try {
      const r = await api('/enrollments', { method: 'POST', body: { label: label.value.trim() } });
      label.value = '';
      tokenBox.replaceChildren(h('div', { class: 'msg ok' },
        h('div', {}, h('strong', {}, 'Enrollment created: '), r.label),
        h('p', { style: 'margin:8px 0 4px' }, 'Token (shown once — copy it into the extension now):'),
        h('pre', { class: 'raw', style: 'user-select:all' }, r.token)));
      render();
    } catch (e) { msg.replaceChildren(h('div', { class: 'msg err' }, e.message)); }
  };

  const storeLine = health.reachable
    ? h('span', {}, h('span', { class: 'dot ok' }), ` Event store online — ${fmtN(health.docs)} events, cluster ${health.status}.`)
    : h('span', {}, h('span', { class: 'dot bad' }), ' Event store unreachable.');

  const origin = location.origin;
  main.append(
    topbar('Telemetry'),
    h('div', { class: 'modelbar' }, storeLine),
    h('div', { class: 'grid g2', style: 'align-items:start' },
      h('div', { class: 'stack' },
        panel('Enroll a device',
          h('div', { class: 'crumb', style: 'margin-bottom:10px' },
            'Create a token, then install the Xpods Telemetry extension on a device you own or manage and paste the token into it. ',
            'The extension records visited page URLs only — never keystrokes, form fields or passwords — and shows a visible indicator to the user.'),
          msg,
          h('div', { class: 'filters' }, label, h('button', { class: 'btn primary', onclick: create }, 'Create token')),
          tokenBox),
        panel('Enrolled devices',
          rows.length ? h('div', { class: 'tablewrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Label', 'Events', 'Last seen', 'Created by', 'Status', ''].map((t) => h('th', {}, t)))),
            h('tbody', {}, rows.map((r) => h('tr', {},
              h('td', {}, r.label),
              h('td', {}, fmtN(r.event_count)),
              h('td', { class: 'nowrap' }, r.last_seen ? ago(r.last_seen) : 'never'),
              h('td', { class: 'crumb' }, r.created_by),
              h('td', {}, r.revoked ? h('span', { class: 'badge state-failed' }, 'revoked') : h('span', { class: 'badge state-running' }, 'active')),
              h('td', { style: 'text-align:right' }, r.revoked ? null : confirmButton('Revoke', async () => {
                await api('/enrollments/' + r.id, { method: 'DELETE' }); render();
              })))))))
            : h('div', { class: 'empty' }, 'No devices enrolled yet.'))),
      panel('Telemetry ingest API',
        h('div', { class: 'md' },
          h('div', { class: 'crumb' }, 'Any enrolled client (a browser extension you build, or an agent) sends visited URLs to this endpoint. Guardrails are enforced server-side: only http/https URLs are stored, credentials in URLs are stripped, and only url/title/ts/visit_type are read — the endpoint cannot capture keystrokes, form values or passwords.'),
          h('h4', {}, 'Endpoint'),
          h('pre', { class: 'raw', style: 'user-select:all' }, 'POST ' + origin + '/api/telemetry'),
          h('h4', {}, 'Headers'),
          h('pre', { class: 'raw', style: 'user-select:all' }, 'Authorization: Bearer <enrollment token>\nContent-Type: application/json'),
          h('h4', {}, 'Body'),
          h('pre', { class: 'raw', style: 'user-select:all' },
            '{\n  "device": "chrome-win-01",\n  "events": [\n    { "url": "https://example.com/page",\n      "title": "Example",\n      "ts": 1790000000000,\n      "visit_type": "navigation" }\n  ]\n}'),
          h('div', { class: 'crumb' }, 'ts accepts epoch ms or ISO-8601. Up to 500 events per POST; retries are idempotent. For remote devices, expose the console over HTTPS behind your reverse proxy or VPN and use that URL.')))));
}

// ------------------------------------------------------------------ audit

async function viewAudit(main) {
  main.append(topbar('Audit log'));
  const rows = await api('/audit?limit=500');
  main.append(h('div', { class: 'panel', style: 'padding:0' }, h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Time', 'User', 'Action', 'Target', 'Detail'].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {},
      h('td', { class: 'mono nowrap' }, fmtTs(r.ts)), h('td', {}, r.user), h('td', {}, h('span', { class: 'chip' }, r.action)),
      h('td', { class: 'mono' }, r.target), h('td', { class: 'trunc' }, r.detail))))))));
}

// ------------------------------------------------------------------ login

function renderLogin() {
  const err = h('div');
  const user = h('input', { type: 'text', placeholder: 'Username', autocomplete: 'username', required: true, value: 'admin' });
  const pass = h('input', { type: 'password', placeholder: 'Password', autocomplete: 'current-password', required: true });
  $app().replaceChildren(h('div', { class: 'login' }, h('div', { class: 'panel' },
    h('div', { class: 'brand' }, LOGO(), 'Xpods Console'),
    h('form', { onsubmit: async (e) => {
      e.preventDefault();
      try {
        state.user = (await api('/login', { method: 'POST', body: { username: user.value, password: pass.value } })).user;
        render();
      } catch (ex) { err.replaceChildren(h('div', { class: 'msg err' }, ex.message)); }
    } }, err, user, pass, h('button', { class: 'btn primary', type: 'submit' }, 'Sign in')))));
  pass.focus();
}

boot();
