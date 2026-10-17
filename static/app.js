/* AI Wargame frontend — vanilla JS, no build step. */
"use strict";

const ZONE_COLORS = {
  internet: "#6b7280", dmz: "#f59e0b", corp: "#3b82f6",
  servers: "#8b5cf6", restricted: "#ef4444",
};

const state = {
  nodes: new Map(),   // id -> node object (force-graph mutates x/y on it)
  links: [],          // {source, target, ...}
  view: "god",
  shortest: [],       // node ids on the current shortest viable path
  cj: null,
  lateralEdges: new Map(), // "src>dst" -> expiry timestamp
  maxRounds: 20,
};

let Graph = null;
let spark = null;
const matchLog = [];            // chronological event log for the timeline modal
let lastReport = null;          // markdown of the after-action report
let gameOverInfo = null;        // winner payload

// ---------------------------------------------------------------- websocket
let ws = null;
let backoff = 1000;
let paused = false;

function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => { backoff = 1000; };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    handle(msg.type, msg.payload || {});
  };
  ws.onclose = () => setTimeout(connect, backoff = Math.min(backoff * 1.6, 8000));
  ws.onerror = () => ws.close();
}

// ---------------------------------------------------------------- graph
function initGraph() {
  Graph = ForceGraph()(document.getElementById("graph"))
    .backgroundColor("rgba(0,0,0,0)")
    .nodeId("id")
    .nodeCanvasObject(paintNode)
    .nodeLabel(nodeTooltip)
    .nodePointerAreaPaint((node, color, ctx) => {
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(node.x, node.y, 10, 0, 2 * Math.PI); ctx.fill();
    })
    .linkCanvasObjectMode(() => "after")
    .linkCanvasObject(paintLinkOverlay)
    .linkColor((l) => l.blocked ? "rgba(90,90,110,0.25)" : "rgba(110,135,180,0.45)")
    .linkLineDash((l) => l.blocked ? [4, 4] : null)
    .linkWidth((l) => onShortestPath(l) ? 3 : 1.2)
    .linkDirectionalParticles((l) => {
      const key = `${idOf(l.source)}>${idOf(l.target)}`;
      return state.lateralEdges.has(key) && Date.now() < state.lateralEdges.get(key) ? 4 : 0;
    })
    .linkDirectionalParticleColor(() => "#ff2d55")
    .linkDirectionalParticleWidth(3)
    .linkDirectionalParticleSpeed(0.012)
    .autoPauseRedraw(false)
    .cooldownTime(5000)
    .warmupTicks(80)
    .onNodeHover((n) => { document.body.style.cursor = n ? "pointer" : "default"; });
  Graph.d3Force("charge").strength(-220);
  Graph.d3Force("link").distance(52);
  window.addEventListener("resize", resizeGraph);
  resizeGraph();
}

function resizeGraph() {
  const el = document.getElementById("graph");
  if (Graph) Graph.width(el.clientWidth).height(el.clientHeight);
}

function idOf(x) { return typeof x === "object" ? x.id : x; }

function onShortestPath(l) {
  const s = state.shortest;
  for (let i = 0; i < s.length - 1; i++) {
    if (idOf(l.source) === s[i] && idOf(l.target) === s[i + 1]) return true;
  }
  return false;
}

function paintNode(node, ctx, globalScale) {
  const god = state.view === "god";
  if (!god && !node.discovered) return;
  const t = Date.now() / 500;
  const dim = god && !node.discovered;
  const r = node.crown ? 12 : 7.5;

  ctx.save();
  if (dim) ctx.globalAlpha = 0.15;

  // compromised: pulsing red glow
  if (node.compromised && node.kind !== "internet") {
    const pulse = 8 + Math.sin(t * 2) * 4;
    ctx.shadowColor = "#ff2d55";
    ctx.shadowBlur = 18 + pulse;
    ctx.fillStyle = "#ff2d55";
    ctx.beginPath(); ctx.arc(node.x, node.y, r + 1.5, 0, 2 * Math.PI); ctx.fill();
    ctx.shadowBlur = 0;
  }

  // body
  let fill = ZONE_COLORS[node.zone] || "#888";
  if (node.isolated) fill = "#3a4150";
  if (node.kind === "internet") fill = "#4b5563";
  const isHp = node.honeypot && god;
  ctx.fillStyle = isHp ? "#d946ef" : fill;
  ctx.beginPath();
  if (isHp) { // diamond
    ctx.moveTo(node.x, node.y - r); ctx.lineTo(node.x + r, node.y);
    ctx.lineTo(node.x, node.y + r); ctx.lineTo(node.x - r, node.y);
    ctx.closePath();
  } else {
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
  }
  ctx.fill();

  // crown jewel: gold ring + glow
  if (node.crown) {
    ctx.shadowColor = "#ffd60a"; ctx.shadowBlur = 16;
    ctx.strokeStyle = "#ffd60a"; ctx.lineWidth = 2.5;
    ctx.beginPath(); ctx.arc(node.x, node.y, r + 4, 0, 2 * Math.PI); ctx.stroke();
    ctx.shadowBlur = 0;
  }
  // isolated: dashed grey ring
  if (node.isolated) {
    ctx.setLineDash([3, 3]);
    ctx.strokeStyle = "#6b7280"; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.arc(node.x, node.y, r + 4, 0, 2 * Math.PI); ctx.stroke();
    ctx.setLineDash([]);
  }
  // shortest-path ring
  if (state.shortest.includes(node.id)) {
    ctx.strokeStyle = "rgba(255,45,85,0.85)"; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(node.x, node.y, r + 7 + Math.sin(t * 2) * 1.5, 0, 2 * Math.PI); ctx.stroke();
  }

  // label
  const fs = Math.max(11 / globalScale, 2.6);
  ctx.font = `${fs}px 'Segoe UI', sans-serif`;
  ctx.textAlign = "center";
  ctx.fillStyle = dim ? "rgba(125,139,161,0.5)" : "#c6d2e3";
  ctx.fillText(node.id, node.x, node.y + r + fs + 2);
  ctx.restore();
}

// host tooltip: real-world intel per vuln (EPSS exploit probability, CISA KEV)
function nodeTooltip(node) {
  const n = state.nodes.get(node.id) || node;
  const flags = [
    n.compromised ? '<span class="tt-flag red">COMPROMISED</span>' : "",
    n.isolated ? '<span class="tt-flag blue">ISOLATED</span>' : "",
    n.honeypot ? '<span class="tt-flag gold">HONEYPOT</span>' : "",
    n.crown ? '<span class="tt-flag gold">👑 CROWN JEWEL</span>' : "",
  ].filter(Boolean).join(" ");
  const vulns = (n.vulns || []).map((v) => {
    const intelBits = [
      v.epss != null ? `EPSS ${(v.epss * 100).toFixed(0)}%` : "",
      v.kev ? '<span class="kev-badge">CISA KEV</span>' : "",
      v.zero_day ? '<span class="kev-badge zero">ZERO-DAY</span>' : "",
    ].filter(Boolean).join(" ");
    return `<div class="tt-vuln ${v.patched ? "patched" : ""}">
      <b>${escapeHtml(v.cve)}</b> ${escapeHtml(v.name || "")} · sev ${v.sev} ${intelBits}</div>`;
  }).join("");
  return `<div class="tt">
    <div class="tt-head">${escapeHtml(n.id)} ${flags}</div>
    <div class="tt-sub">${escapeHtml(n.kind || "")} · ${escapeHtml(n.zone || "")} · ${escapeHtml(n.os || "")} · crit ${n.criticality ?? "-"}</div>
    ${vulns || '<div class="tt-sub">no known vulns</div>'}
  </div>`;
}

function paintLinkOverlay(link, ctx) {
  if (!onShortestPath(link)) return;
  const a = link.source, b = link.target;
  ctx.save();
  ctx.strokeStyle = "rgba(255,45,85,0.55)";
  ctx.lineWidth = 5;
  ctx.shadowColor = "#ff2d55"; ctx.shadowBlur = 12;
  ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  ctx.restore();
}

function applyView() {
  const god = state.view === "god";
  const nodes = [...state.nodes.values()].filter((n) => god || n.discovered);
  const ids = new Set(nodes.map((n) => n.id));
  const links = state.links.filter((l) => ids.has(idOf(l.source)) && ids.has(idOf(l.target)));
  Graph.graphData({ nodes, links });
}

// ---------------------------------------------------------------- snapshot / patch
function loadSnapshot(p) {
  state.nodes.clear();
  state.links = [];
  for (const n of p.nodes) state.nodes.set(n.id, { ...n });
  for (const l of p.links) state.links.push({ ...l });
  state.cj = p.crown_jewel;
  state.maxRounds = p.max_rounds || 20;
  document.getElementById("seed").value = p.seed;
  document.getElementById("banner").classList.add("hidden");
  document.getElementById("report-modal").classList.add("hidden");
  document.getElementById("timeline-modal").classList.add("hidden");
  document.getElementById("endgame-dock").classList.add("hidden");
  matchLog.length = 0;
  lastReport = null;
  gameOverInfo = null;
  attackState.techniques.clear();
  renderAttackBar();
  clearFeeds();
  resetSpark();
  applyView();
  setTimeout(() => Graph.zoomToFit(900, 70), 1200);
}

function applyPatch(p) {
  for (const u of p.nodes || []) {
    const n = state.nodes.get(u.id);
    if (n) Object.assign(n, u);
  }
  for (const n of p.new_nodes || []) state.nodes.set(n.id, { ...n });
  for (const l of p.new_links || []) state.links.push({ ...l });
  for (const u of p.links || []) {
    const l = state.links.find((x) => idOf(x.source) === u.source && idOf(x.target) === u.target);
    if (l) l.blocked = u.blocked;
  }
  applyView();
}

// ---------------------------------------------------------------- feeds & alerts
function clearFeeds() {
  document.getElementById("red-feed").innerHTML = "";
  document.getElementById("blue-feed").innerHTML = "";
  document.getElementById("alerts").innerHTML = "";
}

const pendingCard = { red: null, blue: null };

function addThought(p) {
  const feed = document.getElementById(p.side === "red" ? "red-feed" : "blue-feed");
  const card = document.createElement("div");
  card.className = `card ${p.side}`;
  card.innerHTML = `<div class="thought">💭 ${escapeHtml(p.text)}
    ${p.fallback ? '<span class="fallback-badge">FALLBACK</span>' : ""}</div>
    <div class="action">…</div>`;
  feed.prepend(card);
  trim(feed);
  pendingCard[p.side] = card;
}

function addResult(p) {
  matchLog.push({ round: p.round, side: p.side, kind: "action",
    action: p.action, success: p.success, text: p.narration });
  trackTechniques(p.techniques, p.side);
  if (p.action === "PATCH" && p.success && p.args) {
    const n = state.nodes.get(p.args.host);
    const v = n && (n.vulns || []).find((x) => x.id === p.args.vuln);
    if (v) v.patched = true;
  }
  const card = pendingCard[p.side];
  const args = Object.entries(p.args || {}).map(([k, v]) => `${k}=${v}`).join(" ");
  const chips = (p.techniques || []).map((t) =>
    `<span class="tech-chip ${p.side}" title="${escapeHtml(t.name)}">${escapeHtml(t.id)}</span>`).join("");
  const html = `<div class="action">${p.action} <span style="color:#7d8ba1">${escapeHtml(args)}</span> ${chips}</div>
    <div class="result ${p.success ? "ok" : "fail"}">${p.success ? "✔" : "✘"} ${escapeHtml(p.narration)}</div>`;
  if (card) {
    card.querySelector(".action").outerHTML = html;
  } else {
    const feed = document.getElementById(p.side === "red" ? "red-feed" : "blue-feed");
    const c = document.createElement("div");
    c.className = `card ${p.side}`;
    c.innerHTML = html;
    feed.prepend(c);
    trim(feed);
  }
  // lateral move particle flash
  if (p.side === "red" && p.action === "LATERAL_MOVE" && p.success) {
    const target = p.args.host;
    for (const l of state.links) {
      if (idOf(l.target) === target) {
        state.lateralEdges.set(`${idOf(l.source)}>${target}`, Date.now() + 2500);
      }
    }
  }
}

function addSystemCard(narration) {
  matchLog.push({ round: state.currentRound || null, side: "sys", kind: "intervention", text: narration });
  for (const fid of ["red-feed", "blue-feed"]) {
    const feed = document.getElementById(fid);
    const c = document.createElement("div");
    c.className = "card system";
    c.innerHTML = `<div class="action">${escapeHtml(narration)}</div>`;
    feed.prepend(c);
    trim(feed);
  }
}

function addAlert(p) {
  matchLog.push({ round: state.currentRound || null, side: "blue", kind: "alert",
    text: `Alert on ${p.host} (${p.kind}, confidence ${Math.round(p.confidence * 100)}%)` });
  const box = document.getElementById("alerts");
  const el = document.createElement("div");
  el.className = "alert" + (p.kind === "honeypot" ? " honeypot" : "");
  el.innerHTML = `<b>${escapeHtml(p.host)}</b> — ${escapeHtml(p.kind)}
    <div class="bar"><div style="width:${Math.round(p.confidence * 100)}%"></div></div>`;
  box.prepend(el);
  while (box.children.length > 8) box.lastChild.remove();
}

function trim(feed) { while (feed.children.length > 60) feed.lastChild.remove(); }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------------------------------------------------------------- metrics & sparkline
function initSpark() {
  spark = new Chart(document.getElementById("sparkline"), {
    type: "line",
    data: { labels: [], datasets: [{ data: [], borderColor: "#ff2d55", borderWidth: 2,
      pointRadius: 0, tension: 0.35, fill: true,
      backgroundColor: "rgba(255,45,85,0.12)" }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false, beginAtZero: true } } },
  });
}

function resetSpark() {
  if (spark) { spark.data.labels = []; spark.data.datasets[0].data = []; spark.update(); }
}

function updateMetrics(p) {
  state.currentRound = p.round;
  document.getElementById("st-paths").textContent = p.capped ? p.paths + "+" : p.paths;
  document.getElementById("st-round").textContent = `${p.round}/${p.max_rounds}`;
  document.getElementById("st-comp").textContent = p.compromised;
  document.getElementById("st-impact").textContent = p.impact;
  document.getElementById("st-alerts").textContent = p.alerts;
  state.shortest = p.shortest_path_ids || [];
  if (spark) {
    spark.data.labels.push(p.round);
    spark.data.datasets[0].data.push(p.paths);
    if (spark.data.labels.length > 80) {
      spark.data.labels.shift(); spark.data.datasets[0].data.shift();
    }
    spark.update();
  }
}

// ---------------------------------------------------------------- game over / report
function showGameOver(p) {
  gameOverInfo = p;
  matchLog.push({ round: p.rounds, side: "sys", kind: "end",
    text: `GAME OVER — ${p.winner.toUpperCase()} wins: ${p.reason}` });
  const banner = document.getElementById("banner");
  const txt = document.getElementById("banner-text");
  banner.classList.remove("hidden");
  txt.className = p.winner;
  txt.innerHTML = `${p.winner === "red" ? "🔴 RED WINS" : "🔵 BLUE WINS"}
    <small>${escapeHtml(p.reason)} — ${p.rounds} rounds</small>`;
  document.getElementById("endgame-dock").classList.remove("hidden");
}

function openReport() {
  const modal = document.getElementById("report-modal");
  const body = document.getElementById("report-body");
  if (lastReport) {
    body.innerHTML = window.marked ? marked.parse(lastReport) : escapeHtml(lastReport);
  } else {
    body.innerHTML = "<p style='color:#7d8ba1'>⏳ Report is still being generated by the LLM… try again in a few seconds.</p>";
  }
  modal.classList.remove("hidden");
}

function showReport(p) {
  lastReport = p.markdown || "";
  setTimeout(openReport, 2200);
}

function openTimeline() {
  document.getElementById("timeline-modal").classList.remove("hidden");
  const summary = document.getElementById("timeline-summary");
  const body = document.getElementById("timeline-body");
  const redActs = matchLog.filter((e) => e.side === "red" && e.kind === "action");
  const bluActs = matchLog.filter((e) => e.side === "blue" && e.kind === "action");
  const alerts = matchLog.filter((e) => e.kind === "alert");
  const sys = matchLog.filter((e) => e.side === "sys");
  const go = gameOverInfo;
  summary.innerHTML = go
    ? `<b style="color:${go.winner === "red" ? "#ff2d55" : "#3b9dff"}">${go.winner.toUpperCase()} WINS</b> — ${escapeHtml(go.reason)} ·
       ${go.rounds} rounds · ${redActs.length} RED actions · ${bluActs.length} BLUE actions ·
       ${alerts.length} alerts · ${sys.length - 1} judge intervention(s)`
    : `${matchLog.length} events so far`;
  body.innerHTML = matchLog.map((e) => {
    const icon = { action: e.success ? "✔" : "✘", alert: "⚠", intervention: "⚖", end: "🏁" }[e.kind] || "•";
    const cls = e.kind === "action" ? (e.success ? "ok" : "fail") : "";
    const label = e.kind === "action" ? `<b>${e.action}</b> ` : "";
    return `<div class="tl-row">
      <span class="tl-round">${e.round ? "R" + e.round : ""}</span>
      <span class="tl-side ${e.side}">${e.side.toUpperCase()}</span>
      <span class="tl-text ${cls}">${icon} ${label}${escapeHtml(e.text)}</span>
    </div>`;
  }).join("");
}

// ---------------------------------------------------------------- ATT&CK heatmap
const attackState = { techniques: new Map() };  // id -> {id, name, tactic, count, side}
const TACTIC_ORDER = ["Discovery", "Initial Access", "Credential Access", "Defense Evasion",
  "Lateral Movement", "Exfiltration", "Mitigation", "Deception"];

function trackTechniques(list, side) {
  for (const t of list || []) {
    const cur = attackState.techniques.get(t.id) || { ...t, count: 0, side };
    cur.count += 1;
    attackState.techniques.set(t.id, cur);
  }
  renderAttackBar();
}

function renderAttackBar() {
  const box = document.getElementById("attack-cols");
  if (attackState.techniques.size === 0) {
    box.innerHTML = '<span class="ab-empty">techniques used this match appear here</span>';
    return;
  }
  const groups = new Map();
  for (const t of attackState.techniques.values()) {
    if (!groups.has(t.tactic)) groups.set(t.tactic, []);
    groups.get(t.tactic).push(t);
  }
  const ordered = [...groups.entries()].sort(
    (a, b) => TACTIC_ORDER.indexOf(a[0]) - TACTIC_ORDER.indexOf(b[0]));
  box.innerHTML = ordered.map(([tactic, techs]) => `
    <div class="ab-group">
      <div class="ab-tactic">${escapeHtml(tactic)}</div>
      ${techs.map((t) => `<span class="tech-chip ${t.side}" title="${escapeHtml(t.name)}">
        ${escapeHtml(t.id)}${t.count > 1 ? ` ×${t.count}` : ""}</span>`).join("")}
    </div>`).join("");
}

// ---------------------------------------------------------------- exports
async function downloadExport(url, filename) {
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(await r.text());
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) {
    addSystemCard(`⚠ export unavailable (replay/offline mode): ${url}`);
  }
}

// ---------------------------------------------------------------- event router
function handle(type, p) {
  switch (type) {
    case "graph_snapshot": loadSnapshot(p); break;
    case "graph_patch": applyPatch(p); break;
    case "agent_thought": addThought(p); break;
    case "action_result": addResult(p); break;
    case "alert": addAlert(p); break;
    case "metrics": updateMetrics(p); break;
    case "intervention": addSystemCard(p.narration); break;
    case "game_over": showGameOver(p); break;
    case "report": showReport(p); break;
    case "status": applyStatus(p); break;
  }
}

function applyStatus(p) {
  document.getElementById("red-model").textContent = p.models.red;
  document.getElementById("blue-model").textContent = p.models.blue;
  fillModelSelects(p.available_models || [], p.models);
}

function fillModelSelects(models, current) {
  for (const [id, cur] of [["model-red", current.red], ["model-blue", current.blue]]) {
    const sel = document.getElementById(id);
    sel.innerHTML = "";
    const all = models.length ? models : [cur];
    for (const m of all) {
      const opt = document.createElement("option");
      opt.value = m; opt.textContent = m;
      if (m === cur) opt.selected = true;
      sel.appendChild(opt);
    }
    if (!models.length) sel.disabled = true;
  }
}

// ---------------------------------------------------------------- controls
async function post(url, body) {
  try {
    await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}) });
  } catch (e) { console.warn(url, e); }
}

function initControls() {
  document.getElementById("btn-start").onclick = () => post("/api/start");
  const pauseBtn = document.getElementById("btn-pause");
  pauseBtn.onclick = () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "▶ RESUME" : "⏸ PAUSE";
    post(paused ? "/api/pause" : "/api/resume");
  };
  document.getElementById("btn-step").onclick = () => post("/api/step");
  document.getElementById("btn-reset").onclick = () =>
    post("/api/reset", { seed: parseInt(document.getElementById("seed").value || "42") });
  document.getElementById("btn-zeroday").onclick = () => post("/api/intervene/zero_day");
  document.getElementById("btn-insider").onclick = () => post("/api/intervene/insider");
  const speed = document.getElementById("speed");
  speed.oninput = () => {
    document.getElementById("speed-x").textContent = speed.value + "×";
    post("/api/speed", { x: parseFloat(speed.value) });
  };
  document.getElementById("model-red").onchange = (e) =>
    post("/api/model", { side: "red", model: e.target.value });
  document.getElementById("model-blue").onchange = (e) =>
    post("/api/model", { side: "blue", model: e.target.value });
  document.getElementById("view-god").onclick = () => setView("god");
  document.getElementById("view-red").onclick = () => setView("red");
  document.getElementById("report-close").onclick = () =>
    document.getElementById("report-modal").classList.add("hidden");
  document.getElementById("timeline-close").onclick = () =>
    document.getElementById("timeline-modal").classList.add("hidden");
  document.getElementById("banner-close").onclick = () =>
    document.getElementById("banner").classList.add("hidden");
  document.getElementById("banner-report").onclick = openReport;
  document.getElementById("banner-timeline").onclick = openTimeline;
  document.getElementById("dock-report").onclick = openReport;
  document.getElementById("dock-timeline").onclick = openTimeline;
  const navDl = () => downloadExport("/api/export/navigator", "attack_navigator_layer.json");
  const stixDl = () => downloadExport("/api/export/stix", "match_stix_bundle.json");
  document.getElementById("banner-nav").onclick = navDl;
  document.getElementById("banner-stix").onclick = stixDl;
  document.getElementById("dock-nav").onclick = navDl;
  document.getElementById("dock-stix").onclick = stixDl;
}

function setView(v) {
  state.view = v;
  document.getElementById("view-god").classList.toggle("active", v === "god");
  document.getElementById("view-red").classList.toggle("active", v === "red");
  applyView();
}

// ---------------------------------------------------------------- boot
initGraph();
initSpark();
initControls();
connect();
