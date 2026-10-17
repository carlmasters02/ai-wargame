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
  seed: null,         // seed of the loaded match
};

let Graph = null;
let spark = null;
const matchLog = [];            // chronological event log for the timeline modal
let lastReport = null;          // report payload {markdown, source, model, note}
let reportPending = null;       // {model} while the report is being written
let gameOverInfo = null;        // winner payload
let lastScorecard = null;       // SOC scorecard for the finished match

// ---------------------------------------------------------------- websocket
let ws = null;
let backoff = 1000;
let paused = false;
let everConnected = false;
let reconnecting = false;       // true until the first snapshot after a WS reconnect

function connect() {
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => { backoff = 1000; reconnecting = everConnected; everConnected = true; };
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
    .nodePointerAreaPaint((node, color, ctx, globalScale) => {
      // hit area = the dot AND its name label underneath, so pointing at the text works too
      const r = node.crown ? 12 : 7.5;
      const fs = Math.max(11 / globalScale, 2.6);
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(node.x, node.y, r + 3, 0, 2 * Math.PI); ctx.fill();
      ctx.font = `${fs}px 'Segoe UI', sans-serif`;
      const w = ctx.measureText(node.id).width;
      ctx.fillRect(node.x - w / 2 - 1, node.y + r, w + 2, fs + 4);
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
    .onNodeHover((n) => { document.body.style.cursor = n ? "pointer" : "default"; })
    .onEngineStop(() => { if (!state.userNavigated && anyNodeOutOfView()) fitGraph(); });
  // once the user pans/zooms, stop auto-fitting until they press FIT or a new match loads
  const graphEl = document.getElementById("graph");
  for (const ev of ["wheel", "pointerdown"]) {
    graphEl.addEventListener(ev, () => { state.userNavigated = true; }, { passive: true });
  }
  Graph.d3Force("charge").strength(-220);
  Graph.d3Force("link").distance(52);
  // the graph box changes size when the window does AND when the ATT&CK bar grows
  new ResizeObserver(resizeGraph).observe(document.getElementById("graph-wrap"));
  resizeGraph();
}

function fitGraph(ms = 700) {
  if (Graph && Graph.graphData().nodes.length) Graph.zoomToFit(ms, 60);
}

function anyNodeOutOfView() {
  const el = document.getElementById("graph");
  const w = el.clientWidth, h = el.clientHeight, pad = 12;
  return Graph.graphData().nodes.some((n) => {
    if (n.x == null) return false;
    const p = Graph.graph2ScreenCoords(n.x, n.y);
    return p.x < pad || p.y < pad || p.x > w - pad || p.y > h - pad;
  });
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
    n.beacon ? '<span class="tt-flag red">📡 C2 BEACON</span>' : "",
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
  // a WS blip re-sends the snapshot of the SAME match: refresh the graph, keep feeds/history
  const seen = matchLog.filter((e) => e.kind === "action" && e.action !== "PASS").length;
  const keep = reconnecting && p.seed === state.seed && (p.actions || 0) >= seen;
  reconnecting = false;
  state.nodes.clear();
  state.links = [];
  for (const n of p.nodes) state.nodes.set(n.id, { ...n });
  for (const l of p.links) state.links.push({ ...l });
  state.cj = p.crown_jewel;
  state.seed = p.seed;
  state.maxRounds = p.max_rounds || 20;
  document.getElementById("seed").value = p.seed;
  if (keep) { applyView(); return; }
  document.getElementById("banner").classList.add("hidden");
  document.getElementById("report-modal").classList.add("hidden");
  document.getElementById("timeline-modal").classList.add("hidden");
  document.getElementById("endgame-dock").classList.add("hidden");
  matchLog.length = 0;
  lastReport = null;
  reportPending = null;
  gameOverInfo = null;
  lastScorecard = null;
  attackState.techniques.clear();
  renderAttackBar();
  clearFeeds();
  resetSpark();
  applyView();
  state.userNavigated = false;
  setTimeout(() => fitGraph(900), 1200);
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
  const tb = document.getElementById("telemetry"); if (tb) tb.innerHTML = "";
  caseCount = 0; const cb = document.getElementById("cases-badge"); if (cb) cb.textContent = "0";
}

const pendingCard = { red: null, blue: null };

function addThought(p) {
  const feed = document.getElementById(p.side === "red" ? "red-feed" : "blue-feed");
  const card = document.createElement("div");
  card.className = `card ${p.side}`;
  card.innerHTML = `<div class="thought">💭 ${escapeHtml(p.text)}
    ${p.fallback ? '<span class="fallback-badge">FALLBACK</span>' : ""}
    ${p.model ? `<span class="model-tag">${escapeHtml(p.model)}</span>` : ""}</div>
    <div class="action pending">…</div>`;
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
  if (card) {  // BLUE has 2 actions per turn: append each in order
    const pending = card.querySelector(".pending");
    if (pending) pending.remove();
    card.insertAdjacentHTML("beforeend", html);
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

function addSystemCard(narration, kind = "intervention") {
  matchLog.push({ round: state.currentRound || null, side: "sys", kind, text: narration });
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
  const sensor = p.source ? `<span class="sensor">${escapeHtml(p.source)}</span>` : "";
  const sig = p.signature ? `<div class="sig">${escapeHtml(p.signature)}${p.data_source ? ` · ${escapeHtml(p.data_source)}` : ""}</div>` : "";
  el.innerHTML = `<b>${escapeHtml(p.host)}</b> ${sensor}
    <div class="bar"><div style="width:${Math.round(p.confidence * 100)}%"></div></div>${sig}`;
  box.prepend(el);
  while (box.children.length > 8) box.lastChild.remove();
}

function addTelemetry(p) {
  const box = document.getElementById("telemetry");
  if (!box) return;
  const el = document.createElement("div");
  el.className = "tele" + (p.alerted ? " hot" : "");
  el.innerHTML = `<span class="sensor">${escapeHtml(p.source)}</span>
    <span class="tele-host">${escapeHtml(p.host)}</span>
    <span class="tele-sig">${escapeHtml(p.signature)}</span>`;
  box.prepend(el);
  while (box.children.length > 12) box.lastChild.remove();
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
const campaign = { total: 0, played: 0, baseSeed: 42, score: { red: 0, blue: 0 }, timer: null };

function campaignLabel() {
  const el = document.getElementById("campaign-score");
  if (!campaign.total) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  el.innerHTML = `GAME ${Math.min(campaign.played + 1, campaign.total)}/${campaign.total}
    · 🔴 ${campaign.score.red} — ${campaign.score.blue} 🔵`;
}

function resetCampaign() {
  if (campaign.timer) { clearTimeout(campaign.timer); campaign.timer = null; }
  campaign.played = 0;
  campaign.score = { red: 0, blue: 0 };
  campaign.baseSeed = parseInt(document.getElementById("seed").value || "42");
  campaignLabel();
}

function campaignAdvance(winner) {
  if (!campaign.total || campaign.played >= campaign.total) return;  // series already decided
  if (campaign.played === 0 && state.seed != null) campaign.baseSeed = state.seed;
  if (winner === "red" || winner === "blue") campaign.score[winner] += 1;
  campaign.played += 1;
  campaignLabel();
  if (campaign.played < campaign.total) {
    addSystemCard(`🏆 campaign: game ${campaign.played + 1}/${campaign.total} starts shortly ` +
      `(seed ${campaign.baseSeed + campaign.played})`, "system");
    campaign.timer = setTimeout(() => {
      const seed = campaign.baseSeed + campaign.played;
      document.getElementById("seed").value = seed;
      post("/api/reset", { seed }).then(() => post("/api/start"));
    }, 6000);
  } else {
    const s = campaign.score;
    const champ = s.red === s.blue ? "DRAW" : (s.red > s.blue ? "🔴 RED" : "🔵 BLUE");
    addSystemCard(`🏆 campaign over: ${champ} takes the series ${s.red}–${s.blue}`, "system");
  }
}

function showGameOver(p) {
  if (gameOverInfo) return;  // already handled for this match (WS reconnect re-sends it)
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
  lastScorecard = p.scorecard || null;
  campaignAdvance(p.winner);
}

function fmt(v, dash = "–") { return v == null ? dash : v; }
function usd(n) { return n == null ? "–" : "$" + Math.round(n).toLocaleString(); }

function openScorecard() {
  const modal = document.getElementById("scorecard-modal");
  const body = document.getElementById("scorecard-body");
  const sc = lastScorecard;
  if (!sc) { body.innerHTML = "<p style='color:#7d8ba1'>No scorecard for this match.</p>"; }
  else {
    const r = sc.red, b = sc.blue, rc = sc.red_cost, bc = sc.blue_cost, bcost = sc.business_cost || {};
    const cost = (c) => c.avg_latency_ms == null
      ? "<span style='color:#7d8ba1'>heuristic</span>"
      : `${Math.round(c.avg_latency_ms)} ms · ${c.avg_tokens ? Math.round(c.avg_tokens) + " tok" : "–"} · ${Math.round(c.fallback_rate*100)}% fallback`;
    body.innerHTML = `
      <div class="sc-grid">
        <div class="sc-col red">
          <div class="sc-head">🔴 RED — attacker &nbsp;<span class="sc-grade g-${r.grade}">${r.grade} · ${r.score}</span></div>
          <table>
            <tr><td>Objective (crown jewel)</td><td>${r.objective ? `✔ round ${r.rounds_to_objective}` : "✘ not reached"}</td></tr>
            <tr><td>Hosts compromised</td><td>${r.hosts_compromised}</td></tr>
            <tr><td>Stealth (actions/alert)</td><td>${fmt(r.stealth)}</td></tr>
            <tr><td>Alerts raised</td><td>${r.alerts_raised}</td></tr>
            <tr><td>Model cost</td><td>${cost(rc)}</td></tr>
          </table>
        </div>
        <div class="sc-col blue">
          <div class="sc-head">🔵 BLUE — defender &nbsp;<span class="sc-grade g-${b.grade}">${b.grade} · ${b.score}</span></div>
          <table>
            <tr><td>Detected / missed</td><td>${b.detected} / ${b.missed}</td></tr>
            <tr><td>MTTD (rounds)</td><td>${fmt(b.mttd_rounds)}</td></tr>
            <tr><td>MTTR (rounds)</td><td>${fmt(b.mttr_rounds)}</td></tr>
            <tr><td>False isolations</td><td>${b.false_isolations}</td></tr>
            <tr><td>Exposure reduced</td><td>${Math.round(b.exposure_reduction*100)}%</td></tr>
            <tr><td>Business impact</td><td>${b.business_impact}</td></tr>
            <tr><td>Model cost</td><td>${cost(bc)}</td></tr>
          </table>
        </div>
      </div>
      <div class="sc-cost">
        <div class="sc-cost-head">💰 BUSINESS IMPACT</div>
        <div class="sc-cost-row"><span>Downtime (isolation / reimage)</span><b>${usd(bcost.downtime_usd)}</b></div>
        <div class="sc-cost-row"><span>Incident response (${bcost.hosts_requiring_response} host${bcost.hosts_requiring_response===1?"":"s"})</span><b>${usd(bcost.response_usd)}</b></div>
        <div class="sc-cost-row"><span>Breach loss (objective reached)</span><b>${usd(bcost.breach_usd)}</b></div>
        <div class="sc-cost-row total"><span>Total cost to the business</span><b>${usd(bcost.total_usd)}</b></div>
      </div>
      <p class="sc-note">MTTD = mean rounds to detect a compromise; MTTR = rounds from detection to eviction.
      Scores are 0–100 SOC composites (coverage, speed, precision, exposure control). Costs are illustrative,
      anchored to public breach benchmarks.</p>`;
  }
  modal.classList.remove("hidden");
}

function renderMarkdown(md) {
  // model output is untrusted: parse, then sanitise before it touches the DOM
  if (!window.marked || !window.DOMPurify) return `<pre>${escapeHtml(md)}</pre>`;
  return DOMPurify.sanitize(marked.parse(md));
}

function openReport() {
  const modal = document.getElementById("report-modal");
  const body = document.getElementById("report-body");
  const src = document.getElementById("report-source");
  if (lastReport) {
    body.innerHTML = renderMarkdown(lastReport.markdown || "");
    const llm = lastReport.source === "llm";
    src.className = "report-source" + (lastReport.source === "template" ? " template" : "");
    src.textContent = llm ? `Written by ${lastReport.model}`
      : lastReport.source === "template"
        ? `Template report${lastReport.note ? ` — ${lastReport.note}` : ""}`
        : "";  // older recordings don't say who wrote the report
  } else {
    src.textContent = "";
    const who = reportPending && reportPending.model ? ` by ${reportPending.model}` : "";
    body.innerHTML = `<p style='color:#7d8ba1'>⏳ Report is being written${escapeHtml(who)}… ` +
      "this can take a minute or two for reasoning models.</p>";
  }
  modal.classList.remove("hidden");
}

function showReport(p) {
  const first = lastReport === null;
  lastReport = typeof p.markdown === "string" ? p : { markdown: "" };
  reportPending = null;
  if (first) setTimeout(openReport, 2200);
}

function openTimeline() {
  document.getElementById("timeline-modal").classList.remove("hidden");
  const summary = document.getElementById("timeline-summary");
  const body = document.getElementById("timeline-body");
  const redActs = matchLog.filter((e) => e.side === "red" && e.kind === "action");
  const bluActs = matchLog.filter((e) => e.side === "blue" && e.kind === "action");
  const alerts = matchLog.filter((e) => e.kind === "alert");
  const judge = matchLog.filter((e) => e.kind === "intervention");
  const go = gameOverInfo;
  summary.innerHTML = go
    ? `<b style="color:${go.winner === "red" ? "#ff2d55" : "#3b9dff"}">${go.winner.toUpperCase()} WINS</b> — ${escapeHtml(go.reason)} ·
       ${go.rounds} rounds · ${redActs.length} RED actions · ${bluActs.length} BLUE actions ·
       ${alerts.length} alerts · ${judge.length} judge intervention(s)`
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
  "Command and Control", "Lateral Movement", "Exfiltration", "Mitigation", "Deception"];

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
    if (!r.ok) {
      let msg = `HTTP ${r.status} (replay/offline mode?)`;
      try { msg = (await r.json()).error || msg; } catch (_) { /* non-JSON */ }
      throw new Error(msg);
    }
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);  // Firefox needs the anchor in the DOM
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } catch (e) {
    addSystemCard(`⚠ export unavailable: ${e.message}`, "system");
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
    case "case": bumpCases(); break;
    case "telemetry": addTelemetry(p); break;
    case "metrics": updateMetrics(p); break;
    case "intervention": onIntervention(p); break;
    case "game_over": showGameOver(p); break;
    case "report": showReport(p); break;
    case "report_pending": reportPending = p; break;
    case "status": applyStatus(p); break;
    case "control": applyControl(p); break;
    case "your_turn": showTurnPanel(p); break;
    case "your_turn_end": hideTurnPanel(); break;
    case "turn_start": pendingCard[p.side] = null; break;
    case "error": addSystemCard(`⚠ ${p.message || "server error"}`, "system"); break;
  }
}

function onIntervention(p) {
  addSystemCard(p.narration);
  if (p.kind === "model_swap" && p.side) {
    document.getElementById(`${p.side}-model`).textContent = p.model;
    const sel = document.getElementById(`model-${p.side}`);
    if ([...sel.options].some((o) => o.value === p.model)) sel.value = p.model;
  }
  if (p.kind === "persona" && p.persona) document.getElementById("persona-red").value = p.persona;
}

function applyControl(p) {
  if (p.state) {
    paused = p.state === "paused";
    document.getElementById("btn-pause").textContent = paused ? "▶ RESUME" : "⏸ PAUSE";
  }
  if (p.speed != null) {
    document.getElementById("speed").value = p.speed;
    document.getElementById("speed-x").textContent = p.speed + "×";
  }
  if (p.persona) document.getElementById("persona-red").value = p.persona;
  if (p.players) {
    document.getElementById("play-red").value = p.players.red;
    document.getElementById("play-blue").value = p.players.blue;
  }
}

const turnState = { side: null, n: 1, picked: [] };

function showTurnPanel(p) {
  turnState.side = p.side; turnState.n = p.n_actions; turnState.picked = [];
  const panel = document.getElementById("turn-panel");
  panel.className = p.side;
  document.getElementById("turn-head").innerHTML =
    `🧑 YOUR MOVE — ${p.side.toUpperCase()} · round ${p.round} · ` +
    `pick ${p.n_actions} action${p.n_actions > 1 ? "s" : ""}`;
  const box = document.getElementById("turn-actions");
  box.innerHTML = p.legal.map((a) =>
    `<button class="turn-opt" data-i="${a.index}">
       <span class="to-act">${escapeHtml(a.action)}</span>
       <span class="to-desc">${escapeHtml(a.description)}</span>
     </button>`).join("");
  box.querySelectorAll(".turn-opt").forEach((btn) =>
    btn.onclick = () => pickAction(parseInt(btn.dataset.i), btn));
  document.getElementById("turn-submit").classList.toggle("hidden", p.n_actions < 2);
  updateTurnHint();
  panel.classList.remove("hidden");
}

function pickAction(i, btn) {
  if (turnState.n === 1) { submitTurn([i]); return; }       // RED: one click submits
  const at = turnState.picked.indexOf(i);
  if (at >= 0) { turnState.picked.splice(at, 1); btn.classList.remove("sel"); }
  else if (turnState.picked.length < turnState.n) { turnState.picked.push(i); btn.classList.add("sel"); }
  updateTurnHint();
  if (turnState.picked.length === turnState.n) submitTurn(turnState.picked.slice());
}

function updateTurnHint() {
  const hint = document.getElementById("turn-hint");
  if (hint) hint.textContent = turnState.n > 1
    ? `${turnState.picked.length}/${turnState.n} selected`
    : "click an action to play it";
}

async function submitTurn(indices) {
  await post("/api/act", { indices });
  hideTurnPanel();
}

function hideTurnPanel() {
  turnState.side = null; turnState.picked = [];
  document.getElementById("turn-panel").classList.add("hidden");
}

function applyStatus(p) {
  document.getElementById("red-model").textContent = p.models.red;
  document.getElementById("blue-model").textContent = p.models.blue;
  fillModelSelects(p.available_models || [], p.models);
  fillScenarios(p.scenarios || [], p.scenario);
  applyControl(p);
  const persona = document.getElementById("persona-red");
  persona.disabled = !p.llm;
  persona.title = p.llm ? "RED persona (LLM games)" : "Personas need an LLM (AIAND_API_KEY) — heuristic mode";
}

function fillScenarios(list, current) {
  const sel = document.getElementById("scenario");
  if (!sel || (sel.dataset.filled && !list.length)) return;
  if (list.length) {
    sel.innerHTML = list.map((s) =>
      `<option value="${s.id}" title="${escapeHtml(s.desc)}">${escapeHtml(s.label)}</option>`).join("");
    sel.dataset.filled = "1";
  }
  if (current) sel.value = current;
}

function fillModelSelects(models, current) {
  for (const [id, cur] of [["model-red", current.red], ["model-blue", current.blue]]) {
    const sel = document.getElementById(id);
    sel.innerHTML = "";
    const all = models.length ? [...models] : [cur];
    if (cur && !all.includes(cur)) all.unshift(cur);  // never show a model that isn't running
    for (const m of all) {
      const opt = document.createElement("option");
      opt.value = m; opt.textContent = m;
      if (m === cur) opt.selected = true;
      sel.appendChild(opt);
    }
    sel.disabled = !models.length;
  }
}

// ---------------------------------------------------------------- controls
// optional control token (server WARGAME_TOKEN): pass ?token=... once, kept for the tab
const controlToken = (() => {
  const fromUrl = new URLSearchParams(location.search).get("token");
  try {
    if (fromUrl) sessionStorage.setItem("wargame_token", fromUrl);
    return fromUrl || sessionStorage.getItem("wargame_token") || "";
  } catch (_) { return fromUrl || ""; }
})();
let lockedWarned = false;

async function post(url, body) {
  const headers = { "Content-Type": "application/json" };
  if (controlToken) headers["X-Wargame-Token"] = controlToken;
  try {
    const r = await fetch(url, { method: "POST", headers, body: JSON.stringify(body || {}) });
    if (r.status === 401 && !lockedWarned) {
      lockedWarned = true;
      addSystemCard("🔒 Controls are locked on this server — open the page with ?token=<WARGAME_TOKEN>", "system");
    }
    return r;
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
  document.getElementById("btn-reset").onclick = () => {
    resetCampaign();  // manual reset aborts the running series
    post("/api/reset", { seed: parseInt(document.getElementById("seed").value || "42"),
                         scenario: document.getElementById("scenario").value || "baseline" });
  };
  document.getElementById("scenario").onchange = (e) => {
    resetCampaign();
    post("/api/reset", { seed: parseInt(document.getElementById("seed").value || "42"),
                         scenario: e.target.value }).then(async (r) => {
      if (r) { const d = await r.json().catch(() => ({}));
        if (d && d.scenario_note) addSystemCard(`🎬 scenario: ${d.scenario_note}`, "system"); }
    });
  };
  document.getElementById("btn-zeroday").onclick = () => post("/api/intervene/zero_day");
  document.getElementById("btn-insider").onclick = () => post("/api/intervene/insider");
  const speed = document.getElementById("speed");
  speed.oninput = () => {
    document.getElementById("speed-x").textContent = speed.value + "×";
    post("/api/speed", { x: parseFloat(speed.value) });
  };
  document.getElementById("model-red").onchange = (e) =>
    post("/api/model", { side: "red", model: e.target.value });
  document.getElementById("persona-red").onchange = (e) =>
    post("/api/persona", { persona: e.target.value });
  document.getElementById("model-blue").onchange = (e) =>
    post("/api/model", { side: "blue", model: e.target.value });
  document.getElementById("play-red").onchange = (e) =>
    post("/api/control", { side: "red", who: e.target.value });
  document.getElementById("play-blue").onchange = (e) =>
    post("/api/control", { side: "blue", who: e.target.value });
  document.getElementById("turn-submit").onclick = () => {
    if (turnState.picked.length) submitTurn(turnState.picked.slice());
  };
  document.getElementById("view-god").onclick = () => setView("god");
  document.getElementById("view-fit").onclick = () => { state.userNavigated = false; fitGraph(); };
  document.getElementById("view-red").onclick = () => setView("red");
  document.getElementById("report-close").onclick = () =>
    document.getElementById("report-modal").classList.add("hidden");
  document.getElementById("timeline-close").onclick = () =>
    document.getElementById("timeline-modal").classList.add("hidden");
  document.getElementById("banner-close").onclick = () =>
    document.getElementById("banner").classList.add("hidden");
  document.getElementById("banner-report").onclick = openReport;
  document.getElementById("banner-scorecard").onclick = openScorecard;
  document.getElementById("dock-scorecard").onclick = openScorecard;
  document.getElementById("scorecard-close").onclick = () =>
    document.getElementById("scorecard-modal").classList.add("hidden");
  document.getElementById("banner-timeline").onclick = openTimeline;
  document.getElementById("dock-report").onclick = openReport;
  document.getElementById("dock-timeline").onclick = openTimeline;
  const navDl = () => downloadExport("/api/export/navigator", "attack_navigator_layer.json");
  const stixDl = () => downloadExport("/api/export/stix", "match_stix_bundle.json");
  document.getElementById("banner-nav").onclick = navDl;
  document.getElementById("banner-stix").onclick = stixDl;
  document.getElementById("dock-nav").onclick = navDl;
  document.getElementById("dock-stix").onclick = stixDl;
  document.getElementById("campaign").onchange = (e) => {
    campaign.total = parseInt(e.target.value);
    resetCampaign();
  };
  document.getElementById("btn-board").onclick = openBoard;
  document.getElementById("btn-exposure").onclick = openExposure;
  document.getElementById("btn-cases").onclick = openCases;
  document.getElementById("cases-close").onclick = () =>
    document.getElementById("cases-modal").classList.add("hidden");
  document.getElementById("btn-import").onclick = () => document.getElementById("import-file").click();
  document.getElementById("import-file").onchange = importNetwork;
  document.getElementById("exposure-close").onclick = () =>
    document.getElementById("exposure-modal").classList.add("hidden");
  document.getElementById("board-close").onclick = () =>
    document.getElementById("board-modal").classList.add("hidden");
}

async function importNetwork(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = "";  // allow re-importing the same file
  if (!file) return;
  const content = await file.text();
  const fmt = file.name.toLowerCase().endsWith(".xml") ? "nmap" : "csv";
  const r = await post("/api/import", { format: fmt, content });
  if (!r) return;
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { addSystemCard(`⚠ import failed: ${d.error || r.status}`, "system"); return; }
  resetCampaign();
  addSystemCard(`⬆ imported ${file.name}: ${d.hosts} hosts, ${d.edges} connections, ` +
    `crown jewel ${d.crown_jewel}, exposure ${d.exposure} paths. Press ▶ START or 🎯 for the fix plan.`, "system");
}

let caseCount = 0;
function bumpCases() { caseCount += 1; const b = document.getElementById("cases-badge"); if (b) b.textContent = caseCount; }

const SEV_CLASS = { critical: "sev-crit", high: "sev-high", medium: "sev-med", low: "sev-low" };
const STATUS_ICON = { open: "🔴", investigating: "🔍", contained: "✅", closed: "⚪" };

function renderCases(d) {
  const body = document.getElementById("cases-body");
  const sum = document.getElementById("cases-summary");
  const s = d.summary || {};
  sum.innerHTML = `<span><b>${s.opened||0}</b> opened</span><span><b>${s.contained||0}</b> contained</span>
    <span><b>${s.closed_false_positive||0}</b> false positive</span>
    <span><b>${s.open||0}</b> open</span>
    <span>MTTC <b>${s.mean_time_to_contain ?? "–"}</b></span>`;
  const cases = d.cases || [];
  body.innerHTML = cases.length ? `<table class="cases-table">
    <tr><th>Incident</th><th>Host</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Note</th></tr>
    ${cases.map((c) => `<tr>
      <td class="c-id">${escapeHtml(c.id)}</td>
      <td>${escapeHtml(c.host)}</td>
      <td><span class="sev ${SEV_CLASS[c.severity]||""}">${escapeHtml(c.severity)}</span></td>
      <td>${STATUS_ICON[c.status]||""} ${escapeHtml(c.status)}</td>
      <td>${c.alerts}</td>
      <td class="c-note">${escapeHtml(c.resolution||"")}</td>
    </tr>`).join("")}
    </table>` : "<p style='color:#7d8ba1'>No incidents yet — alerts open a case automatically.</p>";
}

async function openCases() {
  const modal = document.getElementById("cases-modal");
  modal.classList.remove("hidden");
  document.getElementById("cases-body").innerHTML = "<p style='color:#7d8ba1'>Loading…</p>";
  try { renderCases(await (await fetch("/api/cases")).json()); }
  catch (e) { document.getElementById("cases-body").innerHTML = "<p style='color:#7d8ba1'>Case board unavailable.</p>"; }
}

async function openExposure() {
  const modal = document.getElementById("exposure-modal");
  const body = document.getElementById("exposure-body");
  modal.classList.remove("hidden");
  body.innerHTML = "<p style='color:#7d8ba1'>Analysing attack paths…</p>";
  try {
    const d = await (await fetch("/api/exposure")).json();
    const fixes = (d.top_fixes || []).map((f) => `
      <tr><td><span class="xf-act">${escapeHtml(f.action)}</span> ${escapeHtml(f.label)}</td>
        <td class="xf-num">−${f.paths_removed}</td>
        <td><div class="xf-bar"><div style="width:${Math.round(f.pct_removed*100)}%"></div></div>
          <span class="xf-pct">${Math.round(f.pct_removed*100)}%</span></td></tr>`).join("");
    const plan = (d.minimal_fix_plan || []).map((f, i) =>
      `<li>${escapeHtml(f.label)} <span class="xf-left">→ ${f.paths_after} paths left</span></li>`).join("");
    body.innerHTML = `
      <p class="xf-lead">Current exposure: <b>${d.current_exposure}</b> viable attack path${d.current_exposure===1?"":"s"} to the crown jewel.</p>
      <h3>Highest-impact single fixes</h3>
      ${fixes ? `<table class="xf-table">${fixes}</table>` : "<p style='color:#7d8ba1'>No single fix reduces exposure right now.</p>"}
      <h3>Minimal fix plan ${plan ? `<span class="xf-left">(${d.minimal_fix_plan.length} step${d.minimal_fix_plan.length===1?"":"s"} → ${d.residual_after_plan} residual)</span>` : ""}</h3>
      ${plan ? `<ol class="xf-plan">${plan}</ol>` : "<p style='color:#7d8ba1'>Already at minimal exposure.</p>"}
      <p class="sc-note">Each fix is scored by how many attack paths it removes now. The plan greedily
      applies the most impactful fix until exposure reaches zero — a prioritised remediation backlog.</p>`;
  } catch (e) {
    body.innerHTML = "<p style='color:#7d8ba1'>Exposure analysis unavailable.</p>";
  }
}

async function openBoard() {
  const modal = document.getElementById("board-modal");
  const body = document.getElementById("board-body");
  modal.classList.remove("hidden");
  try {
    const r = await fetch("/api/benchmarks");
    if (!r.ok) throw new Error((await r.json()).error || r.status);
    const d = await r.json();
    body.innerHTML = `<p style="color:#7d8ba1">generated ${escapeHtml(d.generated_at)} ·
      wall ${d.wall_time_s}s</p>
      <table><tr><th>RED vs BLUE</th><th>matches</th><th>RED win</th><th>BLUE win</th>
      <th>avg rounds</th><th>fallbacks</th></tr>
      ${d.pairings.map((p) => `<tr><td>${escapeHtml(p.pairing)}</td>
        <td>${p.finished}/${p.matches}</td>
        <td style="color:#ff5c7c">${p.red_win_rate != null ? Math.round(p.red_win_rate * 100) + "%" : "-"}</td>
        <td style="color:#6cb5ff">${p.blue_win_rate != null ? Math.round(p.blue_win_rate * 100) + "%" : "-"}</td>
        <td>${p.avg_rounds ?? "-"}</td><td>${p.avg_fallbacks_per_match ?? 0}</td></tr>`).join("")}
      </table>
      <p style="color:#7d8ba1;font-size:12px">run <code>.venv/bin/python scripts/benchmark.py
      --red &lt;model&gt; --blue &lt;model&gt; -n 10</code> to refresh</p>`;
  } catch (e) {
    body.innerHTML = `<p style="color:#7d8ba1">No benchmark data yet. Run
      <code>.venv/bin/python scripts/benchmark.py -n 12</code> first.</p>`;
  }
}

function setView(v) {
  state.view = v;
  document.getElementById("view-god").classList.toggle("active", v === "god");
  document.getElementById("view-red").classList.toggle("active", v === "red");
  applyView();
}

// ---------------------------------------------------------------- boot
// keep floating UI (endgame dock) clear of the control bar, which wraps on narrow screens
new ResizeObserver(([e]) => document.documentElement.style.setProperty(
  "--footer-h", `${Math.ceil(e.target.getBoundingClientRect().height)}px`))
  .observe(document.getElementById("controls"));
initGraph();
initSpark();
initControls();
connect();
