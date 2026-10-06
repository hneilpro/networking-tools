"""Single-page local web UI. Self-contained: no external resources,
so nothing is fetched from the internet when the page loads."""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Stability Monitor</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; padding: 1.2rem; max-width: 980px; margin-inline: auto; line-height: 1.45; }
  h1 { font-size: 1.4rem; margin-bottom: .2rem; }
  .sub { opacity: .75; margin-top: 0; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
  label { display: block; font-weight: 600; margin: .7rem 0 .25rem; }
  input, button { font: inherit; padding: .5rem; border-radius: 6px; border: 1px solid #8888; width: 100%; box-sizing: border-box; }
  button { cursor: pointer; font-weight: 600; margin-top: .8rem; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: .8rem; }
  .tcard { border: 1px solid #8884; border-radius: 10px; padding: .8rem; }
  .tcard h3 { margin: 0 0 .3rem; font-size: 1rem; }
  .stats { display: grid; grid-template-columns: 1fr 1fr; gap: .2rem .8rem; font-size: .92rem; }
  .ok { color: #1a7f37; } .bad { color: #cf222e; } .mid { color: #bf8700; }
  canvas { width: 100%; height: 260px; display: block; }
  .legend { display: flex; flex-wrap: wrap; gap: .8rem; font-size: .9rem; margin-top: .4rem; }
  .legend span { cursor: pointer; }
  .legend .off { opacity: .35; text-decoration: line-through; }
  .swatch { display: inline-block; width: .8rem; height: .8rem; border-radius: 2px; margin-right: .3rem; }
  .seg { display: flex; flex-wrap: wrap; gap: .4rem; margin: .6rem 0 .2rem; }
  .seg button { width: auto; margin-top: 0; padding: .35rem .7rem; }
  .seg button.active { outline: 2px solid #1f77b4; }
  .bar { height: 10px; border: 1px solid #8888; border-radius: 5px; overflow: hidden; margin: .5rem 0; }
  .bar div { height: 100%; background: #1f77b4; width: 0%; }
  code { background: #8882; padding: .1rem .3rem; border-radius: 4px; word-break: break-all; }
  pre { background: #8882; padding: .7rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  .hidden { display: none; }
  #status { min-height: 1.4em; }
  .badge { display: inline-block; padding: .2rem .7rem; border-radius: 999px; font-weight: 700; color: #fff; }
  .badge.excellent { background: #1a7f37; } .badge.good { background: #5a9e2f; }
  .badge.fair { background: #bf8700; } .badge.poor { background: #cf222e; }
  .badge.unknown { background: #888; }
  .gauge { margin: .9rem 0; }
  .gauge-head { display: flex; justify-content: space-between; gap: .8rem; flex-wrap: wrap; }
  .gauge-track { position: relative; height: 18px; border: 1px solid #8888; border-radius: 9px; background: #8882; margin: 1.4rem 0 .25rem; }
  .gauge-fill { height: 100%; border-radius: 9px; max-width: 100%; }
  .fill-excellent { background: #1a7f37; } .fill-good { background: #5a9e2f; }
  .fill-fair { background: #bf8700; } .fill-poor { background: #cf222e; } .fill-unknown { background: #888; }
  .gauge-marker { position: absolute; top: -4px; bottom: -4px; width: 2px; background: currentColor; }
  .gauge-marker span { position: absolute; top: -1.25rem; right: -1.2rem; font-size: .72rem; white-space: nowrap; opacity: .85; }
</style>
</head>
<body>
<h1>Network Stability Monitor</h1>
<p class="sub">Live ping, jitter, and packet loss to your router and the internet, graphed over time. If the router line stays clean while the internet lines spike, the fault is outside your home. Everything runs on this PC.</p>

<div class="card">
  <h2>Live stability</h2>
  <p id="netinfo">Detecting your network&hellip;</p>
  <div class="seg" id="rangeBar" role="group" aria-label="Graph range">
    <button type="button" data-range="60">1 min</button>
    <button type="button" data-range="300" class="active">5 min</button>
    <button type="button" data-range="900">15 min</button>
    <button type="button" data-range="3600">1 hour</button>
    <button type="button" data-range="all">All</button>
    <button type="button" data-range="session">Session</button>
  </div>
  <canvas id="chart" width="900" height="260"></canvas>
  <div class="legend" id="legend"></div>
  <div class="grid" id="cards" style="margin-top:.8rem"></div>
  <p id="outages"></p>
  <button id="exportBtn" type="button">Download session history (CSV)</button>
</div>

<div class="card">
  <h2>Timed stability session</h2>
  <p>Run the live monitor for a set length, then get one report for exactly that stretch: per-target verdicts, median / p95 / p99, worst spike, jitter, loss, every outage with times, and a plain call on whether the bad stretch was inside your home or outside it. Handy as evidence for your ISP.</p>
  <div class="seg" id="sessionPresets">
    <button type="button" data-min="1">1 minute</button>
    <button type="button" data-min="5">5 minutes</button>
    <button type="button" data-min="60">1 hour</button>
  </div>
  <label for="sessionMinutes">Session length, minutes (1 to 240)</label>
  <input id="sessionMinutes" type="number" min="1" max="240" step="1" value="5">
  <div class="row">
    <button id="sessionStartBtn" type="button">Start session</button>
    <button id="sessionCancelBtn" type="button" class="hidden">Cancel session</button>
  </div>
  <p id="sessionInfo" role="status"></p>
  <div class="bar hidden" id="sessionBarWrap"><div id="sessionBar"></div></div>
  <pre id="sessionReport" class="hidden"></pre>
  <div class="row hidden" id="sessionActions">
    <button id="copyReportBtn" type="button">Copy summary</button>
    <button id="downloadReportBtn" type="button">Download report (.txt)</button>
  </div>
  <button id="sessionCsvBtn" type="button" class="hidden">Download session data (CSV)</button>
</div>

<div class="card">
  <h2>Test a specific site or URL</h2>
  <label for="customUrl">URL or host (optional)</label>
  <input id="customUrl" placeholder="e.g. https://example.com or 192.168.1.50" autocomplete="off">
  <div class="row">
    <button id="addTargetBtn" type="button">Monitor this host continuously</button>
    <button id="httpCheckBtn" type="button">One-shot connection check</button>
  </div>
  <div id="httpResult" class="hidden" style="margin-top:.8rem"></div>
</div>

<div class="card">
  <h2>Speed test</h2>
  <p>Sustained download (about 25 seconds) then upload (about 20 seconds), using several streams at once, with the first couple of seconds of slow-start ramp discarded from the headline numbers. Short bursts mostly measure the ramp, not your line; this runs long enough for the speed to settle. On a fast line this can use well over a gigabyte. The live graph above will spike while it runs; that is the test, not an outage. It also grades bufferbloat: how much your latency rises while the line is saturated.</p>
  <h3>Your expected (plan) speeds</h3>
  <p>What does your internet plan promise? These are saved on this PC only, in a local file that never leaves the machine, and the next speed test is graded against them.</p>
  <div class="row">
    <div>
      <label for="expectedDownload">Expected download (Mbps)</label>
      <input id="expectedDownload" type="number" min="0" step="any" placeholder="e.g. 500" autocomplete="off">
    </div>
    <div>
      <label for="expectedUpload">Expected upload (Mbps)</label>
      <input id="expectedUpload" type="number" min="0" step="any" placeholder="e.g. 50" autocomplete="off">
    </div>
  </div>
  <button id="saveExpectedBtn" type="button">Save expected speeds</button>
  <p id="expectedStatus" role="status"></p>
  <button id="speedBtn" type="button">Run speed test</button>
  <div id="speedResult" role="status"></div>
</div>

<p id="status" role="status"></p>

<script>
const token = new URLSearchParams(location.search).get("token") || "";
const $ = id => document.getElementById(id);
const COLORS = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf"];
async function api(path, body) {
  const opts = { method: body ? "POST" : "GET", headers: { "X-Tool-Token": token } };
  if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("Request failed: " + res.status));
  return data;
}
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
function fmt(v, unit) { return v == null ? "—" : v + unit; }
function fmtClock(s) { s = Math.max(0, Math.round(s)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
function fmtMB(bytes) { return bytes == null ? "—" : (bytes / 1000000).toFixed(1) + " MB"; }
function verdictClass(v) { return v === "stable" ? "ok" : (v === "down" || v === "unstable") ? "bad" : "mid"; }

let lastStatus = null;
let rangeMode = "300";
let hiddenTargets = new Set();

function setRange(mode) {
  rangeMode = mode;
  document.querySelectorAll("#rangeBar button").forEach(b =>
    b.classList.toggle("active", b.dataset.range === mode));
  refresh();
}
document.querySelectorAll("#rangeBar button").forEach(b =>
  b.addEventListener("click", () => setRange(b.dataset.range)));

function drawChart(targets, status) {
  const canvas = $("chart"), ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height, pad = 8, bottom = 16;
  ctx.clearRect(0, 0, W, H);
  const visible = targets.map((t, i) => ({ t, i })).filter(v => !hiddenTargets.has(v.i) && v.t.series.length);
  if (!visible.length) {
    ctx.fillStyle = "#888"; ctx.font = "12px system-ui";
    ctx.fillText("No samples in this range yet. Widen the range or wait a few seconds.", 40, H / 2);
    return;
  }
  let t0 = Infinity, t1 = -Infinity, maxMs = 50;
  visible.forEach(v => v.t.series.forEach(p => {
    if (p[0] < t0) t0 = p[0];
    if (p[0] > t1) t1 = p[0];
    if (p[1] != null && p[1] > maxMs) maxMs = p[1];
  }));
  maxMs = Math.ceil(maxMs * 1.15);
  const xOf = ts => 34 + (W - 34 - pad) * (t1 > t0 ? (ts - t0) / (t1 - t0) : 1);
  // Outage shading first, so the lines draw over it.
  const bands = (status.outages || []).map(o => [o.started_at, o.ended_at])
    .concat((status.active_outages || []).map(o => [o.started_at, null]));
  ctx.fillStyle = "rgba(207,34,46,0.14)";
  bands.forEach(([a, b]) => {
    if (a == null) return;
    const x1 = xOf(Math.max(a, t0)), x2 = xOf(Math.min(b == null ? t1 : b, t1));
    if (x2 > x1) ctx.fillRect(x1, pad, x2 - x1, H - 2 * pad - bottom);
  });
  ctx.strokeStyle = "#8886"; ctx.fillStyle = "#888"; ctx.font = "11px system-ui";
  for (let i = 0; i <= 4; i++) {
    const y = pad + (H - 2 * pad - bottom) * i / 4, val = Math.round(maxMs * (1 - i / 4));
    ctx.beginPath(); ctx.moveTo(34, y); ctx.lineTo(W - pad, y); ctx.stroke();
    ctx.fillText(val + " ms", 2, y + 3);
  }
  ctx.fillText(new Date(t0 * 1000).toLocaleTimeString(), 34, H - 3);
  const endLabel = new Date(t1 * 1000).toLocaleTimeString();
  ctx.fillText(endLabel, W - pad - ctx.measureText(endLabel).width, H - 3);
  visible.forEach(v => {
    const t = v.t;
    ctx.strokeStyle = COLORS[v.i % COLORS.length]; ctx.lineWidth = 1.6; ctx.beginPath();
    let started = false;
    t.series.forEach(p => {
      if (p[1] == null) { started = false; return; }
      const x = xOf(p[0]);
      const y = pad + (H - 2 * pad - bottom) * (1 - Math.min(p[1], maxMs) / maxMs);
      if (!started) { ctx.moveTo(x, y); started = true; } else { ctx.lineTo(x, y); }
    });
    ctx.stroke(); ctx.lineWidth = 1;
  });
}

function render(status) {
  lastStatus = status;
  $("netinfo").textContent = (status.local_ip
    ? `This PC: ${status.local_ip} · Network: ${status.subnet} · Monitoring ${status.targets.length} target(s)`
    : "Could not detect this PC's network address.")
    + (status.network_note ? " " + status.network_note : "");
  $("legend").innerHTML = status.targets.map((t, i) =>
    `<span data-i="${i}" class="${hiddenTargets.has(i) ? "off" : ""}"><span class="swatch" style="background:${COLORS[i % COLORS.length]}"></span>${esc(t.name)}</span>`).join("");
  document.querySelectorAll("#legend span[data-i]").forEach(el =>
    el.addEventListener("click", () => {
      const i = Number(el.dataset.i);
      if (hiddenTargets.has(i)) hiddenTargets.delete(i); else hiddenTargets.add(i);
      render(lastStatus);
    }));
  $("cards").innerHTML = status.targets.map(t => {
    const s = t.stats;
    return `<div class="tcard"><h3>${esc(t.name)}</h3>` +
      `<p class="${verdictClass(t.verdict)}" style="margin:.1rem 0"><strong>${esc(String(t.verdict).replace(/_/g, " "))}</strong> — ${esc(t.verdict_explanation)}</p>` +
      `<div class="stats"><span>Now: ${fmt(s.last_ms, " ms")}</span><span>Median: ${fmt(s.median_ms, " ms")}</span>` +
      `<span>p95: ${fmt(s.p95_ms, " ms")}</span><span>p99: ${fmt(s.p99_ms, " ms")}</span>` +
      `<span>Min: ${fmt(s.min_ms, " ms")}</span><span>Worst spike: ${fmt(s.max_ms, " ms")}</span>` +
      `<span>Jitter: ${fmt(s.jitter_ms, " ms")}</span><span>Loss: ${s.loss_pct}% (${s.successes}/${s.samples})</span></div></div>`;
  }).join("");
  const outageLines = status.outages.slice(-8).reverse().map(o =>
    `${esc(o.target)}: ${new Date(o.started_at * 1000).toLocaleTimeString()} → ${new Date(o.ended_at * 1000).toLocaleTimeString()} (${esc(o.duration_s)}s)`);
  (status.active_outages || []).forEach(o =>
    outageLines.unshift(`${esc(o.target)}: out since ${new Date(o.started_at * 1000).toLocaleTimeString()} (still out)`));
  $("outages").innerHTML = outageLines.length
    ? "<strong>Outages:</strong><br>" + outageLines.join("<br>")
    : "No outages (3+ failed probes in a row) recorded yet.";
  drawChart(status.targets, status);
  renderSession(status.session);
}

function renderSession(session) {
  const info = $("sessionInfo"), barWrap = $("sessionBarWrap"), bar = $("sessionBar");
  const report = $("sessionReport"), actions = $("sessionActions"), csvBtn = $("sessionCsvBtn");
  const cancelBtn = $("sessionCancelBtn"), startBtn = $("sessionStartBtn");
  if (!session) {
    info.textContent = "No session yet. Pick a length and start one.";
    barWrap.classList.add("hidden"); report.classList.add("hidden");
    actions.classList.add("hidden"); csvBtn.classList.add("hidden");
    cancelBtn.classList.add("hidden"); startBtn.disabled = false;
    return;
  }
  startBtn.disabled = session.state === "running";
  cancelBtn.classList.toggle("hidden", session.state !== "running");
  barWrap.classList.remove("hidden");
  bar.style.width = session.progress_pct + "%";
  if (session.state === "running") {
    info.textContent = `Session running: ${fmtClock(session.elapsed_s)} elapsed, ${fmtClock(session.remaining_s)} left. Stats below cover only this session.`;
  } else {
    info.textContent = `Session ${session.state} (${fmtClock(session.elapsed_s)} recorded). ` +
      (session.report && session.report.conclusion ? session.report.conclusion : "");
  }
  if (session.report_text) {
    report.textContent = session.report_text;
    report.classList.remove("hidden");
    actions.classList.remove("hidden"); csvBtn.classList.remove("hidden");
  }
}

async function refresh() {
  try { render(await api("/api/status?range=" + encodeURIComponent(rangeMode))); }
  catch (e) { $("status").textContent = e.message; }
}
refresh(); setInterval(refresh, 2000);

document.querySelectorAll("#sessionPresets button").forEach(b =>
  b.addEventListener("click", () => { $("sessionMinutes").value = b.dataset.min; }));
$("sessionStartBtn").addEventListener("click", async () => {
  const minutes = parseFloat($("sessionMinutes").value);
  if (!minutes || minutes < 1 || minutes > 240) { $("status").textContent = "Session length must be 1 to 240 minutes."; return; }
  try {
    await api("/api/session/start", { duration_min: minutes });
    $("status").textContent = "Session started.";
    setRange("session");
  } catch (e) { $("status").textContent = e.message; }
});
$("sessionCancelBtn").addEventListener("click", async () => {
  try { await api("/api/session/cancel", {}); $("status").textContent = "Session cancelled. Partial report below."; refresh(); }
  catch (e) { $("status").textContent = e.message; }
});
$("copyReportBtn").addEventListener("click", async () => {
  const text = lastStatus && lastStatus.session ? lastStatus.session.report_text : "";
  if (!text) return;
  try { await navigator.clipboard.writeText(text); $("status").textContent = "Summary copied."; }
  catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); ta.remove();
    $("status").textContent = "Summary copied.";
  }
});
$("downloadReportBtn").addEventListener("click", () => {
  const text = lastStatus && lastStatus.session ? lastStatus.session.report_text : "";
  if (!text) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = "network-stability-report.txt"; a.click();
  URL.revokeObjectURL(a.href);
});
$("sessionCsvBtn").addEventListener("click", async () => {
  try {
    const res = await fetch("/api/export.csv?session=1", { headers: { "X-Tool-Token": token } });
    if (!res.ok) throw new Error("Export failed: " + res.status);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "network-session-history.csv"; a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { $("status").textContent = e.message; }
});

$("addTargetBtn").addEventListener("click", async () => {
  const url = $("customUrl").value.trim();
  if (!url) { $("status").textContent = "Type a URL or host first."; return; }
  try { await api("/api/target", { url }); $("status").textContent = "Added. It will appear on the graph as samples come in."; refresh(); }
  catch (e) { $("status").textContent = e.message; }
});
$("httpCheckBtn").addEventListener("click", async () => {
  const url = $("customUrl").value.trim();
  if (!url) { $("status").textContent = "Type a URL or host first."; return; }
  $("httpResult").classList.remove("hidden"); $("httpResult").innerHTML = "Checking&hellip;";
  try {
    const r = (await api("/api/http-check", { url })).result;
    if (!r.ok) { $("httpResult").innerHTML = `<p class="bad">${esc(r.error || "Check failed.")}</p>`; return; }
    $("httpResult").innerHTML = `<div class="stats" style="grid-template-columns:1fr 1fr 1fr">` +
      `<span>Resolved: ${esc(r.resolved_ip)}</span><span>DNS: ${fmt(r.dns_ms, " ms")}</span><span>TCP: ${fmt(r.tcp_ms, " ms")}</span>` +
      `<span>TLS: ${r.tls_ms == null ? "—" : fmt(r.tls_ms, " ms")}</span><span>First byte: ${fmt(r.ttfb_ms, " ms")}</span><span>Total: ${fmt(r.total_ms, " ms")}</span>` +
      `<span>Status: ${esc(r.status)}</span><span>Read: ${esc(r.bytes_read)} bytes</span><span>URL: ${esc(r.url)}</span></div>`;
  } catch (e) { $("httpResult").innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
});
let expectedSpeeds = { download_mbps: null, upload_mbps: null };

function expectedHint() {
  const d = expectedSpeeds.download_mbps, u = expectedSpeeds.upload_mbps;
  if (d == null && u == null) return "No expected speeds saved yet. Add your plan speeds and save.";
  const parts = [];
  if (d != null) parts.push(`Download ${d} Mbps`);
  if (u != null) parts.push(`Upload ${u} Mbps`);
  return "Saved on this PC: " + parts.join(" · ") + ". The next speed test is graded against these.";
}

async function loadExpected() {
  try {
    expectedSpeeds = (await api("/api/expected-speeds")).expected || expectedSpeeds;
    $("expectedDownload").value = expectedSpeeds.download_mbps == null ? "" : expectedSpeeds.download_mbps;
    $("expectedUpload").value = expectedSpeeds.upload_mbps == null ? "" : expectedSpeeds.upload_mbps;
    $("expectedStatus").textContent = expectedHint();
  } catch (e) { $("expectedStatus").textContent = "Could not load saved expected speeds: " + e.message; }
}
loadExpected();

$("saveExpectedBtn").addEventListener("click", async () => {
  const parseField = id => {
    const v = $(id).value.trim();
    return v === "" ? null : Number(v);
  };
  const download = parseField("expectedDownload"), upload = parseField("expectedUpload");
  if ((download !== null && !(download > 0)) || (upload !== null && !(upload > 0))) {
    $("expectedStatus").textContent = "Expected speeds must be numbers above zero, or left blank to clear.";
    return;
  }
  try {
    expectedSpeeds = (await api("/api/expected-speeds", { download_mbps: download, upload_mbps: upload })).expected;
    $("expectedStatus").textContent = "Saved. " + expectedHint();
  } catch (e) { $("expectedStatus").textContent = e.message; }
});

function gaugeHtml(title, assessment, seconds) {
  if (!assessment) return "";
  const a = assessment;
  const head = `<div class="gauge-head"><span>${esc(title)}: ${a.actual_mbps == null ? "failed" : `<strong>${esc(a.actual_mbps)} Mbps</strong>`}` +
    (seconds != null ? ` <small>(${esc(seconds)}s)</small>` : "") + `</span>` +
    `<span class="badge ${esc(a.verdict)}">${esc(a.label)}</span></div>`;
  if (a.expected_mbps == null || a.pct_of_expected == null) {
    return `<div class="gauge">${head}<small>${esc(a.explanation)}</small></div>`;
  }
  const scaleMax = 125; // headroom so beating the plan is visible too
  const fillPct = Math.min(a.pct_of_expected, scaleMax) / scaleMax * 100;
  const markerPct = 100 / scaleMax * 100;
  return `<div class="gauge">${head}` +
    `<div class="gauge-track"><div class="gauge-fill fill-${esc(a.verdict)}" style="width:${fillPct}%"></div>` +
    `<div class="gauge-marker" style="left:${markerPct}%"><span>plan ${esc(a.expected_mbps)} Mbps</span></div></div>` +
    `<small>${esc(a.pct_of_expected)}% of your expected ${esc(title.toLowerCase())} speed. ${esc(a.explanation)}</small></div>`;
}

$("speedBtn").addEventListener("click", async () => {
  $("speedBtn").disabled = true;
  $("speedResult").innerHTML = "Running (about 45 seconds). The graph will spike; that is the test, not an outage.";
  try {
    const r = (await api("/api/speedtest", {})).result;
    if (!r.ok) { $("speedResult").textContent = r.error || "Speed test failed."; return; }
    let html = "";
    if (r.overall_assessment) {
      html += `<p>Overall: <span class="badge ${esc(r.overall_assessment.verdict)}">${esc(r.overall_assessment.label)}</span> ` +
        `<small>${esc(r.overall_assessment.explanation)}</small></p>`;
    }
    html += gaugeHtml("Download", r.download_assessment, r.download_seconds);
    html += gaugeHtml("Upload", r.upload_assessment, r.upload_seconds);
    if (!r.download_assessment && !r.upload_assessment) {
      html += `Download: <strong>${esc(r.download_mbps)} Mbps</strong> · Upload: <strong>${r.upload_mbps == null ? "failed" : esc(r.upload_mbps) + " Mbps"}</strong><br>`;
    }
    html += `<small>Data used: ${esc(fmtMB(r.data_used_bytes))}. ${esc(r.note)}${r.error ? " " + esc(r.error) : ""}</small>`;
    if (r.bufferbloat_grade) {
      html += `<br>Bufferbloat grade: <strong>${esc(r.bufferbloat_grade)}</strong> ` +
        `(latency ${esc(r.idle_latency_ms)} ms idle → ${esc(r.loaded_latency_ms)} ms under load, +${esc(r.bufferbloat_ms)} ms)`;
    } else if (r.idle_latency_ms != null) {
      html += `<br>Idle latency: ${esc(r.idle_latency_ms)} ms. Loaded latency could not be measured this run.`;
    }
    $("speedResult").innerHTML = html;
  } catch (e) { $("speedResult").textContent = e.message; }
  finally { $("speedBtn").disabled = false; }
});
$("exportBtn").addEventListener("click", async () => {
  try {
    const res = await fetch("/api/export.csv", { headers: { "X-Tool-Token": token } });
    if (!res.ok) throw new Error("Export failed: " + res.status);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "network-monitor-history.csv"; a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { $("status").textContent = e.message; }
});
</script>
</body>
</html>
"""
