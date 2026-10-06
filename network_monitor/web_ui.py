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
  .swatch { display: inline-block; width: .8rem; height: .8rem; border-radius: 2px; margin-right: .3rem; }
  code { background: #8882; padding: .1rem .3rem; border-radius: 4px; word-break: break-all; }
  pre { background: #8882; padding: .7rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  .hidden { display: none; }
  #status { min-height: 1.4em; }
</style>
</head>
<body>
<h1>Network Stability Monitor</h1>
<p class="sub">Live ping, jitter, and packet loss to your router and the internet, graphed over time. If the router line stays clean while the internet lines spike, the fault is outside your home. Everything runs on this PC.</p>

<div class="card">
  <h2>Live stability</h2>
  <p id="netinfo">Detecting your network&hellip;</p>
  <canvas id="chart" width="900" height="260"></canvas>
  <div class="legend" id="legend"></div>
  <div class="grid" id="cards" style="margin-top:.8rem"></div>
  <p id="outages"></p>
  <button id="exportBtn" type="button">Download session history (CSV)</button>
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
  <p>On-demand download and upload check. It saturates your connection for a few seconds, so the live graph above will spike while it runs. That is expected, not an outage.</p>
  <button id="speedBtn" type="button">Run speed test</button>
  <p id="speedResult" role="status"></p>
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
function verdictClass(v) { return v === "stable" ? "ok" : (v === "down" || v === "unstable") ? "bad" : "mid"; }

let lastStatus = null;
function drawChart(targets) {
  const canvas = $("chart"), ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height, pad = 8;
  ctx.clearRect(0, 0, W, H);
  let maxMs = 50;
  targets.forEach(t => t.series.forEach(p => { if (p[1] != null && p[1] > maxMs) maxMs = p[1]; }));
  maxMs = Math.ceil(maxMs * 1.15);
  ctx.strokeStyle = "#8886"; ctx.fillStyle = "#888"; ctx.font = "11px system-ui";
  for (let i = 0; i <= 4; i++) {
    const y = pad + (H - 2 * pad) * i / 4, val = Math.round(maxMs * (1 - i / 4));
    ctx.beginPath(); ctx.moveTo(34, y); ctx.lineTo(W - pad, y); ctx.stroke();
    ctx.fillText(val + " ms", 2, y + 3);
  }
  targets.forEach((t, ti) => {
    if (!t.series.length) return;
    const t0 = t.series[0][0], t1 = t.series[t.series.length - 1][0];
    ctx.strokeStyle = COLORS[ti % COLORS.length]; ctx.lineWidth = 1.6; ctx.beginPath();
    let started = false;
    t.series.forEach(p => {
      if (p[1] == null) { started = false; return; }
      const x = 34 + (W - 34 - pad) * (t1 > t0 ? (p[0] - t0) / (t1 - t0) : 1);
      const y = pad + (H - 2 * pad) * (1 - Math.min(p[1], maxMs) / maxMs);
      if (!started) { ctx.moveTo(x, y); started = true; } else { ctx.lineTo(x, y); }
    });
    ctx.stroke(); ctx.lineWidth = 1;
  });
}
function render(status) {
  lastStatus = status;
  $("netinfo").textContent = status.local_ip
    ? `This PC: ${status.local_ip} · Network: ${status.subnet} · Monitoring ${status.targets.length} target(s)`
    : "Could not detect this PC's network address.";
  $("legend").innerHTML = status.targets.map((t, i) =>
    `<span><span class="swatch" style="background:${COLORS[i % COLORS.length]}"></span>${esc(t.name)}</span>`).join("");
  $("cards").innerHTML = status.targets.map(t => {
    const s = t.stats;
    return `<div class="tcard"><h3>${esc(t.name)}</h3>` +
      `<p class="${verdictClass(t.verdict)}" style="margin:.1rem 0"><strong>${esc(t.verdict)}</strong> — ${esc(t.verdict_explanation)}</p>` +
      `<div class="stats"><span>Now: ${fmt(s.last_ms, " ms")}</span><span>Median: ${fmt(s.median_ms, " ms")}</span>` +
      `<span>p95: ${fmt(s.p95_ms, " ms")}</span><span>Min/Max: ${fmt(s.min_ms, "")}/${fmt(s.max_ms, " ms")}</span>` +
      `<span>Jitter: ${fmt(s.jitter_ms, " ms")}</span><span>Loss: ${s.loss_pct}% (${s.successes}/${s.samples})</span></div></div>`;
  }).join("");
  $("outages").innerHTML = status.outages.length
    ? "<strong>Outages:</strong><br>" + status.outages.slice(-8).reverse().map(o =>
        `${esc(o.target)}: ${new Date(o.started_at * 1000).toLocaleTimeString()} → ${new Date(o.ended_at * 1000).toLocaleTimeString()} (${esc(o.duration_s)}s)`).join("<br>")
    : "No outages (3+ failed probes in a row) recorded yet.";
  drawChart(status.targets);
}
async function refresh() {
  try { render(await api("/api/status")); } catch (e) { $("status").textContent = e.message; }
}
refresh(); setInterval(refresh, 2000);

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
$("speedBtn").addEventListener("click", async () => {
  $("speedBtn").disabled = true; $("speedResult").textContent = "Running (about 10 seconds). The graph will spike; that is the test, not an outage.";
  try {
    const r = (await api("/api/speedtest", {})).result;
    $("speedResult").innerHTML = r.ok
      ? `Download: <strong>${esc(r.download_mbps)} Mbps</strong> · Upload: <strong>${r.upload_mbps == null ? "failed" : esc(r.upload_mbps) + " Mbps"}</strong><br><small>${esc(r.note)}${r.error ? " " + esc(r.error) : ""}</small>`
      : esc(r.error || "Speed test failed.");
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
