"""The single-page local web UI. Self-contained: no external resources,
so nothing is fetched from the internet when the page loads."""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RDP Connection Troubleshooter</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; padding: 1.2rem; max-width: 860px; margin-inline: auto; line-height: 1.45; }
  h1 { font-size: 1.4rem; margin-bottom: .2rem; }
  .sub { opacity: .75; margin-top: 0; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
  label { display: block; font-weight: 600; margin: .7rem 0 .25rem; }
  input, select, button { font: inherit; padding: .5rem; border-radius: 6px; border: 1px solid #8888; width: 100%; box-sizing: border-box; }
  button { cursor: pointer; font-weight: 600; margin-top: .8rem; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; }
  .step { display: flex; gap: .6rem; padding: .35rem 0; border-bottom: 1px dashed #8883; }
  .badge { font-weight: 700; min-width: 3.2rem; }
  .pass { color: #1a7f37; } .fail { color: #cf222e; } .warn { color: #bf8700; } .info { color: #57606a; }
  .verdict { border-left: 5px solid #bf8700; }
  code { background: #8882; padding: .1rem .3rem; border-radius: 4px; word-break: break-all; }
  pre { background: #8882; padding: .7rem; border-radius: 8px; overflow-x: auto; }
  pre code { background: none; padding: 0; }
  .device { padding: .4rem .6rem; border: 1px solid #8884; border-radius: 8px; margin: .4rem 0; cursor: pointer; width: 100%; text-align: left; }
  .tag { font-size: .78rem; border: 1px solid #8888; border-radius: 999px; padding: .05rem .5rem; margin-left: .4rem; }
  .hidden { display: none; }
  #status { min-height: 1.4em; }
</style>
</head>
<body>
<h1>Remote Desktop Connection Troubleshooter</h1>
<p class="sub">Works out whether a firewall, the router/network, or the target PC itself is blocking your Windows Remote Desktop connection. Everything runs on this PC; only pick networks and PCs you own or have permission to test.</p>

<div class="card">
  <h2>1. Find the PC you want to connect to</h2>
  <p id="netinfo">Detecting your network&hellip;</p>
  <button id="scanBtn" type="button">Scan my network for devices</button>
  <p id="scanStatus"></p>
  <div id="devices"></div>
  <label for="targetSelect">Found devices (likely Windows PCs first)</label>
  <select id="targetSelect"><option value="">Run a scan, or type the PC below</option></select>
  <label for="target">Target PC name or IP address</label>
  <input id="target" placeholder="e.g. DESKTOP-ABC123 or 192.168.1.42" autocomplete="off">
  <div class="row">
    <div>
      <label for="port">RDP port (default 3389)</label>
      <input id="port" type="number" value="3389" min="1" max="65535">
    </div>
    <div>
      <label for="scenario">How are you connecting?</label>
      <select id="scenario">
        <option value="lan">Same home/office network</option>
        <option value="vpn">Through a VPN</option>
        <option value="internet">Over the internet (different location)</option>
      </select>
    </div>
  </div>
  <label for="symptom">What happens when you try?</label>
  <select id="symptom">
    <option value="generic">It just won't connect</option>
    <option value="not_found">Says the remote PC can't be found</option>
    <option value="timeout">It times out / takes forever then fails</option>
    <option value="refused">Connection refused / the PC couldn't be reached</option>
    <option value="login_rejected">It connects but my login is rejected</option>
    <option value="black_screen">Black screen, freeze, or instant disconnect</option>
  </select>
  <button id="runBtn" type="button">Run diagnosis</button>
  <p id="status" role="status"></p>
</div>

<div class="card hidden" id="results">
  <h2>2. Results</h2>
  <div id="steps"></div>
  <div class="card verdict">
    <h3 id="verdictTitle"></h3>
    <p id="verdictCause"></p>
    <p><strong>Fix steps, in order:</strong></p>
    <ol id="fixSteps"></ol>
  </div>
  <div id="targetChecksWrap" class="hidden">
    <h3>Read-only checks to run ON the target PC</h3>
    <p>Open PowerShell on the target PC itself and paste these. They only read settings; they change nothing.</p>
    <div id="targetChecks"></div>
  </div>
</div>

<script>
const token = new URLSearchParams(location.search).get("token") || "";
const $ = id => document.getElementById(id);
async function api(path, body) {
  const opts = { method: body ? "POST" : "GET", headers: { "X-Tool-Token": token } };
  if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("Request failed: " + res.status));
  return data;
}
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

api("/api/local-info").then(info => {
  $("netinfo").textContent = info.local_ip
    ? `This PC: ${info.local_ip} · Network: ${info.subnet} · Usual router address: ${info.gateway_hint}`
    : "Could not detect this PC's network address.";
}).catch(() => { $("netinfo").textContent = "Could not detect this PC's network address."; });

$("targetSelect").addEventListener("change", () => { if ($("targetSelect").value) $("target").value = $("targetSelect").value; });

$("scanBtn").addEventListener("click", async () => {
  $("scanBtn").disabled = true;
  $("scanStatus").textContent = "Scanning (up to about a minute)...";
  try {
    const data = await api("/api/scan", {});
    const devices = data.devices || [];
    devices.sort((a, b) => (b.windows_likely - a.windows_likely) || (b.rdp_ready - a.rdp_ready));
    $("targetSelect").innerHTML = '<option value="">Pick a device</option>' + devices.map(d =>
      `<option value="${esc(d.ip)}">${esc(d.hostname || d.ip)} (${esc(d.ip)})${d.windows_likely ? " - likely Windows" : ""}${d.rdp_ready ? " - RDP ready" : ""}${d.is_this_pc ? " - this PC" : ""}</option>`).join("");
    $("devices").innerHTML = devices.map(d =>
      `<button type="button" class="device" data-ip="${esc(d.ip)}"><strong>${esc(d.hostname || "Unknown name")}</strong> · ${esc(d.ip)}` +
      `${d.mac ? " · " + esc(d.mac) : ""}${d.windows_likely ? '<span class="tag">likely Windows</span>' : ""}` +
      `${d.rdp_ready ? '<span class="tag">RDP ready</span>' : ""}${d.is_this_pc ? '<span class="tag">this PC</span>' : ""}<br>` +
      `<small>Open ports: ${d.open_ports.length ? d.open_ports.map(p => esc(p.port) + " (" + esc(p.name) + ")").join(", ") : "none found"}${d.ping ? " · answers ping" : ""}</small></button>`).join("");
    document.querySelectorAll(".device").forEach(el => el.addEventListener("click", () => { $("target").value = el.dataset.ip; $("targetSelect").value = el.dataset.ip; }));
    $("scanStatus").textContent = devices.length ? `Found ${devices.length} device(s). Click one to select it.` : "No devices answered. The PCs may be asleep, or the router may isolate devices from each other.";
  } catch (e) {
    $("scanStatus").textContent = e.message;
  } finally { $("scanBtn").disabled = false; }
});

$("runBtn").addEventListener("click", async () => {
  const target = $("target").value.trim();
  if (!target) { $("status").textContent = "Pick a device or type the target PC name/IP first."; return; }
  $("runBtn").disabled = true;
  $("status").textContent = "Running checks...";
  try {
    const data = await api("/api/diagnose", {
      target, port: Number($("port").value || 3389),
      scenario: $("scenario").value, symptom: $("symptom").value
    });
    const r = data.result;
    $("steps").innerHTML = r.steps.map(s =>
      `<div class="step"><span class="badge ${esc(s.status)}">${{pass:"PASS", fail:"FAIL", warn:"WARN", info:"INFO"}[s.status] || "INFO"}</span><span><strong>${esc(s.name)}:</strong> ${esc(s.detail)}</span></div>`).join("");
    $("verdictTitle").textContent = r.verdict_title;
    $("verdictCause").textContent = r.likely_cause + (r.resolved_ip ? ` (Target IP: ${r.resolved_ip})` : "");
    $("fixSteps").innerHTML = r.fix_steps.map(s => `<li>${esc(s)}</li>`).join("");
    if (r.target_checks && r.target_checks.length) {
      $("targetChecks").innerHTML = r.target_checks.map(c =>
        `<p><strong>${esc(c.title)}</strong></p><pre><code>${esc(c.command)}</code></pre><p>${esc(c.read)}</p>`).join("");
      $("targetChecksWrap").classList.remove("hidden");
    }
    $("results").classList.remove("hidden");
    $("status").textContent = "";
  } catch (e) {
    $("status").textContent = e.message;
  } finally { $("runBtn").disabled = false; }
});
</script>
</body>
</html>
"""
