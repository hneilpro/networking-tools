"""Hub homepage. Self-contained: no external resources."""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Networking Tools</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; padding: 1.2rem; max-width: 860px; margin-inline: auto; line-height: 1.45; }
  h1 { font-size: 1.4rem; margin-bottom: .2rem; }
  .sub { opacity: .75; margin-top: 0; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
  a.tool { display: block; text-decoration: none; color: inherit; }
  a.tool:hover { background: #8882; }
  a.tool h2 { margin: 0 0 .3rem; font-size: 1.1rem; }
  a.tool p { margin: 0; opacity: .85; }
</style>
</head>
<body>
<h1>Networking Tools</h1>
<p class="sub">Small local tools that run entirely on this PC. Pick one; it starts only when you pick it, and everything stays in this one program until you close it.</p>

<a class="tool card" href="/launch/rdp?token=__TOKEN__">
  <h2>Remote Desktop Troubleshooter</h2>
  <p>Works out whether a firewall, the router/network, or the target PC itself is blocking a Windows Remote Desktop (RDP) connection, and gives the fix steps in order.</p>
</a>

<a class="tool card" href="/launch/monitor?token=__TOKEN__">
  <h2>Network Stability Monitor</h2>
  <p>Live ping, jitter, and packet loss to your router and the internet, graphed over time, with an optional per-URL connection check and an on-demand speed test.</p>
</a>

<p><small>Each tool page opens with its own private session link. Keep this window's terminal running while you use the tools; Ctrl+C stops everything.</small></p>
</body>
</html>
"""
