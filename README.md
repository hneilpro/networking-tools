# networking-tools

A growing collection of small, local tools that help you troubleshoot network
connection problems. Every tool runs entirely on your own PC in your browser:
no accounts, no cloud, nothing uploaded anywhere.

## Tools

| Tool | What it does |
| --- | --- |
| **Remote Desktop Troubleshooter** (`run_rdp_troubleshooter.py`) | Works out whether a **firewall**, the **router/network**, or the **target PC itself** is blocking a Windows Remote Desktop (RDP) connection, and gives the fix steps in order. |
| **Network Stability Monitor** (`run_network_monitor.py`) | Graphs **ping, jitter, and packet loss** to your router and the internet over time, so you can see whether a slowdown is inside your home or outside it. Optional per-URL connection check and on-demand speed test. |

Run everything from one homepage menu instead:

```bash
python run_networking_tools.py
```

Each tool starts only when you pick it from the menu, and everything runs
inside that one program. Each tool also still works on its own with its
own launcher script.

---

## Remote Desktop Troubleshooter

You try to Remote Desktop into another Windows PC and it just won't connect.
This tool runs a short sequence of checks from your PC to the target and
tells you which layer is blocking you:

1. **Name/IP check** — does the PC name resolve to an address at all?
2. **Network path** — same local network, different subnet/VPN, or over the internet?
3. **Ping test** — is the PC awake and reachable? (Some PCs block ping; the later checks cover that.)
4. **RDP port test (3389)** — open, actively refused, or silently dropped? Each answer means something different:
   - *Open* → RDP is listening; any remaining failure is sign-in/session, not network.
   - *Refused* → the PC answered but nothing is listening: RDP is off, the service is stopped, the port was changed, or the target is a Windows **Home** edition (Home cannot accept RDP connections).
   - *Silent (timeout)* → something is dropping the traffic: a firewall.
5. **Windows port hints (135/139/445)** — if these answer while 3389 is silent, the PC is alive and a firewall is blocking *just* RDP. If nothing answers at all, the PC is off/asleep, on another network, or the router is isolating devices from each other.

The result is a plain-language verdict ("Firewall is most likely blocking just
the RDP port"), why it thinks so, the fix steps in order, and read-only
PowerShell checks you can paste on the target PC to confirm.

It can also **scan your local network** and list the devices that answer,
flagging likely Windows PCs and PCs that are already RDP-ready, so you can
pick the target from a dropdown instead of hunting for its IP address.

### Only use it on networks and PCs you own or have permission to test.

Port scanning other people's networks can be against their rules or the law.
The tool refuses to scan anything except private (home/office) networks of
254 addresses or fewer, and only scans when you click the button.

---

---

## Network Stability Monitor

Your connection feels fine one minute and terrible the next. This tool
watches it continuously and graphs what is actually happening:

- **Ping (latency)** to your gateway/router and to two internet targets
  (Cloudflare 1.1.1.1, Google 8.8.8.8), sampled about once a second.
- **Jitter** — how much the ping bounces around. Steady 40 ms beats
  bouncing between 10 ms and 120 ms; jitter is what makes calls and
  games feel broken.
- **Packet loss** — the share of probes that never came back. Even
  1–3% loss degrades calls and gaming badly.
- Per-target **median, p95, and p99** ping (averages hide spikes),
  current / min / max, worst spike, and a plain-language verdict:
  stable, degraded, unstable, or down. A gateway that refuses probes
  while internet traffic flows through it is reported as
  **probe blocked** instead of down — that is the router (or a virtual
  gateway) ignoring ping, not a LAN outage.
- A **graph range selector** (1 min, 5 min, 15 min, 1 hour, All, or the
  current session): stats follow the range you are looking at, outages
  are shaded red on the graph, and clicking a target name in the legend
  hides or shows its line.
- An **outage log**: when a target failed three probes in a row, when
  it came back, and how long it was out.
- **Router vs internet separation**: if the gateway line stays clean
  while the internet lines spike, the fault is outside your home.

Timed sessions and optional checks:

- **Timed stability session**: run the live monitor for 1 minute,
  5 minutes, 1 hour, or a custom length (1–240 minutes), with a
  progress bar and a live report covering only that stretch. When it
  ends you get per-target verdicts, every outage with times, and a
  plain conclusion — inside your home or outside it — that you can
  copy, download as a report, or export as session CSV. That is the
  evidence to hand your ISP.
- **Test a specific site or URL**: paste a URL (or host) and either add
  it as a continuously monitored target on the same graph, or run a
  one-shot connection breakdown — DNS time, TCP connect, TLS handshake,
  time to first byte, total time, and HTTP status.
- **Run speed test**: a sustained download (about 25 seconds) and
  upload (about 20 seconds) over several streams at once via
  Cloudflare's public speed endpoints, with the first couple of
  seconds of slow-start ramp discarded from the headline numbers —
  short bursts mostly measure the ramp, not your line. It also reports
  a **bufferbloat grade**: how much your latency rises while the line
  is saturated, which is what makes calls and games fall apart during
  someone else's download. On a fast line the test can use well over a
  gigabyte; the result shows how much data it actually used.
- **Expected speeds verdict**: enter the download/upload speeds your
  internet plan promises and save them; every speed test after that is
  graded against them with a bar graphic per direction — the measured
  speed as a percentage of your plan (90%+ excellent, 75%+ good,
  50%+ below expected, under 50% way below), with a marker at your
  plan speed. Your expected speeds are personal and per-PC, so they
  are stored as JSON in `network_monitor/local_data/` inside the app,
  a folder that is excluded from git and never sent anywhere.
- **Download CSV**: exports the whole monitoring history so you have a
  record of a dropout, e.g. for an ISP support call.

Run it:

```bash
python run_network_monitor.py
```

Limitations to know:

- Ping uses your OS `ping` command; if a target blocks ping, the tool
  measures TCP connect time instead and says so. Blocked ping alone
  never counts as "down". The gateway is probed on several common
  ports (80/443/53/8080/22), and its address comes from your OS routing
  table — the old ".1 guess" is only a labelled fallback.
- **Run it natively, not under WSL or a VM, to measure your router.**
  Inside WSL the default gateway is the Windows host's virtual NAT
  (a 172.x.x.1 address), not your physical router; it often refuses
  probes while forwarding traffic fine, and the page flags this.
  The same applies to any virtualized network whose gateway is a
  host-only NAT.
- Sample cadence is about one second per target, but a failing target
  takes longer to time out, so the real interval stretches when things
  are already broken. Timestamps in the CSV are exact.
- The speed test uses several plain-HTTP streams for a fixed time, so
  very fast lines may still read low. Treat it as "is it roughly
  right", not a benchmark record. A 2 GB safety cap ends a phase early
  on extremely fast lines; the result says so when that happens.
- History lives in memory (about two hours of samples) plus the CSV
  export. Nothing is uploaded anywhere.

## Setup (one time)

You need **Python 3.10 or newer**. The tools themselves use only the Python
standard library — nothing to install. (The optional `requirements-dev.txt`
is only for running the test suite.)

Create a project-based virtual environment — a `.venv` folder inside this
project, never a system-wide install:

### Windows (PowerShell)

```powershell
git clone https://github.com/hneilpro/networking-tools.git
cd networking-tools
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, allow scripts for your user once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Windows (Command Prompt)

```bat
git clone https://github.com/hneilpro/networking-tools.git
cd networking-tools
py -m venv .venv
.venv\Scripts\activate.bat
```

### Linux

```bash
git clone https://github.com/hneilpro/networking-tools.git
cd networking-tools
python3 -m venv .venv
source .venv/bin/activate
```

### macOS

```bash
git clone https://github.com/hneilpro/networking-tools.git
cd networking-tools
python3 -m venv .venv
source .venv/bin/activate
```

The `(.venv)` prefix in your prompt means the environment is active. To leave
it later, run `deactivate`. The `.venv` folder is git-ignored, so it stays
yours and is never committed.

## Run it

With the environment active (or even without — there are no dependencies):

```bash
python run_networking_tools.py      # homepage menu with every tool
python run_rdp_troubleshooter.py    # or: just the RDP tool
python run_network_monitor.py       # or: just the stability monitor
```

Your browser opens a local page (address looks like
`http://127.0.0.1:54321/?token=...`). Click **Scan my network**, pick the PC
you want to connect to (or type its name/IP), choose how you're connecting,
and run the diagnosis.

Options:

```bash
python run_rdp_troubleshooter.py --no-open   # don't auto-open a browser; just print the URL
```

Stop it any time with `Ctrl+C` in the terminal.

## How it stays safe

- The web page is served on `127.0.0.1` only — other devices on your network
  cannot reach it.
- Each run generates a random token; the page and every check require it, so
  a random website open in another tab can't poke the tool through your browser.
- No credentials are ever asked for, collected, or stored. The tool never
  tries to log into anything.
- Network scans are limited to private networks, 254 addresses max, and only
  happen when you click Scan.
- Targeted checks go only to the one PC you pick.

## Limitations to know

- **Windows Home can't be an RDP target.** Home editions can connect *out* to
  other PCs but can never accept Remote Desktop connections. The target needs
  Windows Pro, Enterprise, or Education. The tool detects the usual footprint
  of this and will tell you to check.
- **Ping can lie.** Many PCs and firewalls block ping while RDP works fine, so
  the verdict never rests on ping alone.
- **A sleeping PC is invisible.** You can't connect to a PC that's asleep or
  hibernating; wake it for testing.
- **Scanning sees only your local network segment.** PCs behind guest Wi-Fi,
  another VLAN, or router "client isolation" won't show up — which is itself
  one of the things the diagnosis checks for.
- IPv6 targets aren't supported yet.

## Running the tests (optional, for contributors)

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Repo layout

```
run_networking_tools.py       # all-in-one launcher: homepage menu, tools start on pick
run_rdp_troubleshooter.py     # launcher for the RDP troubleshooter
run_network_monitor.py        # launcher for the stability monitor
networking_hub/
    app.py                    # hub server + lazy in-process tool launcher
    web_ui.py                 # the homepage menu
rdp_troubleshooter/
    app.py                    # local web server (127.0.0.1, token-guarded)
    web_ui.py                 # the single browser page (self-contained, no external assets)
    diagnostics.py            # check sequence + verdict engine
    scanner.py                # local network device discovery
    network_utils.py          # input validation, subnet math
network_monitor/
    app.py                    # local web server (127.0.0.1, token-guarded)
    web_ui.py                 # live graph page (self-contained, no external assets)
    monitor.py                # continuous sampler, ring buffer, outage log
    prober.py                 # ping/TCP probes, HTTP breakdown, speed test
    metrics.py                # median/p95/jitter/loss stats + stability verdict
    local_settings.py         # expected plan speeds, stored as local JSON
    local_data/               # runtime-written settings JSON; git-ignored, never committed
tests/                        # pytest suite (verdict logic, metrics, validation, HTTP layer)
```

## License

MIT — see `LICENSE`.
