# networking-tools

A growing collection of small, local tools that help you troubleshoot network
connection problems. Every tool runs entirely on your own PC in your browser:
no accounts, no cloud, nothing uploaded anywhere.

## Tools

| Tool | What it does |
| --- | --- |
| **Remote Desktop Troubleshooter** (`run_rdp_troubleshooter.py`) | Works out whether a **firewall**, the **router/network**, or the **target PC itself** is blocking a Windows Remote Desktop (RDP) connection, and gives the fix steps in order. |

More tools will live alongside it in this repo; each gets its own launcher
script and its own section below.

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
python run_rdp_troubleshooter.py
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
run_rdp_troubleshooter.py     # launcher for the RDP troubleshooter
rdp_troubleshooter/
    app.py                    # local web server (127.0.0.1, token-guarded)
    web_ui.py                 # the single browser page (self-contained, no external assets)
    diagnostics.py            # check sequence + verdict engine
    scanner.py                # local network device discovery
    network_utils.py          # input validation, subnet math
tests/                        # pytest suite (verdict logic, validation, HTTP layer)
```

## License

MIT — see `LICENSE`.
