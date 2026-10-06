#!/usr/bin/env python3
"""Start all the networking tools from one homepage menu.

Opens a local homepage listing every tool in this repo. Each tool
starts only when you pick it, and runs inside this one program.
You can also still start each tool on its own, e.g.
`python run_rdp_troubleshooter.py` or `python run_network_monitor.py`.

Usage:
    python run_networking_tools.py            # start + open browser
    python run_networking_tools.py --no-open  # start, print the URL only
"""
import argparse

from networking_hub.app import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Networking Tools (all-in-one launcher)")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't open a browser automatically; just print the local URL.")
    args = parser.parse_args()
    serve(open_browser=not args.no_open)


if __name__ == "__main__":
    main()
