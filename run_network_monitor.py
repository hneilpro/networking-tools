#!/usr/bin/env python3
"""Start the Network Stability Monitor.

Opens a local web page that graphs ping, jitter, and packet loss to
your router and the internet over time, with an optional per-URL
connection check and an on-demand speed test. Nothing is sent
anywhere except the probes you see on the page.

Usage:
    python run_network_monitor.py            # start + open browser
    python run_network_monitor.py --no-open  # start, print the URL only
"""
import argparse

from network_monitor.app import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Stability Monitor")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't open a browser automatically; just print the local URL.")
    args = parser.parse_args()
    serve(open_browser=not args.no_open)


if __name__ == "__main__":
    main()
