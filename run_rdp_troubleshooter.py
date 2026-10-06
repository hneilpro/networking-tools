#!/usr/bin/env python3
"""Start the Remote Desktop Connection Troubleshooter.

Opens a local web page in your browser. Nothing is sent anywhere;
all checks run from this PC to the target PC you pick.

Usage:
    python run_rdp_troubleshooter.py            # start + open browser
    python run_rdp_troubleshooter.py --no-open  # start, print the URL only
"""
import argparse

from rdp_troubleshooter.app import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Remote Desktop Connection Troubleshooter")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't open a browser automatically; just print the local URL.")
    args = parser.parse_args()
    serve(open_browser=not args.no_open)


if __name__ == "__main__":
    main()
