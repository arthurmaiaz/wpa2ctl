"""
main.py
Main CLI for wpa2ctl — orchestrates the full pipeline:
interface -> scanner -> capture -> cracker -> report
"""

import argparse
import logging
import sys

# from interface import enable_monitor_mode, disable_monitor_mode, check_dependencies
# from scanner import scan_networks, display_networks
# from capture import confirm_authorization, start_capture, send_deauth, wait_for_handshake
# from cracker import convert_to_hashcat_format, crack_with_aircrack, crack_with_hashcat
# from report import build_report, save_json, save_html

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wpa2ctl")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="wpa2ctl - WPA2 audit orchestrator (scan, capture, crack, report)"
    )
    parser.add_argument("--interface", required=True, help="Wireless interface to use (e.g. wlan0)")
    parser.add_argument("--scan-time", type=int, default=20, help="Scan duration in seconds")
    parser.add_argument("--wordlist", required=True, help="Path to the wordlist used for cracking")
    parser.add_argument("--output", default="report.json", help="Path to the output report file")
    parser.add_argument("--engine", choices=["aircrack", "hashcat"], default="aircrack", help="Cracking engine")
    parser.add_argument("--handshake-timeout", type=int, default=120, help="Handshake capture timeout (s)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # TODO: 1. check_dependencies()
    # TODO: 2. monitor_interface = enable_monitor_mode(args.interface)
    # TODO: 3. networks = scan_networks(monitor_interface, args.scan_time); display_networks(networks)
    # TODO: 4. user selects target network (input) -> confirm_authorization(bssid, essid)
    # TODO: 5. cap_file = start_capture(...); wait_for_handshake(cap_file, args.handshake_timeout)
    # TODO: 6. convert format if engine == hashcat
    # TODO: 7. result = crack_with_aircrack(...) or crack_with_hashcat(...)
    # TODO: 8. report = build_report(...); save_json(report, args.output)
    # TODO: 9. cleanup: disable_monitor_mode(monitor_interface)

    logger.info("Pipeline not yet implemented — fill in the modules under src/.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Running cleanup...")
        # TODO: ensure disable_monitor_mode() runs even on interruption
        sys.exit(1)
