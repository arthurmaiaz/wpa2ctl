"""
capture.py
Captures the WPA2 handshake for a target network, with authorization
confirmation and automatic success detection.
"""

import logging
import time

logger = logging.getLogger(__name__)


def confirm_authorization(bssid: str, essid: str) -> bool:
    """
    Requires explicit user confirmation before starting any capture.
    Suggestion: ask the user to re-type the BSSID as confirmation,
    to avoid accidental "yes" clicks.
    """
    # TODO: implement confirmation prompt
    raise NotImplementedError


def start_capture(monitor_interface: str, bssid: str, channel: str, output_prefix: str) -> str:
    """
    Starts a targeted capture with airodump-ng, filtered by BSSID and channel.

    Reference command:
      airodump-ng --bssid <bssid> --channel <channel> --write <output_prefix> <monitor_interface>

    Returns the path to the .cap file being generated.
    """
    # TODO: implement using subprocess.Popen (background process)
    raise NotImplementedError


def send_deauth(monitor_interface: str, bssid: str, client_mac: str | None = None, count: int = 5) -> None:
    """
    Sends deauthentication packets to force a reconnection and speed up
    handshake capture. ONLY use on your own/authorized networks —
    see legal_notice.md.

    Reference command:
      aireplay-ng --deauth <count> -a <bssid> [-c <client_mac>] <monitor_interface>
    """
    # TODO: implement
    raise NotImplementedError


def wait_for_handshake(cap_file: str, timeout: int = 120, check_interval: int = 5) -> bool:
    """
    Periodically monitors the .cap file to check whether the handshake
    has been captured.

    Strategy:
      - every `check_interval` seconds, run `aircrack-ng <cap_file>` and check
        whether the output contains "WPA handshake" for the target BSSID
      - return True as soon as detected, False if the timeout is reached
    """
    # TODO: implement checking loop
    raise NotImplementedError
