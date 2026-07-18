"""
cracker.py
Converts the captured handshake and attempts to crack the password
using a wordlist.
"""

import logging

logger = logging.getLogger(__name__)


def convert_to_hashcat_format(cap_file: str, output_file: str) -> str:
    """
    Converts the .cap file to the .hc22000 format used by hashcat (mode 22000).

    Reference command:
      hcxpcapngtool -o <output_file> <cap_file>
    """
    # TODO: implement
    raise NotImplementedError


def crack_with_aircrack(cap_file: str, wordlist_path: str, bssid: str) -> dict:
    """
    Attempts to crack the password using aircrack-ng.

    Reference command:
      aircrack-ng <cap_file> -w <wordlist_path> -b <bssid>

    Returns a dict with: success (bool), password (str|None),
    total time, attempts made (when available from the output).
    """
    # TODO: implement, parsing stdout in real time
    raise NotImplementedError


def crack_with_hashcat(hc22000_file: str, wordlist_path: str) -> dict:
    """
    Attempts to crack the password using hashcat (faster with GPU).

    Reference command:
      hashcat -m 22000 <hc22000_file> <wordlist_path>

    Returns a dict with: success (bool), password (str|None),
    total time, attempts/second (parsed from hashcat's output).
    """
    # TODO: implement, parsing hashcat's real-time progress
    raise NotImplementedError
