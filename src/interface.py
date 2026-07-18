"""
interface.py
Manages monitor mode for the wireless network interface.
"""

import subprocess
import logging

logger = logging.getLogger(__name__)


def list_wireless_interfaces() -> list[str]:
    """
    Lists the wireless network interfaces available on the system.
    Uses `iw dev` or `ip link` to identify wlan-type interfaces.
    """
    # TODO: run `iw dev`, parse the output, and return interface names
    raise NotImplementedError


def enable_monitor_mode(interface: str) -> str:
    """
    Enables monitor mode on the given interface.

    Steps:
      1. Run `airmon-ng check kill` to kill conflicting processes
      2. Run `airmon-ng start <interface>`
      3. Confirm that the new monitor-mode interface was created (e.g. wlan0mon)

    Returns the name of the new monitor-mode interface.
    """
    # TODO: implement using subprocess.run, capturing stdout/stderr
    raise NotImplementedError


def disable_monitor_mode(monitor_interface: str) -> None:
    """
    Reverts the interface back to managed (normal) mode, cleaning up the environment.
    Should always be called during final cleanup (including on errors).
    """
    # TODO: run `airmon-ng stop <monitor_interface>`
    raise NotImplementedError


def check_dependencies() -> bool:
    """
    Checks whether the required tools are installed:
    airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, hashcat (optional).
    """
    # TODO: use shutil.which() for each required binary
    raise NotImplementedError
