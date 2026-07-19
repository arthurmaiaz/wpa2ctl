
import re
import shutil
import subprocess
import logging

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
OPTIONAL_TOOLS = ["hashcat", "hcxpcapngtool"]


def list_wireless_interfaces() -> list[str]:
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        logger.error("`iw` not found. Install it with: sudo apt install iw")
        return []
    except subprocess.CalledProcessError as e:
        logger.error("Failed to list interfaces: %s", e.stderr)
        return []

    interfaces = re.findall(r"Interface\s+(\S+)", result.stdout)
    logger.info("Found wireless interfaces: %s", interfaces)
    return interfaces


def enable_monitor_mode(interface: str) -> str:

    logger.info("Killing conflicting processes (airmon-ng check kill)...")
    try:
        subprocess.run(
            ["airmon-ng", "check", "kill"],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        # Not fatal - some setups don't have conflicting processes running
        logger.warning("airmon-ng check kill returned a warning: %s", e.stderr)
    except FileNotFoundError:
        raise RuntimeError("airmon-ng not found. Is the aircrack-ng suite installed?")

    logger.info("Starting monitor mode on %s...", interface)
    try:
        result = subprocess.run(
            ["airmon-ng", "start", interface],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to start monitor mode: {e.stderr}")


    match = re.search(r"monitor mode.*?enabled.*?\[?(\w*mon\w*)\]?", result.stdout, re.IGNORECASE)
    if match:
        monitor_interface = match.group(1)
    else:

        monitor_interface = f"{interface}mon"
        logger.warning(
            "Could not parse the monitor interface name from airmon-ng output; "
            "assuming '%s'. Verify with `iw dev`.", monitor_interface
        )

    logger.info("Monitor mode enabled: %s", monitor_interface)
    return monitor_interface


def disable_monitor_mode(monitor_interface: str) -> None:

    logger.info("Disabling monitor mode on %s...", monitor_interface)
    try:
        subprocess.run(
            ["airmon-ng", "stop", monitor_interface],
            capture_output=True, text=True, check=True,
        )
        logger.info("Monitor mode disabled.")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to disable monitor mode cleanly: %s", e.stderr)
    except FileNotFoundError:
        logger.error("airmon-ng not found.")


def check_dependencies() -> bool:

    missing_required = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    missing_optional = [t for t in OPTIONAL_TOOLS if shutil.which(t) is None]

    if missing_optional:
        logger.warning(
            "Optional tools not found (some features will be unavailable): %s",
            missing_optional,
        )

    if missing_required:
        logger.error("Missing required tools: %s", missing_required)
        logger.error("Install the aircrack-ng suite: sudo apt install aircrack-ng")
        return False

    logger.info("All required dependencies are installed.")
    return True