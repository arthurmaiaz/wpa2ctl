import csv
import glob
import logging
import os
import signal
import subprocess
import tempfile
import time

from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NetworkInfo:
    bssid: str
    channel: str
    signal: str
    encryption: str
    essid: str


def scan_networks(monitor_interface: str, scan_time: int = 20) -> list[NetworkInfo]:

    if os.geteuid() != 0:
        raise PermissionError("This scan requires root privileges (airodump-ng needs raw socket access).")

    tmpdir = tempfile.mkdtemp(prefix="wifi_scan_")
    prefix = os.path.join(tmpdir, "scan_temp")

    cmd = [
        "airodump-ng",
        "--write", prefix,
        "--output-format", "csv",
        monitor_interface,
    ]

    logger.info("Starting airodump-ng on %s for %ss", monitor_interface, scan_time)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    try:
        time.sleep(scan_time)
    finally:
        # airodump-ng expects SIGINT/SIGTERM to flush its CSV cleanly.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()

    candidates = sorted(glob.glob(f"{prefix}-*.csv"))
    if not candidates:
        raise FileNotFoundError(
            f"No CSV output found for prefix '{prefix}'. "
            f"Check that '{monitor_interface}' is a valid monitor-mode interface."
        )
    csv_path = candidates[-1]

    try:
        return parse_airodump_csv(csv_path)
    finally:
        for f in glob.glob(f"{prefix}-*"):
            try:
                os.remove(f)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def parse_airodump_csv(csv_path: str) -> list[NetworkInfo]:
   
    networks: list[NetworkInfo] = []

    with open(csv_path, "r", encoding="latin-1", newline="") as f:
        reader = csv.reader(f, skipinitialspace=True)

        header_found = False
        for row in reader:
            if not row or all(not cell.strip() for cell in row):
                if header_found:
                    break
                continue

            if row[0].strip() == "BSSID":
                header_found = True
                continue

            if not header_found:
                continue

      
            if len(row) < 14:
                logger.debug("Skipping malformed row: %r", row)
                continue

            bssid = row[0].strip()
            channel = row[3].strip()
            privacy = row[5].strip()
            cipher = row[6].strip()
            auth = row[7].strip()
            power = row[8].strip()
            essid = row[13].strip() or "<hidden>"

            encryption_parts = [p for p in (privacy, cipher, auth) if p and p != "OPN"]
            encryption = " ".join(encryption_parts) if encryption_parts else "OPEN"

            networks.append(
                NetworkInfo(
                    bssid=bssid,
                    channel=channel,
                    signal=power,
                    encryption=encryption,
                    essid=essid,
                )
            )

    return networks


def display_networks(networks: list[NetworkInfo]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()

    if not networks:
        console.print("[yellow]No networks found.[/yellow]")
        return

    table = Table(title="Redes WiFi encontradas", show_lines=False)
    table.add_column("ESSID", style="cyan", overflow="fold")
    table.add_column("BSSID", style="dim")
    table.add_column("Canal", justify="right")
    table.add_column("Sinal (dBm)", justify="right")
    table.add_column("Segurança", style="magenta")

    def signal_key(n: NetworkInfo) -> int:
        try:
            return -int(n.signal)
        except ValueError:
            return 0

    for net in sorted(networks, key=signal_key):
        color = "green" if net.encryption == "OPEN" else "white"
        table.add_row(
            net.essid,
            net.bssid,
            net.channel,
            net.signal,
            f"[{color}]{net.encryption}[/{color}]",
        )

    console.print(table)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scanner de redes WiFi próximas")
    parser.add_argument("interface", help="Interface em modo monitor (ex: wlan0mon)")
    parser.add_argument("-t", "--time", type=int, default=20, help="Tempo de varredura em segundos")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    nets = scan_networks(args.interface, args.time)
    display_networks(nets)