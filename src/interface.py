import re
import subprocess
import time
import logging
import shutil
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ["iw", "rfkill", "airodump-ng", "aireplay-ng", "aircrack-ng", "iwconfig"]
OPTIONAL_TOOLS = ["hashcat", "hcxpcapngtool", "sed", "awk"]

SUBPROCESS_TIMEOUT = 15
COOLDOWN_DELAY = 2

def list_wireless_interfaces() -> List[str]:
    interfaces = []
    cmd = ["iw", "dev"]
    result = _run_subprocess(cmd, capture_output=True, text=True, timeout=5)

    if result.returncode != 0:
        logger.error("Falha ao listar interfaces: %s", result.stderr)
        return interfaces

    pattern = re.compile(r"Interface\s+(\w+)(?!\s*(eth|lo|docker|wlan\d+wds))")
    interfaces = re.findall(pattern, result.stdout)
    logger.info("Interfaces wireless detectadas: %s", interfaces)
    return interfaces

def enable_monitor_mode(interface: str, retries: int = 2) -> str:
    if not interface or not isinstance(interface, str):
        raise ValueError("interface é obrigatório e deve ser string")

    _rfkill_unblock()

    for attempt in range(retries):
        logger.info("Tentativa %s/%s: ativando modo monitor em %s", attempt+1, retries, interface)

        _kill_conflicting_processes()

        cmd = ["iw", "interface", "set", "type", "monitor"]
        _run_subprocess(cmd, timeout=8, cwd=None)

        monitor_iface = _detect_monitor_interface(interface)
        if monitor_iface:
            logger.info("Modo monitor ativado: %s", monitor_iface)
            return monitor_iface

        if attempt < retries - 1:
            time.sleep(COOLDOWN_DELAY)
            continue

    monitor_iface = f"{interface}mon"
    logger.warning("Fallback: assumindo monitor interface = %s", monitor_iface)
    return monitor_iface

def disable_monitor_mode(monitor_interface: str) -> None:
    if not monitor_interface:
        logger.error("interface vazio: nada a desabilitar")
        return

    cmd = ["iw", "interface", "set", "type", "managed"]
    _run_subprocess(cmd, timeout=5)

    logger.info("Modo monitor desativado em %s", monitor_interface)

def check_dependencies() -> bool:
    missing_required = []
    missing_optional = []

    for tool in REQUIRED_TOOLS:
        if not _which(tool):
            missing_required.append(tool)

    for tool in OPTIONAL_TOOLS:
        if not _which(tool):
            missing_optional.append(tool)

    if missing_required:
        logger.error("Ferramentas obrigatórias ausentes: %s", missing_required)
        logger.error("Instale pacote aircrack-ng: sudo apt update && sudo apt install -y aircrack-ng")
        return False

    if missing_optional:
        msg = "Ferramentas opcionais ausentes (algumas features desabilitadas): %s"
        logger.warning(msg, missing_optional)

    logger.info("Dependências validadas.")
    return True

def _run_subprocess(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT,
                capture_output: bool = True, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=False
    )
    if result.returncode != 0:
        logger.error("Comando falhou (%s): %s\nstderr: %s",
                    result.returncode, " ".join(cmd), result.stderr)
    return result

def _which(tool: str) -> bool:
    found = shutil.which(tool) is not None
    if not found:
        logger.debug("Ferramenta não encontrada no PATH: %s", tool)
    return found

def _rfkill_unblock() -> None:
    cmd = ["rfkill", "unblock", "all"]
    _run_subprocess(cmd, timeout=3)

def _kill_conflicting_processes() -> None:
    for proc in ["NetworkManager", "wpa_supplicant", "dhclient"]:
        cmd = ["pkill", "-9", proc]
        _run_subprocess(cmd, timeout=3, cwd=None)

def _detect_monitor_interface(base_iface: str) -> Optional[str]:
    cmd = ["iw", base_iface, "info"]
    result = _run_subprocess(cmd, timeout=5)

    if result.returncode != 0:
        logger.error("Falha ao detectar interface monitor em %s", base_iface)
        return None

    match = re.search(r"type\s+Monitor\s+channel\s+(\d+)", result.stdout, re.IGNORECASE)
    if not match:
        logger.error("Interface %s não está no modo monitor", base_iface)
        return None

    return base_iface
