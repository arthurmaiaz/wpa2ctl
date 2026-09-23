import logging
import os
import re
import shutil
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)

HASHCAT_MODE_WPA = "22000"

_UNIT_MULTIPLIERS = {
    "h/s": 1,
    "kh/s": 1e3,
    "mh/s": 1e6,
    "gh/s": 1e9,
    "th/s": 1e12,
}


def convert_to_hashcat_format(cap_file: str, output_file: str) -> str:

    if not os.path.isfile(cap_file):
        raise FileNotFoundError(f"Arquivo de captura não encontrado: {cap_file}")

    if shutil.which("hcxpcapngtool") is None:
        raise RuntimeError(
            "hcxpcapngtool não encontrado no PATH. Instale com: sudo apt install hcxtools"
        )

    cmd = ["hcxpcapngtool", "-o", output_file, cap_file]
    logger.info("Convertendo %s para formato hashcat...", cap_file)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if result.stdout:
        logger.debug(result.stdout)
    if result.returncode != 0:
        logger.error("hcxpcapngtool falhou (%s): %s", result.returncode, result.stderr.strip())
        raise RuntimeError(f"Falha na conversão: {result.stderr.strip() or 'erro desconhecido'}")

    if not os.path.isfile(output_file) or os.path.getsize(output_file) == 0:
        raise RuntimeError(
            "Nenhum hash WPA foi extraído. O handshake provavelmente está incompleto "
            "ou o arquivo de captura não contém um handshake válido."
        )

    logger.info("Hash convertido salvo em: %s", output_file)
    return output_file


def crack_with_aircrack(cap_file: str, wordlist_path: str, bssid: str) -> dict:

    if not os.path.isfile(cap_file):
        raise FileNotFoundError(f"Arquivo de captura não encontrado: {cap_file}")
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist não encontrada: {wordlist_path}")
    if shutil.which("aircrack-ng") is None:
        raise RuntimeError("aircrack-ng não encontrado no PATH.")

    cmd = ["aircrack-ng", cap_file, "-w", wordlist_path, "-b", bssid]
    logger.info("Iniciando aircrack-ng contra %s usando %s...", bssid, wordlist_path)

    key_re = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
    tested_re = re.compile(r"([\d,]+)\s+keys tested")

    password: Optional[str] = None
    keys_tested: Optional[int] = None
    start = time.time()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL, 
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        logger.debug(line)

        m = key_re.search(line)
        if m:
            password = m.group(1)

        m = tested_re.search(line)
        if m:
            keys_tested = int(m.group(1).replace(",", ""))

    proc.wait()
    duration_s = time.time() - start

    success = password is not None
    attempts_per_second = (
        keys_tested / duration_s if keys_tested and duration_s > 0 else None
    )

    if success:
        logger.info("Senha encontrada em %.1fs: %s", duration_s, password)
    else:
        logger.warning(
            "Senha não encontrada na wordlist (aircrack-ng retornou código %s).",
            proc.returncode,
        )

    return {
        "success": success,
        "password": password,
        "duration_s": duration_s,
        "attempts_per_second": attempts_per_second,
        "keys_tested": keys_tested,
    }


def _parse_hashcat_speed(line: str) -> Optional[float]:
    m = re.search(r"Speed\.#\d+\.*:\s+([\d.,]+)\s*([kKMGT]?H/s)", line)
    if not m:
        return None
    value = float(m.group(1).replace(",", ""))
    multiplier = _UNIT_MULTIPLIERS.get(m.group(2).lower(), 1)
    return value * multiplier


def crack_with_hashcat(hc22000_file: str, wordlist_path: str) -> dict:

    if not os.path.isfile(hc22000_file):
        raise FileNotFoundError(f"Arquivo de hash não encontrado: {hc22000_file}")
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist não encontrada: {wordlist_path}")
    if shutil.which("hashcat") is None:
        raise RuntimeError("hashcat não encontrado no PATH.")

    cmd = [
        "hashcat",
        "-m", HASHCAT_MODE_WPA,
        hc22000_file,
        wordlist_path,
        "--status",
        "--status-timer=5",
    ]
    logger.info("Iniciando hashcat (modo %s) usando %s...", HASHCAT_MODE_WPA, wordlist_path)

    last_speed: Optional[float] = None
    start = time.time()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        logger.debug(line)

        speed = _parse_hashcat_speed(line)
        if speed is not None:
            last_speed = speed

    proc.wait()
    duration_s = time.time() - start


    password: Optional[str] = None
    success = False
    show_cmd = ["hashcat", "-m", HASHCAT_MODE_WPA, hc22000_file, "--show"]
    show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30, check=False)
    if show_result.stdout.strip():
        last_line = show_result.stdout.strip().splitlines()[-1]
        password = last_line.split(":")[-1]
        success = True

    if success:
        logger.info("Senha encontrada em %.1fs: %s", duration_s, password)
    else:
        logger.warning(
            "Senha não encontrada na wordlist (hashcat retornou código %s).",
            proc.returncode,
        )

    return {
        "success": success,
        "password": password,
        "duration_s": duration_s,
        "attempts_per_second": last_speed,
    }