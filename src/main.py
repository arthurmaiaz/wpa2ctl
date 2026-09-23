import argparse
import logging
import sys
import time
from dataclasses import asdict

from interface import enable_monitor_mode, disable_monitor_mode, check_dependencies
from scanner import scan_networks, display_networks
from capture import confirm_authorization, start_capture, wait_for_handshake
from cracker import convert_to_hashcat_format, crack_with_aircrack, crack_with_hashcat
from report import build_report, save_json, save_html

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


def select_target(networks):
    print("\n" + "=" * 40)
    print(" SELECIONE O ALVO ")
    print("=" * 40)
    for idx, net in enumerate(networks):
        print(f"[{idx}] BSSID: {net.bssid} | ESSID: {net.essid} | CH: {net.channel}")

    raw = input("\nDigite o índice da rede alvo: ").strip()
    if not raw.isdigit():
        logger.error("Seleção inválida: '%s' não é um número.", raw)
        return None

    choice = int(raw)
    if choice < 0 or choice >= len(networks):
        logger.error("Seleção inválida: índice %d fora do intervalo (0-%d).", choice, len(networks) - 1)
        return None

    return networks[choice]


def main() -> None:
    args = parse_args()
    monitor_interface = None

    try:
        if not check_dependencies():
            logger.error("Dependências obrigatórias não encontradas. Abortando.")
            sys.exit(1)

        monitor_interface = enable_monitor_mode(args.interface)
        logger.info("Interface %s pronta para operação.", monitor_interface)

        logger.info("Iniciando scan de redes por %s segundos...", args.scan_time)
        scan_start = time.time()
        networks = scan_networks(monitor_interface, args.scan_time)
        scan_duration_s = time.time() - scan_start
        display_networks(networks)

        if not networks:
            logger.warning("Nenhuma rede encontrada. Encerrando.")
            return

        target = select_target(networks)
        if target is None:
            return

        if not confirm_authorization(target.bssid, target.essid):
            logger.warning("Autorização negada pelo usuário. Abortando.")
            return

        cap_prefix = f"capture_{target.bssid.replace(':', '_')}"
        logger.info("Iniciando captura para %s... Aguardando handshake.", cap_prefix)

        capture_start = time.time()
      
        cap_file = start_capture(monitor_interface, target.bssid, target.channel, cap_prefix)

        handshake_captured = wait_for_handshake(cap_file, args.handshake_timeout)
        capture_duration_s = time.time() - capture_start

        if not handshake_captured:
            logger.error("Handshake não capturado dentro do tempo limite.")
            report = build_report(
                target_essid=target.essid,
                target_bssid=target.bssid,
                scan_duration_s=scan_duration_s,
                capture_duration_s=capture_duration_s,
                crack_duration_s=0.0,
                handshake_captured=False,
                password_found=False,
                password=None,
                attempts_per_second=None,
            )
            save_json(report, args.output)
            save_html(report, args.output.replace(".json", ".html"))
            logger.info("Relatório parcial gerado em %s", args.output)
            return

        crack_start = time.time()
        if args.engine == "hashcat":
            logger.info("Convertendo formato para hashcat (.hc22000)...")
            hc_file = convert_to_hashcat_format(cap_file, cap_file.replace(".cap", ".hc22000"))
            logger.info("Iniciando cracking com hashcat...")
            crack_result = crack_with_hashcat(hc_file, args.wordlist)
        else:
            logger.info("Iniciando cracking com aircrack-ng...")
            crack_result = crack_with_aircrack(cap_file, args.wordlist, target.bssid)
        crack_duration_s = time.time() - crack_start

        report = build_report(
            target_essid=target.essid,
            target_bssid=target.bssid,
            scan_duration_s=scan_duration_s,
            capture_duration_s=capture_duration_s,
            crack_duration_s=crack_duration_s,
            handshake_captured=True,
            password_found=crack_result["success"],
            password=crack_result["password"],
            attempts_per_second=crack_result.get("attempts_per_second"),
        )
        save_json(report, args.output)
        save_html(report, args.output.replace(".json", ".html"))

        logger.info("Relatório gerado com sucesso em %s", args.output)
        if crack_result["success"]:
            logger.info("SENHA ENCONTRADA: %s", crack_result["password"])
        else:
            logger.warning("Senha não encontrada na wordlist fornecida.")

    except Exception:
        logger.exception("Ocorreu um erro crítico durante a execução.")

    finally:
        if monitor_interface:
            logger.info("Limpando ambiente e desativando modo monitor...")
            disable_monitor_mode(monitor_interface)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\nInterrompido pelo usuário. Iniciando limpeza de emergência...")
        sys.exit(1)