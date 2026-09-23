import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AuditReport:
    target_essid: str
    target_bssid: str
    scan_duration_s: float
    capture_duration_s: float
    crack_duration_s: float
    handshake_captured: bool
    password_found: bool
    password: Optional[str]
    attempts_per_second: Optional[float]
    timestamp: str


def build_report(**kwargs) -> AuditReport:
    if "timestamp" not in kwargs:
        kwargs["timestamp"] = datetime.now().isoformat()

    try:
        return AuditReport(**kwargs)
    except TypeError as e:
        logger.error("Erro ao construir relatório: argumentos inválidos. %s", e)
        raise


def save_json(report: AuditReport, output_path: str) -> None:
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=4, ensure_ascii=False)
        logger.info("Relatório JSON salvo em: %s", output_path)
    except OSError as e:
        logger.error("Falha ao salvar JSON: %s", e)


def save_html(report: AuditReport, output_path: str) -> None:
    data = asdict(report)

    status_color = "#2ecc71" if data["password_found"] else "#e74c3c"
    status_text = "SUCESSO" if data["password_found"] else "FALHA"
    password_display = data["password"] if data["password"] else "Não encontrada"
    attempts_display = (
        f"{data['attempts_per_second']:.0f}/s"
        if data["attempts_per_second"] is not None
        else "N/D"
    )

    html_template = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Relatório de Auditoria WPA2 - {data['target_essid']}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#111; color:#eee; margin:0; padding:2rem; }}
  .card {{ max-width: 680px; margin: 0 auto; background:#1b1b1b; border-radius:12px; padding:2rem; }}
  h1 {{ font-size:1.4rem; margin-top:0; }}
  .status {{ display:inline-block; padding:.3rem .8rem; border-radius:6px; font-weight:bold; background:{status_color}; color:#111; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1.5rem; }}
  td {{ padding:.5rem .3rem; border-bottom:1px solid #333; }}
  td:first-child {{ color:#999; width:45%; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Relatório de Auditoria WPA2</h1>
    <span class="status">{status_text}</span>
    <table>
      <tr><td>ESSID</td><td>{data['target_essid']}</td></tr>
      <tr><td>BSSID</td><td>{data['target_bssid']}</td></tr>
      <tr><td>Handshake capturado</td><td>{"Sim" if data['handshake_captured'] else "Não"}</td></tr>
      <tr><td>Senha</td><td>{password_display}</td></tr>
      <tr><td>Tentativas/s</td><td>{attempts_display}</td></tr>
      <tr><td>Tempo de scan</td><td>{data['scan_duration_s']:.1f}s</td></tr>
      <tr><td>Tempo de captura</td><td>{data['capture_duration_s']:.1f}s</td></tr>
      <tr><td>Tempo de crack</td><td>{data['crack_duration_s']:.1f}s</td></tr>
      <tr><td>Gerado em</td><td>{data['timestamp']}</td></tr>
    </table>
  </div>
</body>
</html>
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        logger.info("Relatório HTML salvo em: %s", output_path)
    except OSError as e:
        logger.error("Falha ao salvar HTML: %s", e)