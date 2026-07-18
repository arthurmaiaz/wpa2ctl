"""
report.py
Generates the final audit report (JSON and/or HTML).
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime

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
    password: str | None
    attempts_per_second: float | None
    timestamp: str


def build_report(**kwargs) -> AuditReport:
    """
    Builds the report object from the data collected at each stage
    of the pipeline (scan, capture, crack).
    """
    kwargs.setdefault("timestamp", datetime.now().isoformat())
    return AuditReport(**kwargs)


def save_json(report: AuditReport, output_path: str) -> None:
    """
    Saves the report in JSON format.
    """
    # TODO: use json.dump(asdict(report), ...)
    raise NotImplementedError


def save_html(report: AuditReport, output_path: str) -> None:
    """
    Generates a simple, readable HTML version of the report,
    useful for screenshots/GIFs in the project README.
    """
    # TODO: build basic HTML (a template string works fine)
    raise NotImplementedError
