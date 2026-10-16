"""Optional Google analytics & Pub/Sub events; no raw URL, chat message or credentials are uploaded."""
import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def emit(report: dict):
    parts = report.get("links", []) + report.get("uploads", []) if report.get("kind") == "check" else [report]
    row = {"ts": datetime.now(timezone.utc).isoformat(), "scan_id": report["id"],
           "url_hash": report["url_hash"], "risk_level": report["level"], "risk_score": report["score"],
           "sandbox_status": next((p["sandbox"]["status"] for p in parts), "not_used"),
           "webrisk_checked": any(p["web_risk"]["checked"] for p in parts),
           "flag_count": sum(len(p["signals"]) for p in parts) + len(report.get("message_signals", [])), "elapsed_ms": report["elapsed_ms"]}
    table = os.getenv("BQ_SCAN_TABLE", "")
    if table:
        try:
            from google.cloud import bigquery
            errors = bigquery.Client().insert_rows_json(table, [row])
            if errors: log.warning("BigQuery insert rejected")
        except Exception: log.exception("BigQuery telemetry failed")
    topic = os.getenv("PUBSUB_TOPIC", "")
    if topic:
        try:
            from google.cloud import pubsub_v1
            pubsub_v1.PublisherClient().publish(topic, json.dumps(row).encode(), event_type="scan_completed").result(timeout=5)
        except Exception: log.exception("Pub/Sub telemetry failed")
