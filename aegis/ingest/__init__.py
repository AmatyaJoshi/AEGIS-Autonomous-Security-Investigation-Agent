"""Alert ingestion (SPEC Phase 2): OCSF DetectionFindings from sources plus ground-truth labels."""

from aegis.ingest.generate import AlertRecord, generate_alerts

__all__ = ["AlertRecord", "generate_alerts"]
