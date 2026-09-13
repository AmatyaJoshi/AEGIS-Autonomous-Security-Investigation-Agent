"""Lens bridge (SPEC §10): OpenTelemetry export + locally-computable Lens-style eval metrics."""

from aegis.lens.metrics import LensMetrics, evaluate_investigation

__all__ = ["LensMetrics", "evaluate_investigation"]
