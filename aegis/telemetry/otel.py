"""OpenTelemetry bootstrap (SPEC §10). Phase 0 ships a no-op-safe initialiser.

If ``opentelemetry-sdk`` is installed and ``AEGIS_OTLP_ENDPOINT`` is set, spans export via OTLP to
Lens; otherwise ``tracer()`` returns a no-op tracer so the rest of the code can be instrumented now
without a hard dependency. The full span attribute contract (investigation/alert/node ids, cost,
prompt versions) is wired in Phase 3 when the graph exists.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger(__name__)
_TRACER: Any | None = None


def init_telemetry(service_name: str = "aegis") -> None:
    global _TRACER
    endpoint = os.environ.get("AEGIS_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.info("opentelemetry not installed; telemetry disabled")
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _TRACER = trace.get_tracer(service_name)
    log.info("telemetry -> %s", endpoint)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as s:
        for k, v in attributes.items():
            s.set_attribute(k, v)
        yield s
