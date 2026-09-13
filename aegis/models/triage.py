"""Triage classifier inference wrapper + feature serialisation (SPEC §7.1).

``serialize_features`` renders an alert + context into the fixed feature template used by both
the text model (DeBERTa) and the tree model (LightGBM). The graph's fast-path calls a loaded model's
``score``; when no model is trained/available the graph simply skips the fast-path (``deps.triage``
is None), so this module is import-safe with zero ML dependencies.

Two loadable backends (both optional, produced by ``training/triage``):
* ``LightGBMTriage`` - loads a LightGBM booster + feature list; CPU, fast.
* ``OnnxTriage`` - loads an ONNX DeBERTa sequence classifier; int8, <30 ms CPU target.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.graph.state import ContextBundle
from aegis.schema.ocsf import DetectionFinding

SEVERITY_ORD = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "unknown": 0}
CRIT_ORD = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CREDENTIAL_ACCESS = {"T1003", "T1555", "T1552", "T1558", "T1110"}
DESTRUCTIVE = {"T1486", "T1490", "T1489", "T1491", "T1485"}


def serialize_features(alert: DetectionFinding, context: ContextBundle) -> dict[str, Any]:
    """Fixed feature template (SPEC §7.1): numeric features plus a text serialisation."""
    proc = alert.actor.process if alert.actor and alert.actor.process else None
    cmd = (proc.cmd_line if proc else None) or ""
    parents = proc.parent_process.name if proc and proc.parent_process else None
    techniques = set(alert.technique_ids)
    parent_techs = {t.split(".")[0] for t in techniques}
    numeric = {
        "severity": SEVERITY_ORD.get(str(alert.severity_id.name).lower(), 0),
        "asset_criticality": CRIT_ORD.get(context.asset.criticality, 0),
        "asset_known": int(context.asset.known),
        "identity_privileged": int(context.identity.privileged),
        "identity_service_account": int(context.identity.service_account),
        "identity_known": int(context.identity.known),
        "ti_max_score": max((h.score for h in context.ti_hits), default=0.0),
        "ti_malicious": int(any(h.verdict == "malicious" for h in context.ti_hits)),
        "n_ti_hits": len(context.ti_hits),
        "off_hours": int(context.off_hours),
        "recent_alert_count": context.recent_alert_count,
        "n_observables": len(alert.observables),
        "n_techniques": len(techniques),
        "cred_access": int(bool(parent_techs & {t.split(".")[0] for t in CREDENTIAL_ACCESS})),
        "destructive": int(bool(parent_techs & DESTRUCTIVE)),
        "cmd_len": len(cmd),
        "cmd_has_encoded": int("-enc" in cmd.lower() or "frombase64" in cmd.lower()),
        "cmd_has_lsass": int("lsass" in cmd.lower() or "ntds" in cmd.lower()),
        "n_sigma_rematch": len(context.sigma_rematch),
    }
    text = (
        f"rule: {alert.finding_info.title}\n"
        f"severity: {alert.severity}\n"
        f"techniques: {', '.join(sorted(techniques)) or 'none'}\n"
        f"host: {', '.join(alert.hostnames()) or 'unknown'} "
        f"(criticality {context.asset.criticality}, role {context.asset.role})\n"
        f"user: {', '.join(alert.user_names()) or 'unknown'} "
        f"(privileged {context.identity.privileged}, service {context.identity.service_account}, "
        f"known {context.identity.known})\n"
        f"process: {proc.name if proc else 'none'} parent {parents}\n"
        f"command_line: {cmd[:400]}\n"
        f"ti: {'; '.join(f'{h.observable}={h.verdict}' for h in context.ti_hits) or 'none'}\n"
        f"off_hours: {context.off_hours}\n"
        f"sigma_rematch: {len(context.sigma_rematch)}"
    )
    return {"numeric": numeric, "text": text}


FEATURE_ORDER = [
    "severity",
    "asset_criticality",
    "asset_known",
    "identity_privileged",
    "identity_service_account",
    "identity_known",
    "ti_max_score",
    "ti_malicious",
    "n_ti_hits",
    "off_hours",
    "recent_alert_count",
    "n_observables",
    "n_techniques",
    "cred_access",
    "destructive",
    "cmd_len",
    "cmd_has_encoded",
    "cmd_has_lsass",
    "n_sigma_rematch",
]

CLASSES = ["false_positive", "true_positive", "escalate"]


class LightGBMTriage:
    name = "lightgbm_triage"

    def __init__(self, model_path: Path) -> None:
        import lightgbm as lgb

        meta = json.loads((model_path.with_suffix(".meta.json")).read_text(encoding="utf-8"))
        self.features: list[str] = meta["features"]
        self.classes: list[str] = meta["classes"]
        self.booster = lgb.Booster(model_file=str(model_path))

    def score(self, features: dict[str, Any]) -> dict[str, float]:
        num = features["numeric"]
        row = [[float(num.get(f, 0)) for f in self.features]]
        probs = self.booster.predict(row)[0]
        return _normalise_scores(dict(zip(self.classes, probs, strict=True)))


class OnnxTriage:  # pragma: no cover - requires onnxruntime + tokenizer
    name = "onnx_triage"

    def __init__(self, model_dir: Path) -> None:
        import onnxruntime as ort
        from transformers import AutoTokenizer

        self.tok = AutoTokenizer.from_pretrained(str(model_dir))
        self.sess = ort.InferenceSession(
            str(model_dir / "model.onnx"), providers=["CPUExecutionProvider"]
        )
        meta = json.loads((model_dir / "meta.json").read_text(encoding="utf-8"))
        self.classes = meta["classes"]

    def score(self, features: dict[str, Any]) -> dict[str, float]:
        import numpy as np

        enc = self.tok(features["text"], truncation=True, max_length=1024, return_tensors="np")
        logits = self.sess.run(None, {k: v for k, v in enc.items()})[0][0]
        exp = np.exp(logits - logits.max())
        probs = exp / exp.sum()
        return _normalise_scores(dict(zip(self.classes, probs.tolist(), strict=True)))


def _normalise_scores(class_probs: dict[str, float]) -> dict[str, float]:
    return {
        "p_fp": float(class_probs.get("false_positive", 0.0)),
        "p_tp": float(class_probs.get("true_positive", 0.0)),
        "p_escalate": float(class_probs.get("escalate", 0.0)),
    }


def load_triage(model_path: str | Path) -> Any:
    p = Path(model_path)
    if p.suffix == ".txt" or (p.with_suffix(".meta.json")).exists():
        return LightGBMTriage(p)
    return OnnxTriage(p)
