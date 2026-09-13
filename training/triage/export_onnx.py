"""Export the trained triage model to ONNX int8 for <30 ms CPU inference (SPEC §7.1).

* LightGBM  -> ONNX via ``onnxmltools`` / ``skl2onnx`` (the default fast-path model).
* DeBERTa   -> ONNX via ``optimum`` with dynamic int8 quantisation.

Both write ``model.onnx`` + ``meta.json`` next to the source model and print a p95 latency estimate.
Optional dependencies are imported lazily so the core package never requires them.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from aegis.models.triage import CLASSES, FEATURE_ORDER


def export_lightgbm(model_path: Path) -> dict[str, Any]:  # pragma: no cover - optional deps
    import lightgbm as lgb
    import numpy as np
    import onnxmltools
    from onnxconverter_common.data_types import FloatTensorType

    booster = lgb.Booster(model_file=str(model_path))
    onnx_model = onnxmltools.convert_lightgbm(
        booster, initial_types=[("input", FloatTensorType([None, len(FEATURE_ORDER)]))]
    )
    out = model_path.with_name("model.onnx")
    onnxmltools.utils.save_model(onnx_model, str(out))

    import onnxruntime as ort

    sess = ort.InferenceSession(str(out), providers=["CPUExecutionProvider"])
    x = np.zeros((1, len(FEATURE_ORDER)), dtype=np.float32)
    lat = []
    for _ in range(200):
        t0 = time.perf_counter()
        sess.run(None, {"input": x})
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()
    meta = {
        "features": FEATURE_ORDER,
        "classes": CLASSES,
        "model": "lightgbm-onnx",
        "p95_ms": round(lat[int(len(lat) * 0.95)], 3),
    }
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return {"onnx": str(out), "p95_ms": meta["p95_ms"]}


def export_deberta(model_dir: Path) -> dict[str, Any]:  # pragma: no cover - optional deps
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig

    model = ORTModelForSequenceClassification.from_pretrained(str(model_dir), export=True)
    model.save_pretrained(str(model_dir))
    quantizer = ORTQuantizer.from_pretrained(str(model_dir))
    qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False)
    quantizer.quantize(save_dir=str(model_dir), quantization_config=qconfig)
    return {"onnx_int8": str(model_dir)}


if __name__ == "__main__":  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="training/triage/artifacts/model.txt")
    ap.add_argument("--kind", choices=["lightgbm", "deberta"], default="lightgbm")
    args = ap.parse_args()
    if args.kind == "lightgbm":
        print(json.dumps(export_lightgbm(Path(args.model)), indent=1))
    else:
        print(json.dumps(export_deberta(Path(args.model)), indent=1))
