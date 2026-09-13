"""Train the triage classifier (SPEC §7.1).

Default model: LightGBM multiclass (false_positive / true_positive / escalate) on the engineered
numeric features, class-weighted, CPU. Trains on the train split, early-stops on val. Saves the
booster (``model.txt``) + ``model.meta.json`` (feature order, classes) for the inference wrapper in
:mod:`aegis.models.triage`.

A DeBERTa text classifier is provided as an optional alternative (``--model deberta``) when
``transformers``/``torch`` are installed; it trains on the serialised text and exports to ONNX via
``export_onnx.py``. LightGBM is the default because it trains in seconds on CPU and integrates the
same day.

    python -m training.triage.train                 # LightGBM
    python -m training.triage.train --model deberta # optional, needs a GPU
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.models.triage import CLASSES, FEATURE_ORDER
from training.triage.build_dataset import load_dataset

OUT = Path("training") / "triage" / "artifacts"


def _xy(rows: list[dict[str, Any]], split: str) -> tuple[list[list[float]], list[int]]:
    sel = [r for r in rows if r["split"] == split]
    x = [[float(r["numeric"].get(f, 0)) for f in FEATURE_ORDER] for r in sel]
    y = [CLASSES.index(r["label"]) for r in sel]
    return x, y


def train_lightgbm(data_dir: Path, out_dir: Path = OUT) -> dict[str, Any]:
    import lightgbm as lgb
    import numpy as np

    rows = load_dataset(data_dir)
    x_tr, y_tr = _xy(rows, "train")
    x_val, y_val = _xy(rows, "val")
    # class weights inversely proportional to frequency
    counts = np.bincount(y_tr, minlength=len(CLASSES)).astype(float)
    weights = {i: float(len(y_tr) / (len(CLASSES) * max(1.0, c))) for i, c in enumerate(counts)}
    w_tr = [weights[y] for y in y_tr]
    dtrain = lgb.Dataset(
        np.array(x_tr), label=np.array(y_tr), weight=np.array(w_tr), feature_name=FEATURE_ORDER
    )
    dval = lgb.Dataset(np.array(x_val), label=np.array(y_val), reference=dtrain)
    params = {
        "objective": "multiclass",
        "num_class": len(CLASSES),
        "metric": "multi_logloss",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "min_data_in_leaf": 5,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "verbose": -1,
        "seed": 1337,
    }
    booster = lgb.train(
        params,
        dtrain,
        num_boost_round=400,
        valid_sets=[dval],
        callbacks=[lgb.early_stopping(40, verbose=False), lgb.log_evaluation(0)],
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "model.txt"
    booster.save_model(str(model_path))
    meta = {
        "features": FEATURE_ORDER,
        "classes": CLASSES,
        "model": "lightgbm",
        "best_iteration": booster.best_iteration,
        "feature_importance": dict(
            zip(FEATURE_ORDER, [int(v) for v in booster.feature_importance()], strict=True)
        ),
    }
    (model_path.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return {
        "model_path": str(model_path),
        "best_iteration": booster.best_iteration,
        "n_train": len(y_tr),
        "n_val": len(y_val),
        "top_features": sorted(meta["feature_importance"].items(), key=lambda kv: -kv[1])[:8],
    }


def train_lightgbm_trees(data_dir: Path, out_dir: Path = OUT) -> dict[str, Any]:
    """LightGBM gradient-boosted trees on engineered features - the SPEC §7.1 alternative."""
    return train_lightgbm(data_dir, out_dir)


def train_deberta(data_dir: Path, out_dir: Path = OUT) -> dict[str, Any]:  # pragma: no cover
    """Optional DeBERTa sequence classifier on the serialised text (needs transformers + a GPU)."""
    import numpy as np
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    from datasets import Dataset

    rows = load_dataset(data_dir)
    model_name = "microsoft/deberta-v3-base"
    tok = AutoTokenizer.from_pretrained(model_name)

    def mk(split: str) -> Dataset:
        sel = [r for r in rows if r["split"] == split]
        return Dataset.from_dict(
            {"text": [r["text"] for r in sel], "label": [CLASSES.index(r["label"]) for r in sel]}
        )

    def tokenize(batch: dict[str, Any]) -> dict[str, Any]:
        return tok(batch["text"], truncation=True, max_length=1024)

    train_ds = mk("train").map(tokenize, batched=True)
    val_ds = mk("val").map(tokenize, batched=True)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=len(CLASSES))
    args = TrainingArguments(
        output_dir=str(out_dir / "deberta"),
        num_train_epochs=4,
        per_device_train_batch_size=8,
        learning_rate=2e-5,
        bf16=torch.cuda.is_available(),
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        logging_steps=20,
        seed=1337,
    )
    trainer = Trainer(model=model, args=args, train_dataset=train_ds, eval_dataset=val_ds)
    trainer.train()
    model.save_pretrained(str(out_dir / "deberta"))
    tok.save_pretrained(str(out_dir / "deberta"))
    (out_dir / "deberta" / "meta.json").write_text(
        json.dumps({"classes": CLASSES, "model": model_name}), encoding="utf-8"
    )
    _ = np
    return {"model_path": str(out_dir / "deberta")}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["lightgbm", "deberta"], default="lightgbm")
    ap.add_argument("--data", default="training/triage/data")
    args = ap.parse_args()
    if args.model == "lightgbm":
        print(json.dumps(train_lightgbm(Path(args.data)), indent=1))
    else:
        print(json.dumps(train_deberta(Path(args.data)), indent=1))
