"""LoRA SFT of Qwen2.5-Coder for NL->ES|QL/SPL generation (SPEC §7.2).

Trains a LoRA adapter (r=16, alpha=32, all linear layers) on the Sigma + investigative-intent
pairs with ``trl``'s ``SFTTrainer``. Requires ``torch``/``transformers``/``peft``/``trl`` and a GPU;
imports are lazy so the core package never depends on them. Held-out Sigma categories stay in the
test split and are never trained on.

    python -m training.query_gen.train_lora --base Qwen/Qwen2.5-Coder-1.5B-Instruct
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from training.query_gen.build_pairs import load_pairs

OUT = Path("training") / "query_gen" / "artifacts"

SYSTEM = (
    "You translate a natural-language investigative intent into a single valid SIEM query. "
    "Output only the query. Dialect: {dialect}."
)


def _format(pair: Any) -> dict[str, str]:
    user = f"[{pair.dialect}] {pair.nl}"
    return {"prompt": SYSTEM.format(dialect=pair.dialect) + "\n\n" + user, "completion": pair.query}


def train(
    base_model: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct", out_dir: Path = OUT, epochs: int = 3
) -> dict[str, Any]:  # pragma: no cover - needs GPU
    import torch
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    from datasets import Dataset

    pairs = [p for p in load_pairs() if p.split == "train"]
    ds = Dataset.from_list([_format(p) for p in pairs])
    tok = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForCausalLM.from_pretrained(
        base_model, torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32
    )
    peft_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
    )
    args = SFTConfig(
        output_dir=str(out_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=8,
        gradient_accumulation_steps=2,
        learning_rate=2e-4,
        bf16=torch.cuda.is_available(),
        max_length=2048,
        logging_steps=25,
        save_strategy="epoch",
        seed=1337,
    )
    trainer = SFTTrainer(
        model=model, args=args, train_dataset=ds, peft_config=peft_config, processing_class=tok
    )
    trainer.train()
    trainer.save_model(str(out_dir))
    (out_dir / "meta.json").write_text(
        json.dumps({"base": base_model, "n_train": len(pairs), "lora_r": 16}), encoding="utf-8"
    )
    return {"adapter": str(out_dir), "n_train": len(pairs)}


if __name__ == "__main__":  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    ap.add_argument("--epochs", type=int, default=3)
    args = ap.parse_args()
    print(json.dumps(train(args.base, epochs=args.epochs), indent=1))
