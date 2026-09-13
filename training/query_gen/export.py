"""Serve the fine-tuned NL->query LoRA and plug it into the tool (SPEC §7.2 serving).

``FineTunedQueryGenerator`` loads the Qwen2.5-Coder LoRA (merged or adapter) via vLLM if present,
else transformers, and exposes ``generate(spec, dialect) -> query`` so the ``QueryGenerator`` front
door in :mod:`aegis.models.query_gen` can use it (falling back to the template builder on any error,
and always validating). Set ``AEGIS_QUERYGEN_MODEL=<path>`` to enable it in the live tool.

vLLM serving with grammar-constrained decoding for ES|QL is optional and gated behind availability;
the interface is identical whether served locally or in-process.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aegis.models.query_gen import Dialect, QueryGenerator, QuerySpec, TemplateQueryBuilder


class FineTunedQueryGenerator:  # pragma: no cover - requires the trained model
    def __init__(self, model_path: str | Path, use_vllm: bool = True) -> None:
        self.model_path = str(model_path)
        self.builder = TemplateQueryBuilder()
        self.backend = "template"
        self._llm: Any = None
        try:
            if use_vllm:
                from vllm import LLM  # type: ignore[import-not-found]

                self._llm = LLM(model=self.model_path, dtype="bfloat16", max_model_len=2048)
                self.backend = "vllm"
        except Exception:
            self._llm = None
        if self._llm is None:
            try:
                from transformers import AutoModelForCausalLM, AutoTokenizer

                self._tok = AutoTokenizer.from_pretrained(self.model_path)
                self._hf = AutoModelForCausalLM.from_pretrained(self.model_path)
                self.backend = "transformers"
            except Exception:
                self._hf = None

    def generate(self, spec: QuerySpec, dialect: Dialect) -> str:
        prompt = (
            f"You translate a natural-language investigative intent into a single valid SIEM "
            f"query. Output only the query. Dialect: {dialect}.\n\n[{dialect}] {spec.intent}"
        )
        try:
            if self.backend == "vllm" and self._llm is not None:
                from vllm import SamplingParams  # type: ignore[import-not-found]

                out = self._llm.generate([prompt], SamplingParams(temperature=0.0, max_tokens=256))
                return out[0].outputs[0].text.strip()
            if self.backend == "transformers" and self._hf is not None:
                inputs = self._tok(prompt, return_tensors="pt")
                gen = self._hf.generate(**inputs, max_new_tokens=256, do_sample=False)
                text = self._tok.decode(
                    gen[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
                )
                return text.strip()
        except Exception:
            pass
        # Guaranteed fallback so the tool never emits an empty/invalid query.
        return self.builder.build(spec, dialect)


def make_generator(known_hosts: set[str] | None = None) -> QueryGenerator:
    """Build the QueryGenerator, wiring the fine-tuned model if AEGIS_QUERYGEN_MODEL is set."""
    model_path = os.environ.get("AEGIS_QUERYGEN_MODEL")
    model = (
        FineTunedQueryGenerator(model_path) if model_path and Path(model_path).exists() else None
    )
    return QueryGenerator(model=model, known_hosts=known_hosts)
