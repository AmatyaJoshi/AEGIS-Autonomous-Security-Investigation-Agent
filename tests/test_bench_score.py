from __future__ import annotations

from bench.run_bench import Prediction
from bench.score import _fp_suppression, _macro_f1, score_arm


def _p(gold: str, pred: str, score: float, fp_type: str | None = None) -> Prediction:
    return Prediction(
        alert_id="a",
        gold_label=gold,
        gold_techniques=[],
        fp_type=fp_type,
        split="test",
        pred_label=pred,
        malicious_score=score,
        confidence=score,
    )


def test_fp_suppression_at_2pct_missed() -> None:
    # 10 TPs high, 10 FPs low -> threshold below the lowest TP suppresses all FPs.
    preds = [_p("true_positive", "true_positive", 0.9) for _ in range(10)]
    preds += [_p("false_positive", "false_positive", 0.1) for _ in range(10)]
    supp, _thr, missed, roc = _fp_suppression(preds)
    assert supp == 1.0
    assert missed <= 0.02
    assert roc


def test_fp_suppression_penalised_by_low_scoring_tp() -> None:
    # One TP scores as low as the FPs -> to keep missed-TP <=2% the threshold must sit below it,
    # so not all FPs can be suppressed.
    preds = [_p("true_positive", "true_positive", 0.9) for _ in range(48)]
    preds += [_p("true_positive", "false_positive", 0.05) for _ in range(2)]
    preds += [_p("false_positive", "false_positive", 0.1) for _ in range(50)]
    supp, _thr, missed, _ = _fp_suppression(preds)
    assert missed <= 0.02
    assert supp < 1.0  # the one low TP caps suppression


def test_macro_f1_perfect() -> None:
    conf = {
        "true_positive": {"true_positive": 5, "false_positive": 0, "escalate": 0},
        "false_positive": {"true_positive": 0, "false_positive": 5, "escalate": 0},
        "escalate": {"true_positive": 0, "false_positive": 0, "escalate": 5},
    }
    assert _macro_f1(conf) == 1.0


def test_score_arm_shape() -> None:
    preds = [_p("true_positive", "true_positive", 0.8) for _ in range(5)]
    preds += [_p("false_positive", "false_positive", 0.1, fp_type="dev_procdump") for _ in range(5)]
    preds.append(_p("escalate", "escalate", 0.5))
    s = score_arm("aegis_full", preds)
    assert 0.0 <= s.accuracy <= 1.0
    assert s.confusion["true_positive"]["true_positive"] == 5
    assert "dev_procdump" in s.per_fp_type_suppression
    assert s.citation_rate == 1.0
