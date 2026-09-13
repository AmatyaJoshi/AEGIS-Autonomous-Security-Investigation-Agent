from __future__ import annotations

from lab.emulation.ground_truth import label_events
from lab.noise.generators import FP_TYPES, Org, generate
from lab.security_words import assert_no_offensive_content


def test_generate_is_deterministic() -> None:
    a = list(generate(seed=7, days=3, episodes_per_day=5))
    b = list(generate(seed=7, days=3, episodes_per_day=5))
    assert [w.window_id for _, w in a] == [w.window_id for _, w in b]
    assert [e.event_id for evs, _ in a for e in evs] == [e.event_id for evs, _ in b for e in evs]


def test_every_fp_type_reachable() -> None:
    seen = {w.fp_type for _, w in generate(seed=1, days=30, episodes_per_day=12)}
    assert seen == set(FP_TYPES)


def test_noise_events_labelled_fp_by_their_window() -> None:
    for events, window in generate(seed=3, days=2, episodes_per_day=6):
        matched = [w for _e, w in label_events(events, [window]) if w is not None]
        assert matched, f"episode {window.window_id} produced no in-window events"
        assert all(w.label == "fp" for w in matched)


def test_generated_telemetry_has_no_offensive_content() -> None:
    for events, _w in generate(seed=11, days=30, episodes_per_day=12):
        for e in events:
            assert_no_offensive_content(
                e.process_command_line or "",
                e.process_parent_command_line or "",
                e.script_block_text or "",
            )


def test_org_consistency() -> None:
    org = Org()
    assert org.host("DC01")["criticality"] == "critical"
    assert {u["name"] for u in org.users_by(role="sysadmin")} >= {"adm.patel", "adm.wu"}
