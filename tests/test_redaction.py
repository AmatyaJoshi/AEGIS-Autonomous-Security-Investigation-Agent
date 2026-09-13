from __future__ import annotations

from aegis.security.redaction import Pseudonymizer


def test_reversible_mapping() -> None:
    p = Pseudonymizer()
    text = "Host WS01 user adm.patel from 10.10.20.31 emailed bob@corp.local"
    red = p.redact_text(text, hosts=["WS01"], users=["adm.patel"])
    assert "WS01" not in red
    assert "adm.patel" not in red
    assert "10.10.20.31" not in red
    assert "bob@corp.local" not in red
    assert p.restore(red) == text


def test_stable_aliases() -> None:
    p = Pseudonymizer()
    a = p.redact_text("WS01 and WS01 again", hosts=["WS01"])
    assert a.count("HOST-1") == 2
    assert "HOST-2" not in a


def test_hashes_and_commands_untouched() -> None:
    p = Pseudonymizer()
    text = "procdump -ma lsass.exe SHA256=deadbeef"
    assert p.redact_text(text, hosts=[], users=[]) == text
