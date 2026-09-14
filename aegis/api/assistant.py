"""AEGIS Copilot — an offline, knowledge-grounded assistant for SOC analysts (SPEC §9).

The assistant is deterministic and runs with zero external calls: answers are grounded in the
in-repo knowledge (ATT&CK KB, response playbooks, guardrails and product guidance) and always cite
their source. It is *advisory only* — consistent with the §9 guardrails it never proposes to
execute containment, mutate systems, or emit offensive content; requests to do so are declined with
an explanation. When an LLM key is present the router could enrich phrasing, but the grounded
responder is always the source of truth so the console works fully offline.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator

from aegis.api.auth import current_user

router = APIRouter(prefix="/api/assistant")

# Phrases that would breach the recommend-only / no-offensive guardrails (§9).
_BLOCKED = re.compile(
    r"\b(execute|run|deploy|isolate|quarantine|block|disable|delete|kill|shutdown|"
    r"contain|remediate|exploit|payload|malware|ransomware|c2|reverse shell|"
    r"bypass|disable the guard|ignore (the )?guardrail)\b",
    re.IGNORECASE,
)

STARTERS: list[str] = [
    "How does an AEGIS investigation work end to end?",
    "What are the guardrails and what can the agent not do?",
    "Explain MITRE technique T1003 and how AEGIS detects it",
    "What playbook applies to a confirmed credential-dumping incident?",
    "How do I search logs for a suspicious host?",
    "How is a verdict decided and how confident is it?",
]


class AskIn(BaseModel):
    question: str

    @field_validator("question")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("question must not be empty")
        return v[:1000]


class Citation(BaseModel):
    source: str
    ref: str


class AskOut(BaseModel):
    intent: str
    answer: str
    citations: list[Citation]
    suggestions: list[str]
    guardrail_notice: str | None = None


# --------------------------------------------------------------------------- knowledge helpers
def _techniques_in(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)))


def _explain_technique(tids: list[str], question: str) -> tuple[str, list[Citation]]:
    from aegis.attack.kb import load_kb

    kb = load_kb()
    lines: list[str] = []
    cites: list[Citation] = []
    ids = tids
    if not ids:  # no explicit id — search the KB by description
        hits = kb.search(question, k=3)
        ids = [t.id for t, _ in hits]
    for tid in ids[:4]:
        t = kb.get(tid.upper())
        if not t:
            continue
        tactics = ", ".join(t.tactic_names) or "—"
        lines.append(
            f"**{t.id} · {t.name}**\n\n"
            f"Tactics: {tactics}. AEGIS maps alerts to this technique during the *enrich* step "
            f"using the Sigma pack and the ATT&CK KB, then the *reason* step weighs it against the "
            f"collected evidence before proposing a verdict."
        )
        cites.append(Citation(source="MITRE ATT&CK KB", ref=t.id))
    if not lines:
        return ("I couldn't match that to a technique in the ATT&CK KB.", cites)
    return ("\n\n".join(lines), cites)


def _playbook_guidance(question: str) -> tuple[str, list[Citation]]:
    from aegis.api.soc import _load_playbooks

    pbs = _load_playbooks()
    tids = _techniques_in(question)
    picked: list[dict[str, Any]] = []
    if tids:
        for pb in pbs:
            if set(t.upper() for t in pb.get("techniques", [])) & set(t.upper() for t in tids):
                picked.append(pb)
    if not picked:
        picked = pbs[:3]
    lines = [
        "AEGIS recommends response playbooks — it never executes them. A human approves "
        "every step before any action is taken.\n"
    ]
    cites: list[Citation] = []
    for pb in picked[:3]:
        steps = pb.get("steps", [])
        approvals = sum(1 for s in steps if s.get("requires_approval"))
        lines.append(
            f"**{pb.get('name')}** ({pb.get('id')}) — {len(steps)} recommended steps, "
            f"{approvals} require explicit analyst approval."
        )
        cites.append(Citation(source="Playbook", ref=str(pb.get("id"))))
    return ("\n\n".join(lines), cites)


_GUARDRAILS = (
    "AEGIS operates under inviolable guardrails (SPEC §9):\n\n"
    "- **Recommend-only.** It never executes containment or mutates any system. It proposes "
    "actions; a human analyst approves and performs them.\n"
    "- **Read-only SIEM.** Every generated query is validated before execution and credentials are "
    "read-only.\n"
    "- **No offensive content.** It will not produce exploits, malware, or attack payloads.\n"
    "- **Evidence-cited.** Every verdict cites the events and techniques it rests on.\n"
    "- **Injection-guarded.** Untrusted alert text cannot redirect the agent's instructions.\n"
    "- **Human-in-the-loop.** Analysts review, approve, or override every verdict."
)

_HOW_IT_WORKS = (
    "An AEGIS investigation runs as a LangGraph pipeline:\n\n"
    "1. **Triage** — a fast model scores the alert so obvious noise is fast-pathed.\n"
    "2. **Plan** — the agent forms hypotheses from the alert and ATT&CK context.\n"
    "3. **Enrich / Query** — it generates *validated, read-only* SIEM queries and pulls evidence.\n"
    "4. **Reason** — it weighs evidence against each hypothesis and maps MITRE techniques.\n"
    "5. **Verdict** — true-positive / false-positive / escalate, with a confidence score.\n"
    "6. **Report** — an evidence-cited report and a *recommended* (never executed) playbook.\n\n"
    "Everything is offline-capable and every step is captured in the audit trail for review."
)

_LOG_HELP = (
    "Use the **Logs** page to search the read-only DuckDB snapshot. You can filter by host, user, "
    "process, or free text and pivot on the facets shown. To trace a suspicious host, search its "
    "name, then narrow by time and technique. Queries are validated before they run — there is no "
    "bypass, and nothing is ever written back to the source."
)

_VERDICT_HELP = (
    "A verdict is one of **true_positive**, **false_positive**, or **escalate**. It is produced "
    "by the *reason* step from the evidence gathered, and carries a **confidence** score. "
    "Low-confidence or high-severity cases are routed to the review queue for a human decision. "
    "Analysts can approve or override, and overrides become labels that improve the models."
)


def _respond(question: str) -> AskOut:
    q = question.lower()
    notice: str | None = None
    if _BLOCKED.search(question):
        notice = (
            "I can explain and recommend, but I can't help execute containment, mutate systems, or "
            "produce offensive content — AEGIS is recommend-only with a human in the loop (§9). "
            "Here's the relevant guidance instead."
        )

    tids = _techniques_in(question)
    if tids or any(w in q for w in ("technique", "mitre", "att&ck", "attack tactic", "tactic")):
        ans, cites = _explain_technique(tids, question)
        intent = "technique"
    elif any(
        w in q for w in ("playbook", "respond", "response", "contain", "incident", "remediat")
    ):
        ans, cites = _playbook_guidance(question)
        intent = "response"
    elif any(
        w in q for w in ("guardrail", "cannot", "can't", "not do", "safe", "allowed", "policy")
    ):
        ans, cites, intent = (
            _GUARDRAILS,
            [Citation(source="SPEC", ref="§9 Guardrails")],
            "guardrails",
        )
    elif any(
        w in q for w in ("how does", "workflow", "pipeline", "end to end", "work end", "steps")
    ):
        ans, cites, intent = (
            _HOW_IT_WORKS,
            [Citation(source="SPEC", ref="§2 Architecture")],
            "how-it-works",
        )
    elif any(w in q for w in ("log", "search", "hunt", "query", "siem")):
        ans, cites, intent = _LOG_HELP, [Citation(source="Console", ref="Logs")], "logs"
    elif any(
        w in q
        for w in ("verdict", "confidence", "decide", "score", "true positive", "false positive")
    ):
        ans, cites, intent = _VERDICT_HELP, [Citation(source="SPEC", ref="§3 Verdicts")], "verdict"
    else:
        ans = (
            "I'm the AEGIS Copilot. I can explain how investigations run, walk through MITRE "
            "techniques, point you to the right response playbook, clarify the guardrails, and "
            "help you search logs — all grounded in this deployment's own knowledge. Try one of "
            "the suggestions below."
        )
        cites, intent = [Citation(source="AEGIS", ref="Copilot")], "overview"

    return AskOut(
        intent=intent,
        answer=ans,
        citations=cites,
        suggestions=[s for s in STARTERS if s.lower() != q][:4],
        guardrail_notice=notice,
    )


@router.get("/suggestions")
def suggestions(_: dict[str, Any] = Depends(current_user)) -> dict[str, list[str]]:
    return {"starters": STARTERS}


@router.post("/ask", response_model=AskOut)
def ask(body: AskIn, _: dict[str, Any] = Depends(current_user)) -> AskOut:
    return _respond(body.question)
