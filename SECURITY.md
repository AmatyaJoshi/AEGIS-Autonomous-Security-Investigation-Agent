# SECURITY.md

## Guardrails (SPEC §9, enforced in code)

1. **Recommend-only.** No tool mutates any system. The query validator and the offline SIEM adapter
   reject every mutating or multi-statement query; there is no bypass flag.
2. **Separate credentials.** Agent tools use a read-only SIEM key; only `lab/` loaders hold a writer key.
3. **Injection guard.** Every attacker-influenceable field is scanned; flagged content is redacted and
   forces `escalate`. Tool output is wrapped in `<data>` envelopes that prompts treat as data.
4. **Evidence or silence.** Reports with uncited claims are rejected by the post-processor.
5. **Redaction.** The PII pseudonymiser runs before any external LLM call.
6. **Audit trail.** Every verdict stores hypotheses, queries, evidence ids, model and prompt versions.

## Outbound traffic

Every host the process may contact is in `OUTBOUND_ALLOWLIST` (`aegis/llm/budget.py`) and in
`COST.md`. The list is logged at startup and any other host fails closed before a socket opens.
LLM calls default to a local Ollama; the Groq and Gemini free tiers are opt-in by key; paid providers
are refused unless `AEGIS_ALLOW_PAID_PROVIDERS=1` is set explicitly.

## Evorozen Neural Pulse boundary

AEGIS uses Evorozen Neural Pulse as **case memory and analytics, not as the reasoner**. The LangGraph
pipeline, hypotheses, evidence and verdicts are produced locally and are unchanged by Pulse. Pulse
stores what AEGIS learned and feeds priors back into `triage_pre`.

**Pulse receives metadata only.** Each case record contains: a salted hash of the tenant id, ATT&CK
technique ids, the alert source name, input severity, verdict, confidence, escalation flag, the triage
model probability, reasoner kind, model name, prompt versions, counts of hypotheses / queries /
evidence, duration and cost. Analyst feedback records contain the case id, the analyst verdict, an
agreed flag and a reason code. **Never sent:** raw log events, hostnames, usernames, IP addresses,
alert titles or text, command lines, or report bodies. The record builder
(`aegis/memory/store.py::CaseRecord`) has no access to those fields and `tests/test_memory.py`
asserts that nothing identifying survives serialisation. Hostnames and usernames that must appear in
prompts to an external LLM go through the pseudonymiser first (`aegis/security/redaction.py`).

If Pulse is unreachable or `AEGIS_PULSE_API_KEY` is unset, the same interface writes to a local SQLite
table and the review UI shows **memory: local**. Pulse calls are capped per day
(`BUDGET_PULSE_CALLS_PER_DAY`, default 40); reads are cached for ten minutes and the analytics answer
for a day. AEGIS never deletes memory rows and the client does not expose `delete_data`.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Do not include live log data in reports.
