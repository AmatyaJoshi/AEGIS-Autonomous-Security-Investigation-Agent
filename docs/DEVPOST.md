# AEGIS — the SOC analyst that cites every claim

**Track:** Autonomous B2B SaaS · **Evorozen Apex 2026**

## Description

Security operations centres are drowning. A mid-size SOC sees thousands of alerts a day; most are
false positives, each needs the same 20-minute Tier-1 investigation, and analysts burn out closing
tickets that never mattered. Vendors now bolt an LLM onto the queue, but a chatbot that *summarises* an
alert does not *investigate* it, and its confident prose cannot be audited.

AEGIS runs the Tier-1/Tier-2 department. For every alert it gathers context from logs, identity and
asset systems, enriches indicators with threat intelligence, forms competing hypotheses, runs scoped
read-only SIEM queries to confirm or refute each one, reconstructs the timeline, maps behaviour to
MITRE ATT&CK, decides **true positive / false positive / escalate** with a calibrated confidence and
writes an incident report in which **every factual sentence cites the exact log event it relies on**.
A post-processor rejects any report that does not. Response actions are recommended, never executed;
humans handle only escalations.

It learns. Every verdict and every analyst approve/override is remembered as metadata in **Evorozen
Neural Pulse**, and the learned priors per ATT&CK technique flow back into triage at weight n/(n+20).
The review UI shows the memory: TP-rate by technique, analyst-override rate, and a Pulse analytics
answer. If Pulse is unreachable the same interface runs locally and says so.

It is measured, not asserted. On a frozen 420-alert, ATT&CK-stratified benchmark AEGIS reaches 89%
verdict accuracy and 90% false-positive suppression at 0% missed true positives, against 45% for
rules-only and 52% for a single-shot reasoner; 100% of report claims are cited; a 75-variant
log-injection track is detected 100% with 0% verdict flips. Every number has a committed results file
and a command that regenerates it.

It costs $0 to run: local Ollama or free-tier Groq/Gemini for the reasoner, budget guards that degrade
to a deterministic reasoner instead of paying, an outbound allow-list, and a hosted demo on an
always-free VM.

## How the AI layer and the Pulse API are used

- **Reasoner** (LangGraph): hypothesise → evidence → verdict → report, every output schema-validated,
  prompts versioned, tool output in `<data>` envelopes, injection guard forces escalation.
- **Triage classifier** (LightGBM, CPU): p_tp / p_fp before the investigation; AUROC 1.00, ECE 0.002.
- **NL→SIEM query generator**: template generator offline (Qwen2.5-Coder LoRA with a GPU); every
  generated query must pass the read-only validator; evaluated by execution equivalence (100%).
- **Evorozen Neural Pulse** = case memory + analytics, not the reasoner. Tables `aegis_cases`,
  `aegis_feedback`, `aegis_priors`; one insert per case, one upsert per analyst decision, priors
  flushed once per batch, one cached `analytics` (chat) answer per day. **Metadata only, never log
  content** (SECURITY.md).

## Go-to-market

**Customers.** (1) MSSPs running Tier-1 for dozens of tenants, where per-analyst alert load is the
margin. (2) Mid-market SOCs (200–5,000 employees) with 2–8 analysts and a SIEM they already pay for.

**Pricing.** Platform fee per tenant per month plus a per-alert-investigated price with volume tiers.
A cited, auditable report per alert is the unit customers already budget in analyst minutes; AEGIS
prices below that minute cost and above raw compute. Escalations are free: the incentive is to close
false positives correctly, not to touch every alert.

**Channel.** SIEM marketplaces first (Elastic, Splunk): the alerts and the read-only credentials
already live there, so onboarding is a marketplace install plus a read-only API key. MSSP partners
second, as a white-label Tier-1 layer.

**Pilot offer.** 30 days, one tenant, read-only key, offline snapshot of the customer's own alerts for
week 1; success criterion agreed up front: false-positive suppression at ≤2% missed true positives,
measured the same way as our benchmark and reported with citations.

**Why now.** Alert volume grows faster than analyst headcount; LLM cost per token has fallen enough to
investigate every alert; regulators and insurers increasingly want auditable decisions, which
uncited AI summaries cannot give.

**Moat.** The cited-evidence discipline (post-processor, validator, guard) and the case memory that
compounds with every analyst decision, per tenant, without ever exporting their log data.

## Video script (3:00)

| Time | Scene | On screen |
|---|---|---|
| 0:00 | **Problem.** "A SOC sees thousands of alerts a day. Most are noise. The AI tools that summarise them can't be audited." | Queue of alerts; a vendor-style summary with no evidence. |
| 0:25 | **Live investigation.** `make demo` runs; five alerts land in the queue in seconds. Open the true positive: verdict, confidence, ATT&CK techniques, competing hypotheses with evidence for and against, timeline. Scroll the report: every sentence ends in `[E:<event_id>]`; click one to show the log event. | Terminal, then the investigation page, then the cited report. |
| 1:20 | **Review + escalation.** Open the ambiguous case: AEGIS escalated instead of guessing. Analyst approves; overrides become training labels. Point at the recommended playbook: "recommended, never executed". | Analyst action panel, approve click. |
| 1:40 | **Pulse memory.** Metrics › Case memory: TP-rate by technique, override rate, `priors source: pulse`, the analytics answer. Show the header badge and say what Pulse receives: metadata only. Show the prior on the next case's header. | Memory panel; SECURITY.md boundary paragraph. |
| 2:05 | **Benchmark.** The four-arm table: rules 45%, single-shot 52%, AEGIS 89%; FP-suppression 29% → 90% with the triage model; citations 100%; injection track 100% detected. "Every number has a file and a command." | RESULTS.md / report.html. |
| 2:30 | **GTM.** MSSPs and mid-market SOCs; per-alert pricing plus platform fee; SIEM marketplaces; 30-day pilot with a measured success criterion. Costs $0 to run today. | GTM slide. |
| 2:55 | **End.** "AEGIS: the SOC analyst that cites every claim." Repo link. | Title card. |

## Links

- Repository: https://github.com/AmatyaJoshi/AEGIS-Autonomous-Security-Investigation-Agent
- Results with regeneration commands: `RESULTS.md`, `bench/results/`
- Verification pass: `STATUS.md` · Cost ledger: `COST.md` · Security boundary: `SECURITY.md`
