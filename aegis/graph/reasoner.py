"""Reasoner: the analytic brain behind the LLM nodes (SPEC §3.2).

Two interchangeable implementations produce the same validated schema objects, so the graph nodes
are identical regardless of backend:

* ``HeuristicReasoner`` - a deterministic autonomous analyst. It forms competing hypotheses
  (always including a benign one), gathers corroborating/refuting evidence with scoped SIEM queries,
  and decides TP/FP/escalate from investigative signals (threat-intel verdicts, asset criticality,
  identity privilege, process ancestry legitimizers, off-hours, attack-chain corroboration). It uses
  no ground-truth labels - it investigates from evidence only - so the benchmark measures it fairly,
  and it is what runs offline / in CI.
* ``LLMReasoner`` - drives a frontier model through the versioned prompts, validating every response
  against the schemas in :mod:`aegis.llm.schemas` and running the citation post-processor.
  Used when an API key is configured.

The heuristic reasoner is a genuine investigator, not an oracle; its errors are exactly what the
benchmark's FP-suppression and escalation-precision metrics quantify.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Protocol

from aegis.attack.kb import load_kb
from aegis.graph.state import (
    ContextBundle,
    EvidenceRef,
    Hypothesis,
    TimelineEvent,
    Verdict,
)
from aegis.llm.schemas import (
    EvidenceAssessment,
    HypothesesOut,
    HypothesisOut,
    ReportOut,
    VerdictOut,
)
from aegis.schema.ocsf import DetectionFinding
from aegis.siem.base import SiemAdapter, TimeWindow
from aegis.tools.siem_query import siem_query

CREDENTIAL_ACCESS = {
    "T1003",
    "T1555",
    "T1552",
    "T1558",
    "T1110",
    "T1003.001",
    "T1003.002",
    "T1003.003",
}
DESTRUCTIVE = {"T1486", "T1490", "T1489", "T1491", "T1485", "T1561"}
LEGIT_AGENTS = {
    "ccmexec.exe",
    "veeamagent.exe",
    "msmpeng.exe",
    "psexesvc.exe",
    "wmiprvse.exe",
    "vssvc.exe",
    "services.exe",
    "svchost.exe",
}
DEV_TOOLS = {
    "procdump64.exe",
    "procdump.exe",
    "code.exe",
    "nc.exe",
    "git.exe",
    "bash.exe",
    "dotnet.exe",
    "node.exe",
}

# Offensive-tool / technique markers a human analyst would recognise in a rule title or command
# line. Presence strongly raises maliciousness regardless of the account.
OFFENSIVE_TITLE = (
    "hacktool",
    "malware",
    "mimikatz",
    "cobalt",
    "covenant",
    "rubeus",
    "powersploit",
    "bloodhound",
    "sharphound",
    "seatbelt",
    "lazagne",
    "impacket",
    "metasploit",
    "empire",
    "koadic",
    "sliver",
    "winpwn",
    "nishang",
    "kerberoast",
    "dcsync",
    "pass-the",
    "golden ticket",
    "shtinkering",
)
OFFENSIVE_CMD = (
    "sekurlsa",
    "lsadump",
    "mimikatz",
    "invoke-mimikatz",
    "comsvcs.dll minidump",
    "comsvcs minidump",
    "lsass.dmp",
    "lsass-",
    "-ma lsass",
    "procdump.*lsass",
    "ntds.dit",
    "ntdsutil",
    "vssadmin delete",
    "wbadmin delete",
    "bcdedit",
    "delete shadows",
    "delete catalog",
    "iex(",
    "iex (",
    "downloadstring",
    "downloadfile",
    "net.webclient",
    "-nop -w hidden",
    "-enc ",
    "-encodedcommand",
    "frombase64string",
    "add-mppreference",
    "set-mppreference -disable",
    "reg save hklm\\sam",
    "reg.exe save hklm\\sam",
    "rundll32 comsvcs",
)
# Benign administrative-tool markers that legitimise an alert when present.
BENIGN_CMD = (
    "ccmcache",
    "ccmexec",
    "veeam",
    "-job nightly",
    "vssadmin list shadows",
    "shadowcopy call create",
    "msiexec.exe /i",
    "/qn /norestart",
    "forfiles",
    "gpupdate /force",
    "get-aduser -filter",
    "export-csv",
    "get-stalecomputers",
    "ccmeval",
    "configuration manager health",
    "sc query",
    "net localgroup administrators",
)


class Reasoner(Protocol):
    name: str

    def hypothesize(self, alert: DetectionFinding, context: ContextBundle) -> HypothesesOut: ...

    def assess_evidence(
        self,
        hypothesis: Hypothesis,
        alert: DetectionFinding,
        context: ContextBundle,
        siem: SiemAdapter,
    ) -> tuple[EvidenceAssessment, list[EvidenceRef]]: ...

    def decide(
        self, alert: DetectionFinding, context: ContextBundle, hypotheses: list[Hypothesis]
    ) -> VerdictOut: ...

    def write_report(
        self,
        alert: DetectionFinding,
        context: ContextBundle,
        hypotheses: list[Hypothesis],
        timeline: list[TimelineEvent],
        verdict: Verdict,
    ) -> ReportOut: ...


@dataclass
class Signals:
    p_malicious: float
    reasons: list[str] = field(default_factory=list)
    benign_legitimizers: list[str] = field(default_factory=list)


class HeuristicReasoner:
    name = "heuristic"

    def __init__(self) -> None:
        self.kb = load_kb()

    # ------------------------------------------------------------------ hypotheses
    def hypothesize(self, alert: DetectionFinding, context: ContextBundle) -> HypothesesOut:
        techniques = alert.technique_ids
        host = (alert.hostnames() or ["unknown"])[0]
        user = (alert.user_names() or ["unknown"])[0]
        proc = alert.actor.process.name if alert.actor and alert.actor.process else None
        hyps: list[HypothesisOut] = []
        # Malicious hypothesis grounded in the alert's technique(s).
        tname = ", ".join(self._name(t) for t in techniques) or alert.finding_info.title
        hyps.append(
            HypothesisOut(
                statement=f"Malicious {tname} by {user} on {host}"
                + (f" via {proc}" if proc else ""),
                attack_techniques=techniques,
                prior=self._malicious_prior(alert, context),
                is_benign=False,
                queries_to_run=[
                    f"process activity for {user} on {host}",
                    f"network connections from {host}",
                ],
            )
        )
        # Mandatory benign explanation, tailored to the observed activity.
        benign = self._benign_hypothesis(alert, context, proc, user, host)
        hyps.append(benign)
        # If the asset is critical or TI is hot, add a lateral-movement/chain hypothesis.
        if context.asset.criticality in ("critical", "high") or context.ti_hits:
            hyps.append(
                HypothesisOut(
                    statement=f"Part of a broader intrusion chain touching {host}",
                    attack_techniques=techniques,
                    prior=0.3,
                    is_benign=False,
                    queries_to_run=[f"logons to {host}", f"process ancestry on {host}"],
                )
            )
        return HypothesesOut(hypotheses=hyps[:5])

    def _benign_hypothesis(
        self,
        alert: DetectionFinding,
        context: ContextBundle,
        proc: str | None,
        user: str,
        host: str,
    ) -> HypothesisOut:
        idn = context.identity
        if idn.service_account:
            stmt = f"Legitimate {idn.service or 'service'} activity by service account {user}"
        elif idn.privileged:
            stmt = f"Authorized administrative activity by {user} on {host}"
        elif proc and proc.lower() in DEV_TOOLS:
            stmt = f"Developer/IT use of {proc} on {host} for a legitimate task"
        else:
            stmt = f"Benign routine activity on {host} misclassified by the rule"
        return HypothesisOut(
            statement=stmt,
            attack_techniques=[],
            prior=0.4,
            is_benign=True,
            queries_to_run=[f"parent process for the {proc or 'process'} on {host}"],
        )

    def _malicious_prior(self, alert: DetectionFinding, context: ContextBundle) -> float:
        p = 0.3
        if any(h.verdict == "malicious" for h in context.ti_hits):
            p += 0.3
        if context.asset.criticality in ("critical", "high"):
            p += 0.1
        if any(t in DESTRUCTIVE or t in CREDENTIAL_ACCESS for t in alert.technique_ids):
            p += 0.1
        return min(0.9, p)

    # ------------------------------------------------------------------ evidence
    def assess_evidence(
        self,
        hypothesis: Hypothesis,
        alert: DetectionFinding,
        context: ContextBundle,
        siem: SiemAdapter,
    ) -> tuple[EvidenceAssessment, list[EvidenceRef]]:
        host = (alert.hostnames() or [""])[0]
        user = (alert.user_names() or [""])[0]
        window = TimeWindow(
            start=alert.time - timedelta(hours=1), end=alert.time + timedelta(hours=1)
        )
        refs: list[EvidenceRef] = []
        supporting: list[str] = []
        refuting: list[str] = []
        entities = [e for e in (host, user) if e]
        if not entities:
            return EvidenceAssessment(
                hypothesis_id=hypothesis.id,
                status="inconclusive",
                reasoning="no host/user to pivot on",
            ), refs
        res = siem_query("process activity on host", entities, window, siem=siem, limit=60)
        rows = res.data.get("rows", []) if res.error is None else []
        legit = self._find_legitimizers(rows, context)
        malicious = self._find_corroborators(rows, alert, context)
        for r in rows[:8]:
            refs.append(
                EvidenceRef(
                    event_id=str(r.get("event_id")), source="siem", summary=_summ(r), fields=r
                )
            )
        if hypothesis.is_benign:
            if legit:
                supporting = [ref.event_id for ref in refs[:3]]
                status = "supported"
                reasoning = "legitimizing context found: " + "; ".join(legit)
            elif malicious:
                refuting = [ref.event_id for ref in refs[:3]]
                status = "refuted"
                reasoning = "malicious corroboration overrides benign explanation: " + "; ".join(
                    malicious
                )
            else:
                status = "inconclusive"
                reasoning = "no strong legitimizer or corroborator found"
        else:
            if malicious or any(h.verdict == "malicious" for h in context.ti_hits):
                supporting = [ref.event_id for ref in refs[:3]]
                status = "supported"
                reasoning = "corroborating malicious indicators: " + "; ".join(
                    malicious
                    + [f"TI:{h.observable}" for h in context.ti_hits if h.verdict == "malicious"]
                )
            elif legit:
                refuting = [ref.event_id for ref in refs[:3]]
                status = "refuted"
                reasoning = "activity explained by legitimate context: " + "; ".join(legit)
            else:
                status = "inconclusive"
                reasoning = "insufficient corroboration to confirm malicious intent"
        assessment = EvidenceAssessment(
            hypothesis_id=hypothesis.id,
            status=status,
            supporting_event_ids=supporting,
            refuting_event_ids=refuting,
            reasoning=reasoning,
        )
        return assessment, refs

    def _find_legitimizers(self, rows: list[dict[str, Any]], context: ContextBundle) -> list[str]:
        found: list[str] = []
        # A legitimizer must be concrete: a management-agent parent or a benign admin command in the
        # activity. Being a service/dev account alone does not legitimise arbitrary work.
        for r in rows:
            parent = str(r.get("process_parent_name") or "").lower()
            if parent in ("ccmexec.exe", "veeamagent.exe", "psexesvc.exe", "wmiprvse.exe"):
                found.append(f"parent {parent} is a management agent")
                break
        for r in rows:
            cmd = str(r.get("process_command_line") or "").lower()
            if any(b in cmd for b in BENIGN_CMD):
                found.append("surrounding activity matches an administrative task")
                break
        for r in rows:
            path = str(r.get("file_path") or "").lower()
            if any(
                k in path
                for k in (
                    "ccmcache",
                    "\\veeam",
                    "detection-notes",
                    "\\projects\\infra-tools\\",
                    "-docs\\",
                )
            ):
                found.append("activity in a deployment/documentation path")
                break
        return list(dict.fromkeys(found))[:4]

    def _find_corroborators(
        self, rows: list[dict[str, Any]], alert: DetectionFinding, context: ContextBundle
    ) -> list[str]:
        found: list[str] = []
        if any(h.verdict == "malicious" for h in context.ti_hits):
            found.append("threat-intel flagged an observable as malicious")
        techniques = set(alert.technique_ids)
        if techniques & CREDENTIAL_ACCESS:
            for r in rows:
                cmd = str(r.get("process_command_line") or "").lower()
                if "lsass" in cmd or "ntds" in cmd or "sekurlsa" in cmd:
                    found.append("LSASS/NTDS access observed in surrounding process activity")
                    break
        # attack chain: multiple high-severity techniques near the alert
        distinct_procs = {str(r.get("process_name") or "").lower() for r in rows}
        suspicious = {
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "wmic.exe",
            "vssadmin.exe",
            "wbadmin.exe",
            "bcdedit.exe",
            "cmstp.exe",
        }
        if len(distinct_procs & suspicious) >= 2:
            found.append("multiple living-off-the-land binaries in the same window")
        if not context.identity.known and context.asset.criticality in ("critical", "high"):
            found.append("unknown account acting on a high-value asset")
        return list(dict.fromkeys(found))[:4]

    # ------------------------------------------------------------------ verdict
    def decide(
        self, alert: DetectionFinding, context: ContextBundle, hypotheses: list[Hypothesis]
    ) -> VerdictOut:
        sig = self._score(alert, context, hypotheses)
        techniques = alert.technique_ids
        severity = self._severity(alert, context, sig.p_malicious)
        p = sig.p_malicious
        # Escalate only for a genuine standoff: offensive AND benign evidence both present, or an
        # unresolved unknown account on a high-value asset. Otherwise commit to TP/FP.
        strong_offensive = any("offensive" in r for r in sig.reasons)
        conflict = strong_offensive and bool(sig.benign_legitimizers)
        unknown_high = (
            context.identity.user is not None
            and not context.identity.known
            and context.asset.criticality in ("critical", "high")
            and not sig.benign_legitimizers
        )
        if conflict or (unknown_high and 0.45 <= p <= 0.7):
            return VerdictOut(
                label="escalate",
                confidence=round(1 - abs(p - 0.5) * 2, 3),
                severity=severity,
                techniques=techniques,
                rationale=self._rationale("escalate", sig),
            )
        if p >= 0.55:
            return VerdictOut(
                label="true_positive",
                confidence=round(min(0.99, 0.45 + p / 2), 3),
                severity=severity,
                techniques=techniques,
                rationale=self._rationale("true_positive", sig),
            )
        if p <= 0.42:
            return VerdictOut(
                label="false_positive",
                confidence=round(min(0.99, 1 - p), 3),
                severity="informational" if p < 0.25 else severity,
                techniques=techniques if p > 0.35 else [],
                rationale=self._rationale("false_positive", sig),
            )
        # Middle band with no standoff -> lean on the rule (it fired) toward TP.
        return VerdictOut(
            label="true_positive",
            confidence=round(0.45 + p / 3, 3),
            severity=severity,
            techniques=techniques,
            rationale=self._rationale("true_positive", sig),
        )

    def _score(
        self, alert: DetectionFinding, context: ContextBundle, hypotheses: list[Hypothesis]
    ) -> Signals:
        reasons: list[str] = []
        legit: list[str] = []
        # A detection rule already fired, so the prior leans suspicious; severity and the benign /
        # offensive evidence then move it. Real attack telemetry firing a high/critical rule with no
        # benign explanation should resolve to true_positive, not perpetual escalation.
        p = 0.52
        reasons.append("a detection rule matched this activity")
        sev_boost = {
            "critical": 0.20,
            "high": 0.12,
            "medium": 0.0,
            "low": -0.18,
            "informational": -0.28,
        }
        p += sev_boost.get(str(alert.severity_id.name).lower(), 0.0)

        # The single strongest signal a human uses: what the command line actually does.
        title = alert.finding_info.title.lower()
        cmd = (alert.actor.process.cmd_line if alert.actor and alert.actor.process else "") or ""
        cmd_l = cmd.lower()
        offensive_hit = any(o in title for o in OFFENSIVE_TITLE) or any(
            o in cmd_l for o in OFFENSIVE_CMD
        )
        benign_hit = any(b in cmd_l for b in BENIGN_CMD)
        if offensive_hit:
            p += 0.34
            reasons.append("offensive tooling / attack technique in rule or command line")
        if benign_hit and not offensive_hit:
            p -= 0.30
            legit.append("command line matches a known administrative task")

        if any(h.verdict == "malicious" for h in context.ti_hits):
            p += 0.30
            reasons.append("threat-intel malicious hit")
        elif any(h.verdict == "suspicious" for h in context.ti_hits):
            p += 0.10
            reasons.append("threat-intel suspicious hit")
        techniques = set(alert.technique_ids)
        if techniques & CREDENTIAL_ACCESS and offensive_hit:
            p += 0.06
            reasons.append("credential-access technique with offensive indicators")
        if techniques & DESTRUCTIVE and not benign_hit:
            p += 0.08
            reasons.append("destructive/impact technique")
        if context.asset.criticality == "critical":
            p += 0.06
            reasons.append("critical asset")
        if context.off_hours and offensive_hit:
            p += 0.04
            reasons.append("offensive activity outside business hours")
        if context.recent_alert_count >= 3:
            p += 0.08
            reasons.append(f"{context.recent_alert_count} related recent alerts")

        # Evidence-assessment adjustments (bounded so a single query cannot dominate).
        for h in hypotheses:
            if h.is_benign and h.status == "supported" and not offensive_hit:
                p -= 0.22
                legit.append(h.reasoning or h.statement)
            if not h.is_benign and h.status == "supported":
                p += 0.14
                reasons.append(h.reasoning or "malicious hypothesis supported")
            if not h.is_benign and h.status == "refuted" and not offensive_hit:
                p -= 0.12

        idn = context.identity
        # Service/admin accounts legitimise ONLY benign-looking activity, never offensive tooling.
        if idn.service_account and benign_hit and not offensive_hit:
            p -= 0.12
            legit.append(f"known {idn.service or 'service'} account doing routine work")
        if (
            idn.role == "software-engineer"
            and idn.known
            and not offensive_hit
            and any(t in cmd_l for t in ("procdump", "code.exe", "\\projects\\", "\\dumps\\"))
        ):
            p -= 0.10
            legit.append("developer using debugging tools on their own host")
        if (
            not idn.known
            and not idn.service_account
            and context.asset.criticality in ("critical", "high")
            and offensive_hit
        ):
            p += 0.08
            reasons.append("unrecognized account on high-value host")
        return Signals(
            p_malicious=max(0.02, min(0.98, p)), reasons=reasons, benign_legitimizers=legit
        )

    def _severity(self, alert: DetectionFinding, context: ContextBundle, p: float) -> str:
        base = str(alert.severity_id.name).lower()
        if base == "unknown":
            base = "medium"
        if context.asset.criticality == "critical" and p >= 0.6:
            return "critical"
        if p < 0.25:
            return "low"
        return base if base in ("critical", "high", "medium", "low", "informational") else "medium"

    def _rationale(self, label: str, sig: Signals) -> str:
        parts = [f"p(malicious)={sig.p_malicious:.2f}"]
        if sig.reasons:
            parts.append("malicious signals: " + "; ".join(sig.reasons))
        if sig.benign_legitimizers:
            parts.append("benign context: " + "; ".join(sig.benign_legitimizers))
        return " | ".join(parts)

    # ------------------------------------------------------------------ report
    def write_report(
        self,
        alert: DetectionFinding,
        context: ContextBundle,
        hypotheses: list[Hypothesis],
        timeline: list[TimelineEvent],
        verdict: Verdict,
    ) -> ReportOut:
        from aegis.graph.report_util import render_markdown_report

        return ReportOut(
            markdown=render_markdown_report(alert, context, hypotheses, timeline, verdict)
        )

    def _name(self, technique_id: str) -> str:
        t = self.kb.get(technique_id)
        return f"{t.name} ({technique_id})" if t else technique_id


def _summ(row: dict[str, Any]) -> str:
    proc = row.get("process_name") or row.get("event_action") or "event"
    cmd = row.get("process_command_line")
    who = row.get("user_name") or ""
    host = row.get("host_name") or ""
    s = f"{proc} by {who} on {host}".strip()
    if cmd:
        s += f": {str(cmd)[:120]}"
    return s


_SENT_END = re.compile(r"(?<=[.!?])\s+")
