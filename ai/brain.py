from __future__ import annotations

import ast
import json
from typing import Optional

try:
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None

try:
    from google import genai as google_genai
    from google.genai import types as genai_types
except ImportError:  # pragma: no cover
    google_genai = None
    genai_types = None

from ai.prompts import (
    SYSTEM_PROMPT,
    TRIAGE_PROMPT,
    PAYLOAD_PROMPT,
    NEXT_STEP_PROMPT,
    REPORT_SUMMARY_PROMPT,
)
from config import DEFAULT_MODEL
from utils import extract_host


MAX_TOKENS = 4096
DEFAULT_PAYLOADS = {
    "XSS": [
        {
            "payload": "<script>alert(1)</script>",
            "description": "Basic reflected XSS probe.",
            "encoding": "none",
            "expected_indicator": "<script>alert(1)</script>",
        },
        {
            "payload": '\"><img src=x onerror=alert(1)>',
            "description": "Attribute-breakout XSS probe.",
            "encoding": "none",
            "expected_indicator": "onerror=alert(1)",
        },
    ],
    "SQLi": [
        {
            "payload": "' OR '1'='1",
            "description": "Boolean-based SQL injection probe.",
            "encoding": "none",
            "expected_indicator": "sql syntax",
        },
        {
            "payload": '" OR "1"="1',
            "description": "Double-quote SQL injection probe.",
            "encoding": "none",
            "expected_indicator": "sql syntax",
        },
    ],
    "SSRF": [
        {
            "payload": "http://169.254.169.254/latest/meta-data/",
            "description": "Cloud metadata probe.",
            "encoding": "none",
            "expected_indicator": "meta-data",
        },
        {
            "payload": "http://127.0.0.1/",
            "description": "Loopback SSRF probe.",
            "encoding": "none",
            "expected_indicator": "localhost",
        },
    ],
    "OpenRedirect": [
        {
            "payload": "https://example.com",
            "description": "External redirect probe.",
            "encoding": "none",
            "expected_indicator": "example.com",
        }
    ],
}

SEVERITY_SCORES = {
    "critical": 9.8,
    "high": 8.3,
    "medium": 6.5,
    "low": 3.7,
    "info": 0.0,
}


class PhantomBrain:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, max_tokens: int = MAX_TOKENS):
        if anthropic is None:
            raise RuntimeError("The anthropic package is not installed.")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def _ask(self, user_prompt: str) -> dict:
        raw = ""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            raw = response.content[0].text.strip()
            return json.loads(_extract_json(raw))
        except json.JSONDecodeError as exc:
            return {"error": f"JSON parse error: {exc}", "raw": raw}
        except Exception as exc:
            err_str = str(exc)
            # Treat billing / credit errors as a soft failure so callers can
            # fall back to heuristic mode instead of crashing.
            if "credit balance" in err_str.lower() or "billing" in err_str.lower():
                return {"error": f"API error: {exc}", "_billing_error": True}
            return {"error": f"API error: {exc}"}

    def triage(self, target: str, module: str, scan_output: str) -> dict:
        prompt = TRIAGE_PROMPT.format(
            target=target,
            module=module,
            scan_output=scan_output[:6000],
        )
        return self._ask(prompt)

    def generate_payloads(
        self,
        target: str,
        vuln_type: str,
        context: str,
        previous_payloads: Optional[list] = None,
    ) -> dict:
        prompt = PAYLOAD_PROMPT.format(
            target=target,
            vuln_type=vuln_type,
            context=context,
            previous_payloads=json.dumps(previous_payloads or []),
        )
        return self._ask(prompt)

    def decide_next_step(
        self,
        target: str,
        scope: str,
        findings: list,
        modules_run: list,
        current_phase: str,
    ) -> dict:
        prompt = NEXT_STEP_PROMPT.format(
            target=target,
            scope=scope,
            findings=json.dumps(findings, indent=2),
            modules_run=", ".join(modules_run),
            current_phase=current_phase,
        )
        return self._ask(prompt)

    def generate_report(self, target: str, findings: list) -> dict:
        prompt = REPORT_SUMMARY_PROMPT.format(
            target=target,
            findings=json.dumps(findings, indent=2),
        )
        return self._ask(prompt)


class GeminiBrain:
    """Free AI brain powered by Google Gemini 2.0 Flash (Fast & Free)."""

    GEMINI_MODEL = "gemini-2.0-flash"

    def __init__(self, api_key: str):
        if google_genai is None:
            raise RuntimeError(
                "The google-genai package is not installed. "
                "Run: pip install google-genai"
            )
        self._client = google_genai.Client(api_key=api_key)
        self._api_key = api_key
        self._heuristic = HeuristicBrain()

    def _ask(self, user_prompt: str) -> dict:
        raw = ""
        try:
            response = self._client.models.generate_content(
                model=self.GEMINI_MODEL,
                contents=user_prompt,
                config=genai_types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    max_output_tokens=4096,
                ),
            )
            raw = response.text.strip()
            return json.loads(_extract_json(raw))
        except Exception as exc:
            # Silent fallback to heuristic if Gemini fails
            return {"_gemini_error": str(exc)}

    def triage(self, target: str, module: str, scan_output: str) -> dict:
        prompt = TRIAGE_PROMPT.format(
            target=target,
            module=module,
            scan_output=scan_output[:6000],
        )
        result = self._ask(prompt)
        if "_gemini_error" in result:
            return self._heuristic.triage(target, module, scan_output)
        return result

    def generate_payloads(
        self,
        target: str,
        vuln_type: str,
        context: str,
        previous_payloads: Optional[list] = None,
    ) -> dict:
        prompt = PAYLOAD_PROMPT.format(
            target=target,
            vuln_type=vuln_type,
            context=context,
            previous_payloads=json.dumps(previous_payloads or []),
        )
        result = self._ask(prompt)
        if "_gemini_error" in result:
            return self._heuristic.generate_payloads(target, vuln_type, context, previous_payloads)
        return result

    def decide_next_step(
        self,
        target: str,
        scope: str,
        findings: list,
        modules_run: list,
        current_phase: str,
    ) -> dict:
        prompt = NEXT_STEP_PROMPT.format(
            target=target,
            scope=scope,
            findings=json.dumps(findings, indent=2),
            modules_run=", ".join(modules_run),
            current_phase=current_phase,
        )
        result = self._ask(prompt)
        if "_gemini_error" in result:
            return self._heuristic.decide_next_step(target, scope, findings, modules_run, current_phase)
        return result

    def generate_report(self, target: str, findings: list) -> dict:
        prompt = REPORT_SUMMARY_PROMPT.format(
            target=target,
            findings=json.dumps(findings, indent=2),
        )
        result = self._ask(prompt)
        if "_gemini_error" in result:
            return self._heuristic.generate_report(target, findings)
        return result


class HeuristicBrain:
    def triage(self, target: str, module: str, scan_output: str) -> dict:
        parsed = _coerce_data(scan_output)
        module_name = (module or "").lower()

        if isinstance(parsed, dict):
            if parsed.get("type") in {"XSS", "SQLi", "SSRF", "OpenRedirect"}:
                return _finding_from_issue(parsed)
            if parsed.get("severity") and parsed.get("vuln_type"):
                return _finding_from_issue(parsed)
            if parsed.get("title") and parsed.get("url"):
                return _finding_from_issue(parsed)

        if module_name == "manual":
            return _manual_triage(target, scan_output)

        return {
            "is_finding": False,
            "severity": "none",
            "confidence": 0.25,
            "vuln_type": "None",
            "affected_url": None,
            "reasoning": f"No concrete finding was confirmed from the {module_name or 'scan'} output.",
            "next_payloads": [],
            "next_action": "pivot",
            "report_paragraph": "",
        }

    def generate_payloads(
        self,
        target: str,
        vuln_type: str,
        context: str,
        previous_payloads: Optional[list] = None,
    ) -> dict:
        del target, context, previous_payloads
        key = vuln_type or "Other"
        return {
            "payloads": DEFAULT_PAYLOADS.get(key, []),
            "notes": "Generated from PhantomAI's local fallback payload library.",
        }

    def decide_next_step(
        self,
        target: str,
        scope: str,
        findings: list,
        modules_run: list,
        current_phase: str,
    ) -> dict:
        del target, scope
        if findings and "exploit" not in modules_run:
            likely = [item for item in findings if item.get("severity") in {"high", "critical", "medium"}]
            if likely:
                return {
                    "next_module": "exploit",
                    "next_targets": _unique_values(
                        item.get("affected_url") for item in likely if item.get("affected_url")
                    ),
                    "reasoning": "Confirmed or strongly-indicated findings should be validated before reporting.",
                    "priority_params": _unique_values(
                        item.get("artifact", {}).get("param") for item in likely if item.get("artifact")
                    ),
                    "attack_vectors": _unique_values(item.get("vuln_type") for item in likely),
                    "estimated_impact": "Attempt to confirm whether high-signal issues are reproducible.",
                }

        if current_phase == "recon" and "enum" not in modules_run:
            return {
                "next_module": "enum",
                "next_targets": [],
                "reasoning": "Enumeration builds endpoint coverage before fuzzing.",
                "priority_params": [],
                "attack_vectors": [],
                "estimated_impact": "Discover reachable attack surface.",
            }

        if "fuzz" not in modules_run:
            return {
                "next_module": "fuzz",
                "next_targets": [],
                "reasoning": "Fuzzing should run after enumeration to exercise discovered routes.",
                "priority_params": [],
                "attack_vectors": [],
                "estimated_impact": "Probe for reflected input handling, redirects, and obvious injection signals.",
            }

        return {
            "next_module": "report" if findings else "done",
            "next_targets": [],
            "reasoning": "The useful scan phases are complete.",
            "priority_params": [],
            "attack_vectors": [],
            "estimated_impact": "Wrap up the session cleanly.",
        }

    def generate_report(self, target: str, findings: list) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        normalized_findings = []

        for finding in findings:
            ai_result = finding.get("ai_result", finding)
            severity = ai_result.get("severity", "info")
            if severity in counts:
                counts[severity] += 1

            vuln_type = ai_result.get("vuln_type", "Finding")
            affected_url = ai_result.get("affected_url") or finding.get("affected_url") or target
            title = ai_result.get("title") or f"{vuln_type} on {extract_host(affected_url)}"
            reasoning = ai_result.get("reasoning", "Potentially security-relevant behavior was identified.")
            report_paragraph = ai_result.get("report_paragraph") or reasoning

            normalized_findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "cvss_score": SEVERITY_SCORES.get(severity, 0.0),
                    "cvss_vector": _cvss_vector_for_severity(severity),
                    "affected_url": affected_url,
                    "description": report_paragraph,
                    "impact": _impact_for_vuln(vuln_type, severity),
                    "steps_to_reproduce": _steps_from_finding(ai_result),
                    "remediation": _remediation_for_vuln(vuln_type),
                    "references": [],
                }
            )

        total = sum(counts.values())
        ordered = ["critical", "high", "medium", "low", "info"]
        overall_risk = next((level for level in ordered if counts[level] > 0), "informational")

        return {
            "executive_summary": (
                f"PhantomAI reviewed {target} and recorded {total} findings. "
                f"The highest observed risk was {overall_risk}.\n\n"
                "This report was generated locally using PhantomAI's heuristic mode. "
                "Findings should still be manually validated before external disclosure."
            ),
            "overall_risk": overall_risk,
            "total_findings": total,
            "findings_by_severity": counts,
            "recommendations": [
                "Validate exposed assets and remove unnecessary public endpoints.",
                "Review input handling on dynamic endpoints and add server-side validation.",
                "Retest confirmed findings manually before using them in a formal report.",
            ],
            "findings": normalized_findings,
        }


def _extract_json(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end >= start:
        return cleaned[start : end + 1]
    return cleaned


def _coerce_data(scan_output: str):
    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(scan_output)
        except Exception:
            continue
    return scan_output


def _finding_from_issue(issue: dict) -> dict:
    vuln_type = issue.get("vuln_type") or issue.get("type") or "Other"
    severity = issue.get("severity", "medium")
    url = issue.get("url") or issue.get("affected_url")
    reasoning = issue.get("reasoning") or issue.get("title") or "Potentially vulnerable behavior observed."
    confidence = float(issue.get("confidence", 0.82))
    param = issue.get("param")
    payload = issue.get("payload")

    report_paragraph = reasoning
    if param:
        report_paragraph = f"{reasoning} Parameter `{param}` was involved at {url or 'the tested endpoint'}."
    if payload:
        report_paragraph += f" Observed payload: {payload}."

    return {
        "is_finding": severity != "none",
        "severity": severity,
        "confidence": confidence,
        "vuln_type": vuln_type,
        "affected_url": url,
        "reasoning": reasoning,
        "next_payloads": [item["payload"] for item in DEFAULT_PAYLOADS.get(vuln_type, [])],
        "next_action": "escalate" if severity in {"critical", "high", "medium"} else "report",
        "report_paragraph": report_paragraph,
        "title": issue.get("title", vuln_type),
    }


def _manual_triage(target: str, raw: str) -> dict:
    lowered = raw.lower()
    if "sql syntax" in lowered or "sqlstate" in lowered:
        return {
            "is_finding": True,
            "severity": "high",
            "confidence": 0.75,
            "vuln_type": "SQLi",
            "affected_url": target,
            "reasoning": "The supplied output contains database error strings commonly associated with SQL injection.",
            "next_payloads": [item["payload"] for item in DEFAULT_PAYLOADS["SQLi"]],
            "next_action": "escalate",
            "report_paragraph": "Database error output suggests that user-controlled input may reach a SQL context unsafely.",
        }

    if "<script>alert(1)</script>" in lowered or "onerror=alert(1)" in lowered:
        return {
            "is_finding": True,
            "severity": "medium",
            "confidence": 0.7,
            "vuln_type": "XSS",
            "affected_url": target,
            "reasoning": "The supplied output appears to reflect a JavaScript execution payload.",
            "next_payloads": [item["payload"] for item in DEFAULT_PAYLOADS["XSS"]],
            "next_action": "escalate",
            "report_paragraph": "The provided response appears to reflect a script execution payload and may indicate reflected XSS.",
        }

    return {
        "is_finding": False,
        "severity": "none",
        "confidence": 0.2,
        "vuln_type": "None",
        "affected_url": target,
        "reasoning": "The supplied output did not match a high-signal finding pattern.",
        "next_payloads": [],
        "next_action": "pivot",
        "report_paragraph": "",
    }


def _unique_values(values) -> list[str]:
    seen = set()
    ordered = []
    for value in values:
        if value and value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered


def _remediation_for_vuln(vuln_type: str) -> str:
    mapping = {
        "XSS": "Apply contextual output encoding and validate or sanitize untrusted input.",
        "SQLi": "Use parameterized queries and review server-side input handling.",
        "SSRF": "Restrict outbound requests, validate destinations, and deny access to internal address ranges.",
        "OpenRedirect": "Restrict redirect destinations to an allowlist and avoid using raw user input in redirect logic.",
        "InfoDisclosure": "Remove or protect sensitive endpoints and configuration artifacts from unauthenticated users.",
        "Misconfiguration": "Review deployment configuration and remove unnecessary public-facing management surfaces.",
    }
    return mapping.get(vuln_type, "Review the affected code path and harden the exposed behavior.")


def _impact_for_vuln(vuln_type: str, severity: str) -> str:
    if vuln_type == "SQLi":
        return "A successful SQL injection could expose or alter backend data."
    if vuln_type == "XSS":
        return "A successful XSS issue can execute attacker-controlled JavaScript in another user's browser."
    if vuln_type == "SSRF":
        return "A successful SSRF issue can expose internal services and cloud metadata."
    if vuln_type == "OpenRedirect":
        return "An open redirect can support phishing chains and redirect-based trust abuse."
    if severity in {"critical", "high"}:
        return "The observed behavior could expose sensitive internals or materially expand attack surface."
    return "The observed behavior leaks information or increases reachable attack surface."


def _steps_from_finding(finding: dict) -> list[str]:
    steps = []
    affected_url = finding.get("affected_url")
    if affected_url:
        steps.append(f"Request the affected endpoint: {affected_url}")
    artifact = finding.get("artifact", {})
    if artifact.get("param") and artifact.get("payload"):
        steps.append(
            f"Supply `{artifact['payload']}` to the `{artifact['param']}` parameter and inspect the response."
        )
    reasoning = finding.get("reasoning")
    if reasoning:
        steps.append(f"Observe the resulting behavior: {reasoning}")
    return steps or ["Replay the request and confirm the observed behavior manually."]


def _cvss_vector_for_severity(severity: str) -> str:
    mapping = {
        "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    }
    return mapping.get(severity, mapping["info"])
