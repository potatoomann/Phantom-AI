import asyncio
import json
from typing import Optional

from config import Settings
from output import terminal as term
from output.logger import SessionLogger


class Orchestrator:
    def __init__(
        self,
        target: str,
        mode: str,
        brain,
        logger: SessionLogger,
        settings: Settings,
        scope: str = "",
    ):
        self.target = target
        self.mode = mode
        self.brain = brain
        self.logger = logger
        self.settings = settings
        self.scope = scope or target
        self.findings = []
        self.confirmed_findings = []
        self.modules_run = []
        self.current_phase = "recon"
        self.recon_results: dict = {}
        self.enum_results: dict = {}

    async def run(self):
        term.phase_start("Starting scan", self.target)

        if self.mode == "recon":
            await self._run_recon()
        elif self.mode == "full":
            await self._run_recon()
            await self._run_enum()
            await self._run_fuzz()
            await self._run_owasp()
            await self._ai_driven_loop()
        elif self.mode == "ai":
            term.info("AI mode: paste raw output below (end with EOF / Ctrl+D)")
            import sys
            raw = sys.stdin.read()
            await self._triage_output("manual", raw)

        term.summary_table(self.confirmed_findings)
        excluded = len(self.findings) - len(self.confirmed_findings)
        if excluded > 0:
            term.info(
                f"{excluded} candidate finding(s) were excluded from the final summary until confirmed."
            )
        self.logger.finish_session()

    async def _triage_output(self, module: str, raw_output: str, artifact: Optional[dict] = None):
        with term.ai_thinking(f"AI triaging {module} output..."):
            result = self.brain.triage(self.target, module, raw_output)

        # Auto-downgrade on billing / credit errors: try Gemini first, then heuristic
        if result.get('_billing_error'):
            gemini_key = getattr(self.settings, 'gemini_api_key', '')
            if gemini_key:
                try:
                    from ai.brain import GeminiBrain
                    self.brain = GeminiBrain(api_key=gemini_key)
                    term.info('Anthropic credits exhausted - switching to Gemini (free) for the rest of this scan.')
                except Exception:
                    from ai.brain import HeuristicBrain
                    self.brain = HeuristicBrain()
                    term.info('Gemini unavailable - switching to heuristic mode.')
            else:
                from ai.brain import HeuristicBrain
                self.brain = HeuristicBrain()
                term.info('API credits exhausted - switching to heuristic mode for the rest of this scan.')
            result = self.brain.triage(self.target, module, raw_output)

        if result.get('error') and not result.get('_billing_error'):
            term.error(result['error'])
            return

        if artifact:
            result["artifact"] = artifact
            if not result.get("affected_url"):
                result["affected_url"] = artifact.get("url") or artifact.get("affected_url")
        result["confirmed"] = self._is_confirmed_result(module, result)

        self.logger.log_finding(module, raw_output, result)

        if result.get("is_finding"):
            self.findings.append(result)
            if result["confirmed"]:
                self.confirmed_findings.append(result)
            term.finding(result)

        return result

    async def _run_recon(self):
        from modules.recon import run_recon

        term.phase_start("Recon", self.target)
        results = await run_recon(self.target, self.settings)
        self.recon_results = results
        self.modules_run.append("recon")
        term.phase_done("Recon", len(results.get("subdomains", [])))

        summary = {
            "target": self.target,
            "subdomain_count": results.get("subdomain_count", 0),
            "domain": results.get("domain"),
        }
        await self._triage_output("recon", json.dumps(summary), artifact=summary)
        self.current_phase = "enum"

    async def _run_enum(self):
        from modules.enum import run_enum

        term.phase_start("Enumeration", self.target)
        results = await run_enum(
            self.target,
            subdomains=self.recon_results.get("subdomains", []),
            settings=self.settings,
        )
        self.enum_results = results
        self.modules_run.append("enum")
        term.phase_done("Enumeration", len(results.get("endpoints", [])))

        if results.get("issues"):
            for issue in results["issues"]:
                await self._triage_output("enum", json.dumps(issue), artifact=issue)
        else:
            summary = {
                "target": self.target,
                "interesting_count": len(results.get("interesting", [])),
                "tech_stack": results.get("tech_stack", []),
            }
            await self._triage_output("enum", json.dumps(summary), artifact=summary)
        self.current_phase = "fuzz"

    async def _run_fuzz(self):
        from modules.fuzzer import run_fuzz

        term.phase_start("Fuzzing", self.target)
        results = await run_fuzz(
            self.target,
            interesting=self.enum_results.get("interesting", []),
            settings=self.settings,
        )
        self.modules_run.append("fuzz")
        term.phase_done("Fuzzing", len(results.get("hits", [])))

        for hit in results.get("hits", []):
            await self._triage_output("fuzzer", json.dumps(hit), artifact=hit)

        self.current_phase = "exploit"

    async def _ai_driven_loop(self):
        max_iterations = self.settings.scan.max_ai_iterations
        for _ in range(max_iterations):
            with term.ai_thinking("AI deciding next step..."):
                decision = self.brain.decide_next_step(
                    target=self.target,
                    scope=self.scope,
                    findings=self.findings,
                    modules_run=self.modules_run,
                    current_phase=self.current_phase,
                )

            if decision.get("error"):
                term.error(decision["error"])
                break

            term.next_step_decision(decision)
            next_module = decision.get("next_module", "done")

            if next_module in ("done", "report"):
                break
            if next_module == "exploit":
                await self._run_exploit(decision)
            elif next_module == "fuzz":
                await self._run_fuzz()
            elif next_module == "enum":
                await self._run_enum()
            else:
                break

    async def _run_exploit(self, decision: dict):
        from modules.exploit import run_exploit

        term.phase_start("Exploit / confirmation", self.target)
        targets = decision.get("next_targets") or [self.target]
        vectors = decision.get("attack_vectors", [])
        params = decision.get("priority_params", [])

        for url in targets[:5]:
            results = await run_exploit(
                url,
                vectors,
                self.brain,
                self.settings,
                candidate_params=params,
            )
            self.modules_run.append("exploit")
            for hit in results.get("confirmed", []):
                await self._triage_output("exploit", json.dumps(hit), artifact=hit)

    async def _run_owasp(self):
        """Run all OWASP Top 10 2021 + 2025 checks against discovered endpoints."""
        import httpx
        import re
        import time
        from modules.owasp_checks import CHECKS, OWASP_2021, OWASP_2025

        term.phase_start("OWASP Checks (2021 + 2025)", self.target)

        # Collect endpoints to test — normalise everything to plain strings
        raw_endpoints = list(self.enum_results.get("endpoints", []))
        interesting = self.enum_results.get("interesting", [])
        for item in interesting:
            if isinstance(item, dict):
                u = item.get("url") or item.get("affected_url", "")
            else:
                u = str(item)
            if u and u not in raw_endpoints:
                raw_endpoints.append(u)

        # Guarantee every entry is a string
        endpoints = []
        for entry in raw_endpoints:
            if isinstance(entry, str):
                endpoints.append(entry)
            elif isinstance(entry, dict):
                u = entry.get("url") or entry.get("affected_url", "")
                if u:
                    endpoints.append(str(u))
        if not endpoints:
            endpoints = [self.target]

        findings_count = 0
        proxy = None
        if self.settings.proxy.enabled and self.settings.proxy.url:
            proxy = self.settings.proxy.url

        async with httpx.AsyncClient(
            timeout=15.0,
            verify=False,
            follow_redirects=True,
            proxy=proxy if proxy else None,
        ) as client:
            for url in endpoints[:20]:  # Limit to 20 endpoints
                for check in CHECKS:
                    if check.get("passive"):
                        continue  # Skip passive-only checks here
                    if not check.get("payloads"):
                        continue

                    url_patterns = check.get("url_patterns", [])
                    if url_patterns and not any(p in url.lower() for p in url_patterns):
                        continue

                    # Fetch baseline BEFORE injecting — required for all checks
                    try:
                        baseline_start = time.monotonic()
                        baseline_resp = await client.get(url)
                        baseline_elapsed = time.monotonic() - baseline_start
                        baseline_body = baseline_resp.text.lower()
                    except Exception:
                        baseline_body = ""
                        baseline_elapsed = 0.0

                    for payload in check["payloads"][:3]:  # Top 3 payloads per check
                        test_url = url
                        # Inject into query string if possible
                        if "?" in url:
                            test_url = re.sub(r"(=[^&]*)", f"={payload}", url, count=1)
                        else:
                            test_url = f"{url}?test={payload}"

                        try:
                            start = time.monotonic()
                            resp = await client.get(test_url)
                            elapsed = time.monotonic() - start
                            body = resp.text.lower()

                            hit = False
                            evidence = ""

                            # Time-based: injected response must be significantly slower than baseline
                            if check.get("time_based") and elapsed >= check.get("time_threshold", 4.0):
                                if elapsed > baseline_elapsed + 3.0:  # Must be meaningfully slower
                                    hit = True
                                    evidence = f"Response delayed {elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s"

                            # Indicator check: indicator must appear AFTER injection but NOT in baseline
                            for indicator in check.get("indicators", []):
                                ind_lower = indicator.lower()
                                # SSTI check: "49" is too generic; require it as the direct evaluation result
                                if check["id"] == "ssti" and ind_lower == "49":
                                    # Must appear in injected response but not in baseline
                                    if re.search(r'\b49\b', body) and not re.search(r'\b49\b', baseline_body):
                                        hit = True
                                        evidence = "Template expression {{7*7}} evaluated to 49 (not present in baseline)"
                                        break
                                elif ind_lower in body and ind_lower not in baseline_body:
                                    hit = True
                                    evidence = f"Found '{indicator}' in response (absent in baseline)"
                                    break

                            if hit:
                                findings_count += 1
                                owasp_21 = check["owasp_2021"]
                                owasp_25 = check.get("owasp_2025", owasp_21)
                                finding = {
                                    "is_finding": True,
                                    "title": check["name"],
                                    "severity": check["severity"],
                                    "confidence": 0.85,
                                    "url": test_url,
                                    "affected_url": test_url,
                                    "evidence": evidence,
                                    "payload": payload,
                                    "owasp_2021": f"{owasp_21}:2021 – {OWASP_2021[owasp_21]}",
                                    "owasp_2025": f"{owasp_25}:2025 – {OWASP_2025[owasp_25]}",
                                    "check_id": check["id"],
                                    "confirmed": True,
                                }
                                self.findings.append(finding)
                                self.confirmed_findings.append(finding)
                                self.logger.log_finding("owasp", test_url, finding)
                                term.finding(finding)
                                break  # Move to next check on first hit

                        except Exception:
                            continue

        term.phase_done("OWASP Checks", findings_count)
        self.modules_run.append("owasp")

    def _is_confirmed_result(self, module: str, result: dict) -> bool:
        if not result.get("is_finding"):
            return False

        module_name = (module or "").lower()
        if module_name in {"exploit", "enum", "manual", "owasp"}:
            return True

        # Recon and fuzzer output are treated as candidate signals until a
        # follow-up confirmation step proves them out.
        return False
