import tempfile
import unittest
from pathlib import Path

import output.logger as logger_module
from config import Settings
from orchestrator import Orchestrator
from output.logger import SessionLogger


class DummyBrain:
    def triage(self, target, module, scan_output):
        del target, module, scan_output
        return {
            "is_finding": True,
            "severity": "medium",
            "confidence": 0.8,
            "vuln_type": "OpenRedirect",
            "affected_url": "https://example.com/login",
            "reasoning": "Candidate redirect found.",
            "next_payloads": [],
            "next_action": "escalate",
            "report_paragraph": "Candidate redirect.",
        }


class ConfirmationFlowTests(unittest.TestCase):
    def test_orchestrator_marks_only_exploit_enum_and_manual_as_confirmed(self):
        orchestrator = Orchestrator(
            target="https://example.com",
            mode="full",
            brain=DummyBrain(),
            logger=None,
            settings=Settings(),
        )

        self.assertFalse(orchestrator._is_confirmed_result("fuzzer", {"is_finding": True}))
        self.assertFalse(orchestrator._is_confirmed_result("recon", {"is_finding": True}))
        self.assertTrue(orchestrator._is_confirmed_result("exploit", {"is_finding": True}))
        self.assertTrue(orchestrator._is_confirmed_result("enum", {"is_finding": True}))
        self.assertTrue(orchestrator._is_confirmed_result("manual", {"is_finding": True}))

    def test_logger_only_loads_confirmed_findings_for_reports(self):
        original_db_path = logger_module.DB_PATH
        with tempfile.TemporaryDirectory() as tmpdir:
            logger_module.DB_PATH = Path(tmpdir) / "sessions.db"
            try:
                logger = SessionLogger(target="https://example.com", mode="full")
                logger.log_finding(
                    "fuzzer",
                    "{}",
                    {
                        "severity": "medium",
                        "vuln_type": "OpenRedirect",
                        "affected_url": "https://example.com/login",
                        "reasoning": "Candidate only.",
                        "confirmed": False,
                    },
                )
                logger.log_finding(
                    "exploit",
                    "{}",
                    {
                        "severity": "medium",
                        "vuln_type": "OpenRedirect",
                        "affected_url": "https://example.com/login",
                        "reasoning": "Confirmed redirect.",
                        "confirmed": True,
                    },
                )

                findings = SessionLogger.load_session_findings(logger.session_id)
                logger.finish_session()
            finally:
                logger_module.DB_PATH = original_db_path

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["module"], "exploit")


if __name__ == "__main__":
    unittest.main()
