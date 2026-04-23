import json
import unittest

from ai.brain import HeuristicBrain


class HeuristicBrainTests(unittest.TestCase):
    def setUp(self):
        self.brain = HeuristicBrain()

    def test_triage_fuzzer_hit(self):
        result = self.brain.triage(
            "https://example.com",
            "fuzzer",
            json.dumps(
                {
                    "type": "XSS",
                    "severity": "medium",
                    "url": "https://example.com/search",
                    "param": "q",
                    "payload": "<script>alert(1)</script>",
                    "reasoning": "The payload was reflected.",
                }
            ),
        )

        self.assertTrue(result["is_finding"])
        self.assertEqual(result["vuln_type"], "XSS")
        self.assertEqual(result["affected_url"], "https://example.com/search")

    def test_manual_triage_detects_sql_errors(self):
        result = self.brain.triage(
            "https://example.com",
            "manual",
            "Unhandled SQLSTATE[42000] syntax error near SELECT",
        )

        self.assertTrue(result["is_finding"])
        self.assertEqual(result["vuln_type"], "SQLi")


if __name__ == "__main__":
    unittest.main()
