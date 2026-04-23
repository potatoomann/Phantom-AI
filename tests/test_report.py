import tempfile
import unittest
from pathlib import Path

from output.report import generate_html_report


class ReportTests(unittest.TestCase):
    def test_generate_html_report_creates_output_in_report_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(
                target="https://example.com",
                ai_report={
                    "executive_summary": "Summary",
                    "overall_risk": "low",
                    "findings_by_severity": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 1,
                        "info": 0,
                    },
                    "findings": [
                        {
                            "title": "Example finding",
                            "severity": "low",
                            "affected_url": "https://example.com",
                            "description": "Desc",
                            "impact": "Impact",
                            "steps_to_reproduce": ["Step 1"],
                            "remediation": "Fix it",
                        }
                    ],
                },
                report_dir=tmpdir,
            )

            output_file = Path(path)
            self.assertTrue(output_file.exists())
            self.assertTrue(str(output_file).startswith(tmpdir))


if __name__ == "__main__":
    unittest.main()
