import os
import tempfile
import unittest
from pathlib import Path

from config import load_settings


class ConfigTests(unittest.TestCase):
    def test_load_settings_merges_yaml_and_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        'anthropic_api_key: "from-file"',
                        "ai:",
                        '  model: "custom-model"',
                        "scan:",
                        "  timeout: 30",
                    ]
                ),
                encoding="utf-8",
            )

            os.environ["ANTHROPIC_API_KEY"] = "from-env"
            try:
                settings = load_settings(str(config_path))
            finally:
                del os.environ["ANTHROPIC_API_KEY"]

            self.assertEqual(settings.anthropic_api_key, "from-env")
            self.assertEqual(settings.ai.model, "custom-model")
            self.assertEqual(settings.scan.timeout, 30)


if __name__ == "__main__":
    unittest.main()
