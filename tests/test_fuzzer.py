import unittest

from modules.fuzzer import _build_test_cases


class FuzzerTests(unittest.TestCase):
    def test_build_test_cases_uses_url_like_params_for_redirects(self):
        cases = _build_test_cases(
            "https://example.com",
            [{"url": "https://example.com/login", "status": 200}],
        )

        login_cases = [case for case in cases if case["url"] == "https://example.com/login"]
        self.assertTrue(any("redirect" in case["types"] for case in login_cases))


if __name__ == "__main__":
    unittest.main()
