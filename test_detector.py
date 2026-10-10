
import os
import tempfile
import unittest

from detector import scan_file


class TestDataSniffDetector(unittest.TestCase):

    def scan_text(self, content):
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".log",
                encoding="utf-8",
                delete=False
            ) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            return scan_file(temp_path)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    def test_email_detection(self):
        results = self.scan_text("Email: test@example.com")
        self.assertEqual(len(results.get("Emails", [])), 1)

    def test_password_detection(self):
        results = self.scan_text("Password=DemoPass123!")
        self.assertEqual(len(results.get("Passwords", [])), 1)

    def test_api_key_detection(self):
        results = self.scan_text("API=sk_TEST123456789")
        self.assertEqual(len(results.get("API Keys", [])), 1)

    def test_github_token_detection(self):
        token = "ghp_" + "a" * 36
        results = self.scan_text("GitHub=" + token)
        self.assertEqual(len(results.get("GitHub Tokens", [])), 1)

    def test_ip_detection(self):
        results = self.scan_text("Server IP: 192.168.1.10")
        self.assertEqual(len(results.get("IP Addresses", [])), 1)

    def test_phone_detection(self):
        results = self.scan_text("Phone: 9876543210")
        self.assertEqual(len(results.get("Phone Numbers", [])), 1)

    def test_duplicate_entropy_filter(self):
        token = "ghp_" + "a" * 36
        results = self.scan_text("GitHub=" + token)

        entropy_values = results.get("High Entropy Strings", [])
        self.assertNotIn(token, entropy_values)

    def test_invalid_ip_rejected(self):
        results = self.scan_text("IP: 999.999.999.999")
        self.assertEqual(len(results.get("IP Addresses", [])), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
