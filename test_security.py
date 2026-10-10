
import unittest
from app import mask_value, mask_results


class TestDataSniffSecurity(unittest.TestCase):

    def test_password_redaction(self):
        self.assertEqual(
            mask_value("Passwords", "DemoPass123!"),
            "[REDACTED]"
        )

    def test_api_key_redaction(self):
        self.assertEqual(
            mask_value("API Keys", "sk_TEST123456789"),
            "[REDACTED]"
        )

    def test_github_token_redaction(self):
        self.assertEqual(
            mask_value("GitHub Tokens", "ghp_" + "a" * 36),
            "[REDACTED]"
        )

    def test_aws_key_redaction(self):
        self.assertEqual(
            mask_value("AWS Access Keys", "AKIAIOSFODNN7EXAMPLE"),
            "[REDACTED]"
        )

    def test_jwt_redaction(self):
        self.assertEqual(
            mask_value("JWT Tokens", "header.payload.signature"),
            "[REDACTED]"
        )

    def test_database_url_redaction(self):
        self.assertEqual(
            mask_value(
                "Database Connection Strings",
                "postgresql://user:secret@localhost/db"
            ),
            "[REDACTED]"
        )

    def test_private_key_redaction(self):
        self.assertEqual(
            mask_value(
                "Private Key Blocks",
                "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----"
            ),
            "[REDACTED]"
        )

    def test_mask_results(self):
        results = {
            "Passwords": ["secret123"],
            "GitHub Tokens": ["ghp_" + "a" * 36]
        }

        masked = mask_results(results)

        self.assertEqual(masked["Passwords"], ["[REDACTED]"])
        self.assertEqual(masked["GitHub Tokens"], ["[REDACTED]"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
