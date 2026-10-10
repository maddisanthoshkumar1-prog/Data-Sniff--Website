
import os
import io
import json
import unittest

from app import app, REPORT_FOLDER, UPLOAD_FOLDER


class TestDataSniffAppSecurity(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.created_reports = []

    def tearDown(self):
        for filename in self.created_reports:
            path = os.path.join(REPORT_FOLDER, filename)

            if os.path.isfile(path):
                os.remove(path)

    def create_report(self):
        filename = "test_security_report.json"
        path = os.path.join(REPORT_FOLDER, filename)

        os.makedirs(REPORT_FOLDER, exist_ok=True)

        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "file_name": "test.log",
                    "date": "10-10-2026 10:00:00",
                    "risk_level": "HIGH",
                    "results": {
                        "Passwords": ["secret123"],
                        "GitHub Tokens": ["ghp_" + "a" * 36],
                    },
                },
                file,
            )

        self.created_reports.append(filename)
        return filename

    def test_report_download_masks_secrets(self):
        filename = self.create_report()

        response = self.client.get(
            f"/download-report/{filename}"
        )

        try:
            self.assertEqual(response.status_code, 200)

            downloaded = response.get_data(as_text=True)

            self.assertIn("[REDACTED]", downloaded)
            self.assertNotIn("secret123", downloaded)
            self.assertNotIn("ghp_" + "a" * 36, downloaded)
        finally:
            response.close()

    def test_report_detail_masks_secrets(self):
        filename = self.create_report()

        response = self.client.get(f"/report/{filename}")

        self.assertEqual(response.status_code, 200)

        page = response.get_data(as_text=True)

        self.assertIn("[REDACTED]", page)
        self.assertNotIn("secret123", page)

    def test_report_delete_requires_post(self):
        filename = self.create_report()

        response = self.client.get(
            f"/delete-report/{filename}"
        )

        self.assertEqual(response.status_code, 405)

        path = os.path.join(REPORT_FOLDER, filename)
        self.assertTrue(os.path.isfile(path))

    def test_report_delete_post(self):
        filename = self.create_report()

        response = self.client.post(
            f"/delete-report/{filename}"
        )

        self.assertEqual(response.status_code, 302)

        path = os.path.join(REPORT_FOLDER, filename)
        self.assertFalse(os.path.isfile(path))

        self.created_reports.remove(filename)

    def test_uploaded_file_is_deleted_after_scan(self):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        before = set(os.listdir(UPLOAD_FOLDER))

        response = self.client.post(
            "/scan-file",
            data={
                "logfile": (
                    io.BytesIO(b"Normal log message"),
                    "cleanup_test.log",
                )
            },
            content_type="multipart/form-data",
        )

        try:
            self.assertEqual(response.status_code, 200)

            after = set(os.listdir(UPLOAD_FOLDER))

            self.assertEqual(
                after,
                before,
                "Uploaded file was not cleaned up after scanning.",
            )
        finally:
            response.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
