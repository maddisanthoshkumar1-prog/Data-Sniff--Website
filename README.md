# DataSniff – Log and Data Leak Detector

DataSniff is a Python Flask-based cybersecurity web application that scans log and text files to detect sensitive information and potential data leaks.

## Features

- Detects emails, IP addresses, passwords, API keys, GitHub tokens, phone numbers, AWS access keys, JWTs, database connection strings, and private key blocks.
- Identifies suspicious high-entropy strings.
- Masks detected sensitive values in results and reports.
- Assigns LOW, MEDIUM, or HIGH risk levels based on finding counts.
- Provides a dashboard and scan report history.
- Supports viewing, downloading, and deleting reports.
- Validates file extensions and file sizes.
- Deletes uploaded files after scanning.
- Includes automated tests for detection, masking, and application security.

## Technology Stack

- Python
- Flask
- HTML, CSS, JavaScript
- Regular expressions
- Entropy-based string detection
- JSON report storage
- Python unittest

## Supported File Types

- `.txt`
- `.log`
- `.json`

Maximum upload size: 10 MB.

## Installation and Usage

1. Clone this repository.
2. Open a terminal in the project directory.
3. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   ```

   Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

4. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Start the application:

   ```bash
   python app.py
   ```

6. Open `http://127.0.0.1:5000/` in your browser.

## Run Tests

```bash
python -m unittest test_detector test_security test_app_security -v
```

## Security Notes

- Detected secrets are masked before being displayed and saved in reports.
- Uploaded files are removed after scanning.
- Reports are stored locally as JSON files.
- This is an educational portfolio project, not a substitute for a professional security auditing solution.
- High-entropy detection may produce false positives or miss some secrets.
- Do not upload real production logs or confidential data to an untrusted environment.

## Project Status

Portfolio project — testing, documentation, and final presentation in progress.