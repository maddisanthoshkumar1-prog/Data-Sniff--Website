

from flask import Flask, render_template, request, redirect, send_file

from werkzeug.utils import secure_filename

from detector import scan_file



import os

import json

import glob

import uuid

import tempfile

from datetime import datetime





app = Flask(__name__)



BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

REPORT_FOLDER = os.path.join(BASE_DIR, "reports")



os.makedirs(UPLOAD_FOLDER, exist_ok=True)

os.makedirs(REPORT_FOLDER, exist_ok=True)



ALLOWED_EXTENSIONS = {"txt", "log", "json"}

MAX_FILE_SIZE = 10 * 1024 * 1024



app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + (64 * 1024)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")



# --------------------------------------------------

# File validation

# --------------------------------------------------



def allowed_file(filename):

    return (

        "." in filename

        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    )





# --------------------------------------------------

# Sensitive data masking

# --------------------------------------------------



def mask_value(category, value):
    """Mask sensitive values before they are displayed or saved."""
    value = str(value)

    # Never expose secrets, even partially.
    fully_redact_categories = {
        "Passwords",
        "API Keys",
        "GitHub Tokens",
        "High Entropy Strings",
        "AWS Access Keys",
        "JWT Tokens",
        "Database Connection Strings",
        "Private Key Blocks",
    }
    if category in fully_redact_categories:
        return "[REDACTED]"

    if category == "Emails":
        if "@" in value:
            username, domain = value.split("@", 1)
            return f"{username[:1]}***@{domain}" if username else f"***@{domain}"
        return "[REDACTED]"

    if category == "Phone Numbers":
        digits = "".join(ch for ch in value if ch.isdigit())
        return f"******{digits[-4:]}" if len(digits) >= 4 else "[REDACTED]"

    if category == "IP Addresses":
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.***.***.{parts[3]}"
        return "[REDACTED]"

    # Fail closed for any unknown detector category.
    return "[REDACTED]"


def mask_results(results):
    """Return a masked copy of detector results."""
    safe_results = {}
    for category, values in results.items():
        if isinstance(values, list):
            safe_results[category] = [mask_value(category, value) for value in values]
        else:
            safe_results[category] = []
    return safe_results


def save_report(filename, results, risk):

    report = {

        "file_name": filename,

        "date": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),

        "risk_level": risk,

        "results": results

    }



    report_name = (

        datetime.now().strftime("%Y%m%d_%H%M%S")

        + "_"

        + uuid.uuid4().hex

        + ".json"

    )



    report_path = os.path.join(REPORT_FOLDER, report_name)



    with open(report_path, "w", encoding="utf-8") as f:

        json.dump(report, f, indent=4, ensure_ascii=False)



    print("Saved report:", report_name)





# --------------------------------------------------

# File too large handler

# --------------------------------------------------



@app.errorhandler(413)

def file_too_large(error):

    return render_template(

        "scan.html",

        error="File is too large. Maximum allowed size is 10 MB."

    ), 413





# --------------------------------------------------

# Home and information pages

# --------------------------------------------------



@app.route("/")

def home():

    return render_template("index.html")





@app.route("/scan")

def scan_page():

    return render_template("scan.html")





@app.route("/about")

def about():

    return render_template("about.html")





@app.route("/contact")

def contact():

    return render_template("contact.html")





# --------------------------------------------------

# Dashboard

# --------------------------------------------------



@app.route("/dashboard")

def dashboard():

    all_reports = []



    for file_path in glob.glob(os.path.join(REPORT_FOLDER, "*.json")):

        try:

            with open(file_path, "r", encoding="utf-8") as f:

                report = json.load(f)



            if not isinstance(report, dict):

                continue



            report["_report_id"] = os.path.basename(file_path)

            report["_sort_time"] = os.path.getmtime(file_path)

            all_reports.append(report)



        except (OSError, json.JSONDecodeError) as exc:

            print("Could not read report:", exc)



    all_reports.sort(

        key=lambda report: report.get("_sort_time", 0),

        reverse=True

    )



    total_scans = len(all_reports)



    total_findings = sum(

        len(values)

        for report in all_reports

        for values in report.get("results", {}).values()

        if isinstance(values, list)

    )



    high_risk = sum(

        1 for report in all_reports

        if str(report.get("risk_level", "")).startswith("HIGH")

    )



    medium_risk = sum(

        1 for report in all_reports

        if str(report.get("risk_level", "")).startswith("MEDIUM")

    )



    low_risk = sum(

        1 for report in all_reports

        if str(report.get("risk_level", "")).startswith("LOW")

    )



    return render_template(

        "dashboard.html",

        total_scans=total_scans,

        total_findings=total_findings,

        high_risk=high_risk,

        medium_risk=medium_risk,

        low_risk=low_risk,

        recent_reports=all_reports[:5]

    )





# --------------------------------------------------

# All reports

# --------------------------------------------------



@app.route("/reports")

def reports():

    report_files = []

    report_paths = glob.glob(os.path.join(REPORT_FOLDER, "*.json"))



    for file_path in report_paths:

        try:

            with open(file_path, "r", encoding="utf-8") as f:

                report = json.load(f)



            if not isinstance(report, dict):

                continue



            report["_report_id"] = os.path.basename(file_path)

            report_files.append(report)



        except (OSError, json.JSONDecodeError) as exc:

            print("Could not read report:", exc)



    report_files.sort(

        key=lambda report: report.get("date", ""),

        reverse=True

    )



    return render_template(

        "reports.html",

        reports=report_files,

        total_reports=len(report_files)

    )





# --------------------------------------------------

# View individual report

# --------------------------------------------------



@app.route("/report/<filename>")

def report_detail(filename):

    if (

        filename != os.path.basename(filename)

        or not filename.endswith(".json")

    ):

        return "Invalid report filename", 400



    report_path = os.path.join(REPORT_FOLDER, filename)



    if not os.path.isfile(report_path):

        return "Report not found", 404



    try:

        with open(report_path, "r", encoding="utf-8") as f:

            report = json.load(f)



        if not isinstance(report, dict):

            return "Invalid report data", 400



        report_results = report.get("results", {})



        if not isinstance(report_results, dict):

            report_results = {}



        safe_results = mask_results(report_results)



        total = sum(

            len(values)

            for values in safe_results.values()

            if isinstance(values, list)

        )



        return render_template(

            "report_detail.html",

            report=report,

            results=safe_results,

            total=total

        )



    except (OSError, json.JSONDecodeError, TypeError) as exc:

        print("Could not open report:", exc)

        return "Could not read this report", 500





# --------------------------------------------------

# Download masked JSON report

# --------------------------------------------------



@app.route("/download-report/<filename>")

def download_report(filename):

    if (

        filename != os.path.basename(filename)

        or not filename.endswith(".json")

    ):

        return "Invalid report filename", 400



    report_path = os.path.join(REPORT_FOLDER, filename)



    if not os.path.isfile(report_path):

        return "Report not found", 404



    try:

        with open(report_path, "r", encoding="utf-8") as f:

            report = json.load(f)



        if not isinstance(report, dict):

            return "Invalid report data", 400



        report_results = report.get("results", {})



        if not isinstance(report_results, dict):

            report_results = {}



        safe_report = {

            "file_name": report.get("file_name", "Unknown"),

            "date": report.get("date", "Unknown"),

            "risk_level": report.get("risk_level", "UNKNOWN"),

            "results": mask_results(report_results)

        }



        # Temporary download file

        with tempfile.NamedTemporaryFile(

            mode="w",

            encoding="utf-8",

            suffix=".json",

            prefix="DataSniff_",

            delete=False,

            dir=REPORT_FOLDER

        ) as temp_file:

            json.dump(

                safe_report,

                temp_file,

                indent=4,

                ensure_ascii=False

            )

            download_path = temp_file.name



        response = send_file(

            download_path,

            as_attachment=True,

            download_name="DataSniff_Report.json",

            mimetype="application/json"

        )



        @response.call_on_close

        def cleanup_download():

            try:

                if os.path.isfile(download_path):

                    os.remove(download_path)

            except OSError as exc:

                print("Temporary download cleanup error:", exc)



        return response



    except (OSError, json.JSONDecodeError, TypeError) as exc:

        print("Report download error:", exc)

        return "Could not download report", 500





# --------------------------------------------------

# Delete report - POST only

# --------------------------------------------------



@app.route("/delete-report/<filename>", methods=["POST"])

def delete_report(filename):

    if (

        filename != os.path.basename(filename)

        or not filename.endswith(".json")

    ):

        return "Invalid report filename", 400



    path = os.path.join(REPORT_FOLDER, filename)



    if not os.path.isfile(path):

        return "Report not found", 404



    try:

        os.remove(path)

    except OSError as exc:

        print("Could not delete report:", exc)

        return "Could not delete report", 500



    return redirect("/reports")





# --------------------------------------------------

# Scan uploaded file

# --------------------------------------------------



@app.route("/scan-file", methods=["POST"])

def scan():

    uploaded_file = request.files.get("logfile")



    if uploaded_file is None or not uploaded_file.filename:

        return render_template(

            "scan.html",

            error="Please select a file to scan."

        ), 400



    original_name = secure_filename(uploaded_file.filename)



    if not original_name:

        return render_template(

            "scan.html",

            error="Invalid filename. Please select another file."

        ), 400



    if not allowed_file(original_name):

        return render_template(

            "scan.html",

            error="Unsupported file type. Upload TXT, LOG or JSON files only."

        ), 400



    path = os.path.join(

        UPLOAD_FOLDER,

        uuid.uuid4().hex + "_" + original_name

    )



    try:

        uploaded_file.save(path)



        actual_size = os.path.getsize(path)



        if actual_size > MAX_FILE_SIZE:

            return render_template(

                "scan.html",

                error="File is too large. Maximum allowed size is 10 MB."

            ), 413



        if actual_size == 0:

            return render_template(

                "scan.html",

                error="The selected file is empty."

            ), 400



        results = scan_file(path)



        # Remove entropy matches that duplicate known sensitive findings

        
        # Remove entropy matches that duplicate known sensitive findings
        specific_categories = [
            "Emails",
            "IP Addresses",
            "Passwords",
            "API Keys",
            "GitHub Tokens",
            "Phone Numbers",
            "AWS Access Keys",
            "JWT Tokens",
            "Database Connection Strings",
            "Private Key Blocks",
        ]

        known_secrets = [
            str(value).strip()
            for category in specific_categories
            for value in results.get(category, [])
            if str(value).strip()
        ]

        entropy_values = results.get("High Entropy Strings", [])

        filtered_entropy = []

        for entropy_value in entropy_values:
            candidate = str(entropy_value).strip()

            # Keep empty or very short values out of duplicate matching.
            if not candidate:
                continue

            is_duplicate = False

            if len(candidate) >= 8:
                for secret in known_secrets:
                    if (
                        candidate.lower() in secret.lower()
                        or secret.lower() in candidate.lower()
                    ):
                        is_duplicate = True
                        break

            if not is_duplicate:
                filtered_entropy.append(entropy_value)

        results["High Entropy Strings"] = filtered_entropy

        # Remove duplicates within categories

        for category, values in results.items():

            results[category] = sorted(set(values))



        total = sum(

            len(values)

            for values in results.values()

        )



        if total == 0:

            risk = "LOW 🟢"

        elif total <= 5:

            risk = "MEDIUM 🟡"

        else:

            risk = "HIGH 🔴"



        safe_results = mask_results(results)



        save_report(original_name, safe_results, risk)



        return render_template(

            "result.html",

            results=safe_results,

            total=total,

            risk=risk

        )



    except (OSError, UnicodeError, ValueError, TypeError) as exc:

        print("File processing error:", exc)



        return render_template(

            "scan.html",

            error="Could not process this file. Please check the file and retry."

        ), 400



    finally:

        if os.path.isfile(path):

            try:

                os.remove(path)

            except OSError as exc:

                print("Could not remove uploaded file:", exc)





# --------------------------------------------------

# Run application

# --------------------------------------------------



if __name__ == "__main__":

    app.run(debug=False)
