
import re
import math
import ipaddress
from collections import defaultdict


# --------------------------------------------------
# Sensitive data patterns
# --------------------------------------------------

PATTERNS = {
    "Emails": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "IP Addresses": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),

    "Passwords": re.compile(
        r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"'&,;]+)"""
    ),

    "API Keys": re.compile(
        r"""(?i)\b(?:api(?:[_-]?key)?|secret[_-]?key|access[_-]?key)\b"""
        r"""\s*[:=]\s*["']?([A-Za-z0-9_\-/.+=]{8,})"""
    ),

    "GitHub Tokens": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
    ),

    "Phone Numbers": re.compile(
        r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)"
    ),

    "AWS Access Keys": re.compile(
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),

    "JWT Tokens": re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    ),

    "Database Connection Strings": re.compile(
        r"""(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis)"""
        r"""://[^\s"'<>]+"""
    ),

    "Private Key Blocks": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        re.DOTALL
    ),

    "High Entropy Strings": re.compile(
        r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9])"
    ),
}


# --------------------------------------------------
# Entropy calculation
# --------------------------------------------------

def calculate_entropy(text):
    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )


def find_high_entropy_strings(text):
    matches = set()

    for match in PATTERNS["High Entropy Strings"].finditer(text):
        value = match.group(0)

        if len(value) >= 24 and calculate_entropy(value) >= 3.5:
            matches.add(value)

    return matches


# --------------------------------------------------
# IP validation
# --------------------------------------------------

def valid_ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ipaddress.AddressValueError:
        return False


# --------------------------------------------------
# Filter entropy matches covered by specific findings
# --------------------------------------------------

def overlaps_specific_finding(candidate, known_values):
    candidate_lower = candidate.lower()

    for known in known_values:
        known_lower = known.lower()

        # Filter only when the candidate is contained
        # within a specifically detected secret.
        if candidate_lower in known_lower:
            return True

    return False


# --------------------------------------------------
# Main scan function
# --------------------------------------------------

def scan_file(file_path):
    results = defaultdict(set)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()

    specific_categories = [
        category
        for category in PATTERNS
        if category != "High Entropy Strings"
    ]

    # Detect specific sensitive categories first.
    for category in specific_categories:
        pattern = PATTERNS[category]

        for match in pattern.finditer(content):
            if category in ("Passwords", "API Keys"):
                value = match.group(1)
            else:
                value = match.group(0)

            if not value:
                continue

            value = value.strip()

            if category == "IP Addresses" and not valid_ipv4(value):
                continue

            results[category].add(value)

    # Gather the detected values for duplicate filtering.
    known_values = {
        value
        for values in results.values()
        for value in values
    }

    entropy_values = find_high_entropy_strings(content)

    for candidate in entropy_values:
        if not overlaps_specific_finding(candidate, known_values):
            results["High Entropy Strings"].add(candidate)

    # Return unique findings in a predictable order.
    return {
        category: sorted(values)
        for category, values in results.items()
        if values
    }
