#!/usr/bin/env python3
import argparse
import os
import re
import sys
from datetime import datetime

OUTPUT_FILE = "access.log"
DEFAULT_KEY = "MAYDAY"
BRUTE_FORCE_THRESHOLD = 5
REPEATED_403_THRESHOLD = 5
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
SQL_INJECTION_PATTERNS = ("DROP TABLE", "OR 1=1", "OR '1'='1'")
DIRECTORY_TRAVERSAL_REGEX = re.compile(r"\.\./")
SENSITIVE_FILES = (
    ".env",
    ".git",
    ".htaccess",
    ".htpasswd",
    "auth.log",
    "backup.sql",
    "config.php",
    "db.sqlite",
    "etc/hosts",
    "etc/passwd",
    "etc/shadow",
    "id_rsa",
    "win.ini",
    "wp-config.php",
)
# The lookarounds match whole names only, so .env does not match /.environment.
SENSITIVE_FILE_REGEX = re.compile(
    r"(?<![\w-])(?:" + "|".join(map(re.escape, SENSITIVE_FILES)) + r")(?![\w-])",
    re.IGNORECASE,
)
SOC_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
HIGH_SEVERITY_STATUS_PREFIXES = ("2", "5")  # 2xx and 5xx responses
RESET = "\033[0m"
SEVERITY_COLORS = {
    HIGH: "\033[1;31m",  # Red
    MEDIUM: "\033[1;38;5;208m",  # Orange
    LOW: "\033[1;33m",  # Yellow
}


def decrypt_line(line, shifts):
    """Return a decrypted copy of one line (bytes), restarting the key.

    Only A-Z and a-z are decrypted, and their case is preserved. Other bytes
    are unchanged and do not advance the key.
    """
    decrypted = bytearray(line)
    key_index = 0
    for position, char in enumerate(line):
        if ord("A") <= char <= ord("Z"):
            base = ord("A")
        elif ord("a") <= char <= ord("z"):
            base = ord("a")
        else:
            continue
        shift = shifts[key_index % len(shifts)]
        decrypted[position] = base + (char - base - shift) % 26
        key_index += 1
    return bytes(decrypted)


def parse_key(key):
    """Return the key as a list of shifts (A/a = 0 ... Z/z = 25).

    Raises ValueError if the key contains anything other than A-Z or a-z.
    """
    if not (key.isascii() and key.isalpha()):
        raise ValueError("key must contain only the letters A-Z or a-z")
    return [ord(char) - ord("A") for char in key.upper()]


def parse_log_line(line):
    """Return (ip, timestamp, request, status) from a log line, or None if malformed."""
    fields = line.split()
    quoted_parts = line.split('"')
    if len(fields) < 5 or len(quoted_parts) < 3 or not quoted_parts[2].split():
        return None
    timestamp = f"{fields[3].lstrip('[')} {fields[4].rstrip(']')}"
    return fields[0], timestamp, quoted_parts[1], quoted_parts[2].split()[0]


def record_attempt(attempts, ip, timestamp, request, status):
    """Add one attempt to an IP's details.

    Updates the count and the first and last timestamps, and keeps the request
    so that it can be reported on its own line.
    """
    if ip not in attempts:
        attempts[ip] = {"count": 0, "first": timestamp, "last": timestamp, "requests": []}
    attempts[ip]["count"] += 1
    attempts[ip]["last"] = timestamp
    attempts[ip]["requests"].append((timestamp, request, status))


def detect_repeated_status(lines, target_status, threshold):
    """Return {ip: details} for each IP with at least threshold target_status responses."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, status = parsed
        if status == target_status:
            record_attempt(attempts, ip, timestamp, request, status)
    return {
        ip: details
        for ip, details in attempts.items()
        if details["count"] >= threshold
    }


def detect_brute_force(lines):
    """Return {ip: details} for each IP with enough 401 responses."""
    return detect_repeated_status(lines, "401", BRUTE_FORCE_THRESHOLD)


def detect_repeated_403(lines):
    """Return {ip: details} for each IP with enough 403 responses."""
    return detect_repeated_status(lines, "403", REPEATED_403_THRESHOLD)


def detect_sql_injection(lines):
    """Return {ip: details} for each IP whose requests contain an SQL injection pattern."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, status = parsed
        if any(pattern in request for pattern in SQL_INJECTION_PATTERNS):
            record_attempt(attempts, ip, timestamp, request, status)
    return attempts


def detect_directory_traversal(lines):
    """Return {ip: details} for each IP whose requests contain ../"""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, status = parsed
        if DIRECTORY_TRAVERSAL_REGEX.search(request):
            record_attempt(attempts, ip, timestamp, request, status)
    return attempts


def detect_sensitive_files(lines):
    """Return {ip: details} for each IP whose requests target a sensitive file."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, status = parsed
        if SENSITIVE_FILE_REGEX.search(request):
            record_attempt(attempts, ip, timestamp, request, status)
    return attempts


def detect_multiple_attack_types(attacks):
    """Return {ip: details} for each IP flagged by two or more attack types.

    attacks maps each attack name to that attack's {ip: details} results.
    """
    by_ip = {}
    for attack_name, attackers in attacks.items():
        for ip, details in attackers.items():
            by_ip.setdefault(ip, {})[attack_name] = details

    multiple = {}
    for ip, ip_attacks in by_ip.items():
        if len(ip_attacks) < 2:
            continue
        firsts = [details["first"] for details in ip_attacks.values()]
        lasts = [details["last"] for details in ip_attacks.values()]
        multiple[ip] = {
            "types": {name: details["count"] for name, details in ip_attacks.items()},
            "first": min(firsts, key=parse_timestamp),
            "last": max(lasts, key=parse_timestamp),
        }
    return multiple


def parse_timestamp(timestamp):
    """Return a log timestamp as a datetime so that timestamps can be compared."""
    return datetime.strptime(timestamp, TIMESTAMP_FORMAT)


def colorize(text, color):
    """Return text in the given color, or unchanged if color should not be used.

    Color is only used on a terminal, so piped or redirected output stays plain
    and matches the alert format. Setting NO_COLOR also turns it off.
    """
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"{color}{text}{RESET}"
    return text


def format_timestamp(timestamp):
    """Return a log timestamp in the SOC format, such as 2024-03-15 09:22:45."""
    return parse_timestamp(timestamp).strftime(SOC_TIMESTAMP_FORMAT)


def format_time_range(details):
    """Return the first and last attempt times of an attacker's details."""
    first = format_timestamp(details["first"])
    last = format_timestamp(details["last"])
    return f"first attempt {first}, last attempt {last}"


def sanitize(text):
    """Replace non-printable characters, so log data cannot send terminal escape codes."""
    return "".join(char if char.isprintable() else "?" for char in text)


def print_alert(severity, timestamp, message):
    """Print one SOC-style alert line, with the severity colored."""
    severity_tag = colorize(f"[{severity}]", SEVERITY_COLORS[severity])
    print(f"[{format_timestamp(timestamp)}] {severity_tag} {message}")


def print_request_alerts(attackers, attack_name, other_severity):
    """Print one alert per matching request, in time order.

    A request is HIGH if it got a 2xx or 5xx response, and other_severity
    otherwise.
    """
    alerts = [
        (timestamp, ip, request, status)
        for ip, details in attackers.items()
        for timestamp, request, status in details["requests"]
    ]
    for timestamp, ip, request, status in sorted(
        alerts, key=lambda alert: parse_timestamp(alert[0])
    ):
        severity = HIGH if status.startswith(HIGH_SEVERITY_STATUS_PREFIXES) else other_severity
        message = f"{attack_name} detected from {ip}: {sanitize(request)} (status {status})"
        print_alert(severity, timestamp, message)


def print_repeated_status_alerts(attackers, attack_name, count_label):
    """Print one HIGH alert per IP, since these attacks are only found by counting."""
    for ip, details in attackers.items():
        message = (
            f"{attack_name} detected from {ip} "
            f"({details['count']} {count_label}, {format_time_range(details)})"
        )
        print_alert(HIGH, details["last"], message)


def print_multiple_attack_alerts(attackers):
    """Print one HIGH alert per IP using several attack types.

    Each type's count is shown separately rather than as a total, because one
    request can count towards two types (an SQL injection that returns 403).
    """
    for ip, details in attackers.items():
        attack_types = ", ".join(
            f"{name} ({count})" for name, count in details["types"].items()
        )
        message = (
            f"Multiple attack types detected from {ip}: {attack_types} "
            f"({format_time_range(details)})"
        )
        print_alert(HIGH, details["last"], message)


def main():
    """Decrypt the log, save it, and report attacks.

    Returns the exit status: 1 if an attack is detected, 0 if none is, or 2 on
    an error.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Decrypt a Vigenere-encrypted web server log and detect attacks in it."
    )
    parser.add_argument("encrypted_log", help="path to the encrypted log file")
    parser.add_argument(
        "key",
        nargs="?",
        default=DEFAULT_KEY,
        help=f"Vigenere key, letters only (default: {DEFAULT_KEY})",
    )
    args = parser.parse_args()

    try:
        shifts = parse_key(args.key)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    try:
        with open(args.encrypted_log, "rb") as source:
            decrypted = [decrypt_line(line, shifts) for line in source]
        with open(OUTPUT_FILE, "wb") as output:
            output.writelines(decrypted)
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    lines = [line.decode("ascii", errors="replace") for line in decrypted]
    brute_force_attackers = detect_brute_force(lines)
    sql_injection_attackers = detect_sql_injection(lines)
    directory_traversal_attackers = detect_directory_traversal(lines)
    repeated_403_attackers = detect_repeated_403(lines)
    sensitive_file_attackers = detect_sensitive_files(lines)
    multiple_attack_attackers = detect_multiple_attack_types(
        {
            "Brute force": brute_force_attackers,
            "SQL injection": sql_injection_attackers,
            "Directory traversal": directory_traversal_attackers,
            "Repeated 403": repeated_403_attackers,
            "Sensitive files": sensitive_file_attackers,
        }
    )
    print_repeated_status_alerts(brute_force_attackers, "Brute force", "failed logins")
    print_request_alerts(sql_injection_attackers, "SQL injection", LOW)
    print_request_alerts(directory_traversal_attackers, "Directory traversal", MEDIUM)
    print_repeated_status_alerts(repeated_403_attackers, "Repeated 403 responses", "responses")
    print_request_alerts(sensitive_file_attackers, "Sensitive file access", MEDIUM)
    print_multiple_attack_alerts(multiple_attack_attackers)

    if (
        brute_force_attackers
        or sql_injection_attackers
        or directory_traversal_attackers
        or repeated_403_attackers
        or sensitive_file_attackers
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
