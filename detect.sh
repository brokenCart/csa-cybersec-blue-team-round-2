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
BOLD_RED = "\033[1;31m"
BOLD = "\033[1m"
CYAN = "\033[36m"
RESET = "\033[0m"


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


def record_attempt(attempts, ip, timestamp):
    """Add one attempt to an IP's count and update its first and last timestamps."""
    if ip not in attempts:
        attempts[ip] = {"count": 0, "first": timestamp, "last": timestamp}
    attempts[ip]["count"] += 1
    attempts[ip]["last"] = timestamp


def detect_repeated_status(lines, target_status, threshold):
    """Return {ip: details} for each IP with at least threshold target_status responses."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, _, status = parsed
        if status == target_status:
            record_attempt(attempts, ip, timestamp)
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
        ip, timestamp, request, _ = parsed
        if any(pattern in request for pattern in SQL_INJECTION_PATTERNS):
            record_attempt(attempts, ip, timestamp)
    return attempts


def detect_directory_traversal(lines):
    """Return {ip: details} for each IP whose requests contain ../"""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, _ = parsed
        if DIRECTORY_TRAVERSAL_REGEX.search(request):
            record_attempt(attempts, ip, timestamp)
    return attempts


def detect_sensitive_files(lines):
    """Return {ip: details} for each IP whose requests target a sensitive file."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, request, _ = parsed
        if SENSITIVE_FILE_REGEX.search(request):
            record_attempt(attempts, ip, timestamp)
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


def print_alerts(attackers, attack_name, attempt_label):
    """Print an alert and the attack details for each attacker of one attack type."""
    for ip, details in attackers.items():
        tag = colorize("[ALERT]", BOLD_RED)
        message = colorize(
            f"{attack_name} from {ip} ({details['count']} {attempt_label})", BOLD
        )
        print(f"{tag} {message}")
        print(f"  {colorize('Attacker IP:', CYAN)} {ip}")
        print(f"  {colorize('First Attempt:', CYAN)} {details['first']}")
        print(f"  {colorize('Last Attempt:', CYAN)} {details['last']}")
        print(f"  {colorize('Total Attempts:', CYAN)} {details['count']}")


def print_multiple_attack_alerts(attackers):
    """Print an alert and the attack details for each IP using several attack types.

    Each type's count is shown separately rather than as a total, because one
    request can count towards two types (an SQL injection that returns 403).
    """
    for ip, details in attackers.items():
        tag = colorize("[ALERT]", BOLD_RED)
        message = colorize(
            f"Multiple attack types from {ip} ({len(details['types'])} attack types)",
            BOLD,
        )
        attack_types = ", ".join(
            f"{name} ({count})" for name, count in details["types"].items()
        )
        print(f"{tag} {message}")
        print(f"  {colorize('Attacker IP:', CYAN)} {ip}")
        print(f"  {colorize('Attack Types:', CYAN)} {attack_types}")
        print(f"  {colorize('First Attempt:', CYAN)} {details['first']}")
        print(f"  {colorize('Last Attempt:', CYAN)} {details['last']}")


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
    print_alerts(brute_force_attackers, "Brute force", "failed logins")
    print_alerts(sql_injection_attackers, "SQL injection", "attempts")
    print_alerts(directory_traversal_attackers, "Directory traversal", "attempts")
    print_alerts(repeated_403_attackers, "Repeated 403 responses", "responses")
    print_alerts(sensitive_file_attackers, "Sensitive file access", "requests")
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
