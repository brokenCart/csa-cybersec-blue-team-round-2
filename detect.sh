#!/usr/bin/env python3
import argparse
import os
import re
import sys

OUTPUT_FILE = "access.log"
DEFAULT_KEY = "MAYDAY"
BRUTE_FORCE_THRESHOLD = 5
SQL_INJECTION_PATTERNS = ("DROP TABLE", "OR 1=1", "OR '1'='1'")
DIRECTORY_TRAVERSAL_REGEX = re.compile(r"\.\./")
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


def detect_brute_force(lines):
    """Return {ip: details} for each IP with enough 401 responses."""
    attempts = {}
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, timestamp, _, status = parsed
        if status == "401":
            record_attempt(attempts, ip, timestamp)
    return {
        ip: details
        for ip, details in attempts.items()
        if details["count"] >= BRUTE_FORCE_THRESHOLD
    }


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
    print_alerts(brute_force_attackers, "Brute force", "failed logins")
    print_alerts(sql_injection_attackers, "SQL injection", "attempts")
    print_alerts(directory_traversal_attackers, "Directory traversal", "attempts")

    if brute_force_attackers or sql_injection_attackers or directory_traversal_attackers:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
