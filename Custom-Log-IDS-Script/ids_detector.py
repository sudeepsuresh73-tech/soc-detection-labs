#!/usr/bin/env python3
"""
ids_detector.py
----------------
Custom Log-based Intrusion Detection Script (Lab 5)

Reads a Linux auth.log file, finds SSH brute-force attempts
(repeated "Failed password" lines from the same source IP),
and prints an alert for any IP that crosses the threshold.

Usage:
    python3 ids_detector.py
    python3 ids_detector.py --log /var/log/auth.log --threshold 5
    python3 ids_detector.py --log /var/log/auth.log --output /var/log/ids_alerts.log
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime

FAILED_PASSWORD_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
INVALID_USER_RE = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")


def parse_log(log_file):
    """Parse the auth.log file and count failed attempts per source IP."""
    ip_counts = defaultdict(int)
    ip_users = defaultdict(set)
    ip_first_seen = {}
    ip_last_seen = {}
    total_lines = 0

    with open(log_file, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1

            match = FAILED_PASSWORD_RE.search(line)
            if match:
                ip = match.group(1)
                ip_counts[ip] += 1

                # Try to capture the username that was targeted
                user_match = re.search(r"for (?:invalid user )?(\S+) from", line)
                if user_match:
                    ip_users[ip].add(user_match.group(1))

                # Track timestamps if present at the start of the line
                ts_match = re.match(r"^(\S+\s+\d+\s+[\d:]+|\S+T[\d:.]+)", line)
                if ts_match:
                    ts = ts_match.group(1)
                    if ip not in ip_first_seen:
                        ip_first_seen[ip] = ts
                    ip_last_seen[ip] = ts

    return ip_counts, ip_users, ip_first_seen, ip_last_seen, total_lines


def generate_alerts(ip_counts, ip_users, ip_first_seen, ip_last_seen, threshold):
    """Generate alert strings for any IP at or above the threshold."""
    alerts = []
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1]):
        if count >= threshold:
            users = ", ".join(sorted(ip_users.get(ip, [])))
            first = ip_first_seen.get(ip, "unknown")
            last = ip_last_seen.get(ip, "unknown")
            alert = (
                f"[ALERT] Brute-force suspected from {ip} "
                f"- {count} failed attempts "
                f"- targeted user(s): {users or 'unknown'} "
                f"- first: {first} - last: {last}"
            )
            alerts.append(alert)
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Simple SSH brute-force log detector")
    parser.add_argument("--log", default="/var/log/auth.log", help="Path to auth.log")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts before alerting")
    parser.add_argument("--output", default=None, help="Optional file to append alerts to")
    args = parser.parse_args()

    print(f"[*] Scanning {args.log} (threshold = {args.threshold} failed attempts)")
    print(f"[*] Run time: {datetime.now().isoformat()}")
    print("-" * 70)

    try:
        ip_counts, ip_users, first_seen, last_seen, total_lines = parse_log(args.log)
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.log}")
        return
    except PermissionError:
        print(f"[!] Permission denied reading {args.log} - try running with sudo")
        return

    alerts = generate_alerts(ip_counts, ip_users, first_seen, last_seen, args.threshold)

    print(f"[*] Lines scanned: {total_lines}")
    print(f"[*] Unique source IPs with failed logins: {len(ip_counts)}")
    print("-" * 70)

    if not alerts:
        print("[*] No brute-force activity detected above threshold.")
    else:
        for alert in alerts:
            print(alert)

        if args.output:
            with open(args.output, "a") as out:
                out.write(f"\n--- Scan at {datetime.now().isoformat()} ---\n")
                for alert in alerts:
                    out.write(alert + "\n")
            print(f"\n[*] {len(alerts)} alert(s) written to {args.output}")

    print("-" * 70)
    print("[*] Scan complete.")


if __name__ == "__main__":
    main()
