import re
from collections import defaultdict

#---Constants---
LOG_FILE = "sample.log"
FAILED_CODES = {"401","403","404","500"}
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<request>[^"]+)"\s(?P<status>\d{3})'
)

def load_log(filepath):
    """
    Read a log file and return its lines.
    Args:
        filepath (str): Path to the log file.

    Returns:
        list: Lines from the file, or empty list on error.
    """
    try:
        with open(filepath,"r") as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"[ERROR]File not found: {filepath}")
        return []


def parse_log(lines):
    """
    Parse log lines and extract failed request events.
    Args:
        lines (list): Raw log lines.
    Returns:
        tuple: (defaultdict of IP fail counts, list of event tuples)
    """
    failed_ips = defaultdict(int)
    failed_events = []

    for line in lines:
        match = LOG_PATTERN.search(line)
        if not match:
            continue #skip malformed lines

        ip = match.group("ip")
        request = match.group("request")
        status = match.group("status")

        if status in FAILED_CODES:
            failed_ips[ip] += 1
            failed_events.append((ip,status,request))

    return failed_ips, failed_events

def print_report(failed_ips, failed_events):
    """
        Print a formatted summary report of failed requests.

        Args:
            failed_ips (dict): IP addresses and their fail counts.
            failed_events (list): Individual failed event tuples.

    """
    print("="*45)
    print("  LOG ANALYZER - FAILED REQUESTS")
    print("="*45)

    print("\n[+] Suspicious IPs and fail Counts:")
    sorted_ips = sorted(failed_ips.items(), key=lambda x:x[1], reverse=True)
    for ip, count in sorted_ips:
        print(f"{ip} {count} failed request(s)")

    print("\n[+] Event Detail:")
    for ip, status, request in failed_events:
        print(f" {ip:<18} | {status} | {request}")

    print("\n[+] Summary:")
    print(f" Total failed events: {len(failed_events)}")
    print(f" Unique suspicious IPs: {len(failed_ips)}")

def main():
    """Main entry point for the log analyzer."""
    lines = load_log(LOG_FILE)

    if not lines:
      return #exit cleanly if file couldn't be loaded

    failed_ips, failed_events = parse_log(lines)
    print_report(failed_ips, failed_events)

if __name__=="__main__":
    main()

