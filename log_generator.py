"""
SIEM Log Generator
Appends a realistic SSH auth log entry every 3 seconds to logs/a.log
Run: python3 log_generator.py
"""

import random
import time
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).parent / "logs" / "a.log"
INTERVAL = 3  # seconds between entries

USERS    = ["admin", "root", "test", "guest", "ubuntu", "deploy", "oracle"]
IPS      = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "9.9.9.9", "5.5.5.5",
            "45.33.32.156", "192.168.1.105", "10.0.0.22", "8.8.8.8"]
SERVICES = ["sshd", "auth", "app"]
HOSTNAME = "server1"

# 70% of attempts are failures, 30% success — realistic brute-force traffic
EVENTS = [
    ("failed", "invalid", 70),
    ("accepted", "valid",  30),
]

def weighted_event():
    roll = random.randint(1, 100)
    return ("failed", "invalid") if roll <= 70 else ("accepted", "valid")

def make_log_line():
    now        = datetime.now().strftime("%b %d %H:%M:%S")
    service    = random.choice(SERVICES)
    pid        = random.randint(1000, 9999)
    user       = random.choice(USERS)
    ip         = random.choice(IPS)
    port       = random.randint(1024, 65535)
    event_type, validity = weighted_event()

    if event_type == "accepted":
        msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    else:
        msg = f"Failed password for invalid user {user} from {ip} port {port} ssh2"

    return f"{now} {HOSTNAME} {service}[{pid}]: {msg}"

def main():
    print(f"Writing to {LOG_FILE} every {INTERVAL}s — press Ctrl+C to stop\n")
    count = 0
    while True:
        line = make_log_line()
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
        count += 1
        print(f"[{count:04d}] {line}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
