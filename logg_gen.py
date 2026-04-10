import time
import random
import os
from datetime import datetime

LOG_FILE = "logs/a.log"
os.makedirs("logs", exist_ok=True)

# ── 1. FIXED RECURRING IPs (known actors, always present) ────────────────────
FIXED_IPS = {
    # Internal/corp — login regularly on a schedule
    "10.0.1.25":      {"type": "internal", "schedule": (60, 180),   "success_rate": 0.92},
    "192.168.1.105":  {"type": "internal", "schedule": (90, 240),   "success_rate": 0.88},
    "172.16.0.55":    {"type": "vpn",      "schedule": (120, 300),  "success_rate": 0.85},
    "34.201.12.45":   {"type": "legit",    "schedule": (180, 480),  "success_rate": 0.80},
    # Persistent attacker — slow scanning, always lurking
    "185.220.101.12": {"type": "tor",      "schedule": (30, 90),    "success_rate": 0.04},
    "45.155.205.233": {"type": "botnet",   "schedule": (20, 60),    "success_rate": 0.03},
    "103.214.132.55": {"type": "scanner",  "schedule": (15, 45),    "success_rate": 0.02},
}

# ── 2. RANDOM IP POOLS (pick fresh IPs each run) ─────────────────────────────
def random_ip():
    """Generate a plausible public IPv4 (avoids RFC1918/loopback/reserved)."""
    while True:
        a = random.randint(1, 254)
        if a in (10, 127, 169, 172, 192):
            continue
        b, c, d = random.randint(0, 254), random.randint(0, 254), random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"

# Pre-generate a pool of random IPs for the session
RANDOM_ATTACKER_POOL  = [random_ip() for _ in range(40)]
RANDOM_LEGIT_POOL     = [random_ip() for _ in range(10)]

# ── 3. USERNAME POOLS ─────────────────────────────────────────────────────────
USERNAMES = {
    "internal": ["alice", "bob", "charlie", "dave", "eve", "frank",
                 "svc_monitor", "svc_backup", "deploy", "jenkins"],
    "vpn":      ["alice", "bob", "carol", "dave", "remote_user"],
    "legit":    ["alice", "bob", "charlie", "dave", "svc_monitor"],
    "tor":      ["root", "admin", "administrator", "test", "ubuntu", "user"],
    "botnet":   ["root", "ubuntu", "pi", "support", "guest", "info",
                 "admin", "operator", "supervisor", "user"],
    "scanner":  ["oracle", "postgres", "mysql", "www-data", "ftp", "git",
                 "jenkins", "hadoop", "tomcat", "nagios", "deploy", "test"],
    "cloud":    ["ubuntu", "ec2-user", "centos", "ansible", "deploy", "user1"],
    "unknown":  ["root", "admin", "test", "user", "guest"],
}

LEGIT_TYPES = {"internal", "vpn", "legit"}

# ── 4. PORT POOLS ─────────────────────────────────────────────────────────────
LEGIT_PORTS    = [22, 2222]
ATTACKER_PORTS = [22, 2222, 22222, 2022, 8022, 1022]

# ── 5. AUTH METHOD WEIGHTS ────────────────────────────────────────────────────
def pick_method(ip_type):
    if ip_type in ("internal", "vpn"):
        return random.choices(["publickey", "password"], weights=[0.80, 0.20])[0]
    if ip_type == "legit":
        return random.choices(["publickey", "password"], weights=[0.60, 0.40])[0]
    return random.choices(["password", "publickey"], weights=[0.92, 0.08])[0]

# ── 6. LOG LINE BUILDERS ──────────────────────────────────────────────────────
def ts():
    return datetime.now().strftime("%Y %b %d %H:%M:%S")

def sha256():
    c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    return ''.join(random.choices(c, k=43))

_pid = [10000]
def next_pid():
    _pid[0] += random.randint(1, 5)
    return _pid[0]

def line_accepted_password(user, ip, port):
    return f"{ts()} server sshd[{next_pid()}]: Accepted password for {user} from {ip} port {port} ssh2"

def line_accepted_pubkey(user, ip, port):
    kt = random.choice(["RSA", "ECDSA", "ED25519"])
    return f"{ts()} server sshd[{next_pid()}]: Accepted publickey for {user} from {ip} port {port} ssh2: {kt} SHA256:{sha256()}"

def line_failed(user, ip, port, invalid=False):
    tag = "invalid user " if invalid else ""
    return f"{ts()} server sshd[{next_pid()}]: Failed password for {tag}{user} from {ip} port {port} ssh2"

def line_disconnect(user, ip):
    return f"{ts()} server sshd[{next_pid()}]: Disconnected from user {user} {ip} port 22"

def line_closed(ip):
    return f"{ts()} server sshd[{next_pid()}]: Connection closed by {ip} port {random.randint(1024,65000)}"

def line_pam(user, ip):
    n = random.randint(2, 5)
    return (f"{ts()} server sshd[{next_pid()}]: PAM {n} more authentication failures; "
            f"logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}")

def line_max_auth(ip):
    return (f"{ts()} server sshd[{next_pid()}]: error: maximum authentication attempts exceeded "
            f"for invalid user root from {ip} port 22 ssh2 [preauth]")

def line_preauth(ip):
    u = random.choice(["root", "admin", "test"])
    return f"{ts()} server sshd[{next_pid()}]: Disconnected from invalid user {u} {ip} port 22 [preauth]"

def line_sudo(user):
    action = random.choice(["session opened", "session closed"])
    return f"{ts()} server sudo: pam_unix(sudo:session): {action} for user root by {user}(uid=0)"

def line_new_session(user):
    return f"{ts()} server systemd-logind[{next_pid()}]: New session for user {user}."

def line_session_removed(user):
    return f"{ts()} server systemd-logind[{next_pid()}]: Session removed for user {user}."

def line_cron(user):
    cmd = random.choice(["/usr/bin/backup.sh", "/opt/monitor.py", "/usr/bin/check_disk.sh"])
    return f"{ts()} server CRON[{next_pid()}]: ({user}) CMD ({cmd})"

# ── 7. EVENT EMITTERS ─────────────────────────────────────────────────────────
def write(line):
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
        f.flush()
    print(line)

def emit_legit_login(ip, ip_type):
    """Successful login with realistic session events."""
    user    = random.choice(USERNAMES.get(ip_type, USERNAMES["legit"]))
    port    = random.choice(LEGIT_PORTS)
    method  = pick_method(ip_type)

    if method == "publickey":
        write(line_accepted_pubkey(user, ip, port))
    else:
        write(line_accepted_password(user, ip, port))

    write(line_new_session(user))

    # Maybe sudo
    if random.random() < 0.35:
        time.sleep(random.uniform(0.2, 1.0))
        write(line_sudo(user))

    # Maybe cron noise during session
    if random.random() < 0.2:
        time.sleep(random.uniform(1, 3))
        write(line_cron(user))

    # Session end
    session_len = random.uniform(5, 40)
    time.sleep(min(session_len, random.uniform(2, 6)))  # don't actually wait full session
    write(line_disconnect(user, ip))
    write(line_session_removed(user))

def emit_failed_login(ip, ip_type, burst=False):
    """Failed attempt(s) — attacker pattern."""
    user     = random.choice(USERNAMES.get(ip_type, USERNAMES["unknown"]))
    port     = random.choice(ATTACKER_PORTS)
    invalid  = random.random() < 0.30
    retries  = random.randint(1, 4) if burst else random.randint(1, 2)

    for i in range(retries):
        if i > 0:
            time.sleep(random.uniform(0.05, 0.4))
        write(line_failed(user, ip, port, invalid=invalid and i == 0))

    # Follow-up noise
    if retries >= 3 and random.random() < 0.5:
        write(line_pam(user, ip))
    if random.random() < 0.2:
        write(line_max_auth(ip))
    if random.random() < 0.25:
        write(line_preauth(ip))
    if random.random() < 0.15:
        write(line_closed(ip))

# ── 8. FIXED-IP SCHEDULER ────────────────────────────────────────────────────
class FixedIPScheduler:
    def __init__(self):
        self.next_fire = {}
        for ip, cfg in FIXED_IPS.items():
            lo, hi = cfg["schedule"]
            self.next_fire[ip] = time.time() + random.uniform(lo * 0.1, lo * 0.5)

    def due(self):
        now = time.time()
        return [ip for ip, t in self.next_fire.items() if now >= t]

    def reschedule(self, ip):
        lo, hi = FIXED_IPS[ip]["schedule"]
        self.next_fire[ip] = time.time() + random.uniform(lo, hi)

scheduler = FixedIPScheduler()

# ── 9. BURST STATE ────────────────────────────────────────────────────────────
class BurstState:
    active = False
    ip     = None
    count  = 0
    max    = 0

burst = BurstState()

def maybe_trigger_burst():
    if not burst.active and random.random() < 0.015:
        burst.active = True
        burst.ip     = random.choice(RANDOM_ATTACKER_POOL)
        burst.count  = 0
        burst.max    = random.randint(20, 60)
        print(f"\n[!] BURST started from {burst.ip} ({burst.max} attempts)\n")


# ── ALERT TEST SCENARIOS ──────────────────────────────────────────────────────
# These fire on a fixed schedule to guarantee alerts are triggered

SCENARIO_INTERVAL = 10   # seconds between forced scenarios
_last_scenario    = [0.0]

ALERT_ATTACK_IPS = ["6.6.6.6", "7.7.7.7", "66.66.66.66"]

def scenario_brute_force():
    """Send 15 rapid failed logins from one IP → triggers BRUTE_FORCE alert."""
    ip   = random.choice(ALERT_ATTACK_IPS)
    user = random.choice(["admin", "root", "ubuntu"])
    port = 22
    print(f"\n[SCENARIO] Brute force from {ip} (15 attempts)\n")
    for _ in range(15):
        write(line_failed(user, ip, port, invalid=True))
        time.sleep(0.1)

def scenario_burst():
    """Send 35 rapid failed logins → triggers BURST_ATTACK alert."""
    ip = "99.99.99.99"
    print(f"\n[SCENARIO] Burst attack from {ip} (35 attempts)\n")
    for _ in range(35):
        user = random.choice(["root", "admin", "test", "oracle"])
        write(line_failed(user, ip, 22, invalid=True))
        time.sleep(0.05)

def scenario_root_login():
    """Accepted root login → triggers ROOT_LOGIN alert."""
    ip = random.choice(ALERT_ATTACK_IPS)
    print(f"\n[SCENARIO] Root login from {ip}\n")
    write(line_accepted_password("root", ip, 22))
    write(line_new_session("root"))

def scenario_preauth_storm():
    """6 preauth disconnects from same IP → triggers PREAUTH_STORM alert."""
    ip = "55.55.55.55"
    print(f"\n[SCENARIO] Preauth storm from {ip} (6 disconnects)\n")
    for _ in range(6):
        write(line_preauth(ip))
        time.sleep(0.1)

def scenario_max_auth():
    """Max auth exceeded event."""
    ip = random.choice(ALERT_ATTACK_IPS)
    print(f"\n[SCENARIO] Max auth exceeded from {ip}\n")
    write(line_max_auth(ip))

SCENARIOS = [
    scenario_brute_force,
    scenario_burst,
    scenario_root_login,
    scenario_preauth_storm,
    scenario_max_auth,
]
_scenario_idx = [0]

def maybe_run_scenario():
    now = time.time()
    if now - _last_scenario[0] >= SCENARIO_INTERVAL:
        _last_scenario[0] = now
        for _ in range(2):
            fn = SCENARIOS[_scenario_idx[0] % len(SCENARIOS)]
            _scenario_idx[0] += 1
            fn()


# ── 10. MAIN LOOP ─────────────────────────────────────────────────────────────
def simulate():
    print("[*] Realistic SSH log generator started — Ctrl+C to stop")
    print(f"[*] Session random attacker pool: {len(RANDOM_ATTACKER_POOL)} IPs")
    print(f"[*] Session random legit pool:    {len(RANDOM_LEGIT_POOL)} IPs")
    print(f"[*] Alert scenarios fire every {SCENARIO_INTERVAL}s\n")

    tick = 0

    while True:
        tick += 1

        # ── A. Fire any scheduled fixed-IP events ──
        for ip in scheduler.due():
            cfg     = FIXED_IPS[ip]
            ip_type = cfg["type"]
            if random.random() < cfg["success_rate"]:
                emit_legit_login(ip, ip_type)
            else:
                emit_failed_login(ip, ip_type)
            scheduler.reschedule(ip)

        # ── B. Handle active burst ──
        if burst.active:
            emit_failed_login(burst.ip, "botnet", burst=True)
            burst.count += 1
            if burst.count >= burst.max:
                burst.active = False
                print(f"\n[*] Burst from {burst.ip} ended\n")
            time.sleep(random.uniform(0.05, 0.25))
            continue

        # ── C. Forced alert scenarios ──
        maybe_run_scenario()

        # ── D. Random background event ──
        roll = random.random()

        if roll < 0.55:
            ip      = random.choice(RANDOM_LEGIT_POOL)
            ip_type = random.choice(["legit", "internal", "vpn"])
            emit_legit_login(ip, ip_type)
            time.sleep(random.uniform(2, 8))

        elif roll < 0.80:
            ip      = random.choice(RANDOM_ATTACKER_POOL)
            ip_type = random.choice(["scanner", "botnet", "tor", "cloud", "unknown"])
            emit_failed_login(ip, ip_type)
            time.sleep(random.uniform(0.5, 3))

        elif roll < 0.90:
            ip      = random.choice(list(FIXED_IPS.keys())[:4])
            ip_type = FIXED_IPS[ip]["type"]
            user    = random.choice(USERNAMES.get(ip_type, USERNAMES["legit"]))
            port    = random.choice(LEGIT_PORTS)
            write(line_failed(user, ip, port, invalid=False))
            if random.random() < 0.75:
                time.sleep(random.uniform(2, 6))
                write(line_accepted_password(user, ip, port))
                write(line_new_session(user))
            time.sleep(random.uniform(1, 4))

        else:
            if random.random() < 0.5:
                u = random.choice(["root", "deploy", "svc_monitor"])
                write(line_cron(u))
            else:
                write(line_closed(random.choice(RANDOM_ATTACKER_POOL)))
            time.sleep(random.uniform(0.5, 2))

        # ── E. Random organic burst ──
        maybe_trigger_burst()

if __name__ == "__main__":
    simulate()