"""
SIEM Alert Engine
Polls Elasticsearch every 10 seconds, evaluates detection rules,
writes alerts to logs/alerts.log in JSON format.

Run: python3 alerts.py
"""

import json
import time
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("[!] Install dependency: pip install elasticsearch")
    raise

# ── CONFIG ────────────────────────────────────────────────────────────────────
ES_URL        = os.getenv("ES_URL", "http://localhost:9200")
INDEX         = "siem-logs-*"
ALERTS_LOG    = Path(__file__).parent / "logs" / "alerts.log"
BLOCKLIST     = Path(__file__).parent / "logs" / "blocklist.json"
POLL_INTERVAL = 10   # seconds between each rule evaluation
LOOKBACK      = 120  # seconds of history to scan per rule run

# ── RULE THRESHOLDS ───────────────────────────────────────────────────────────
RULES = {
    "BRUTE_FORCE":       {"failed_in_window": 10,  "window_sec": 60,  "severity": "HIGH"},
    "BURST_ATTACK":      {"failed_in_window": 30,  "window_sec": 60,  "severity": "CRITICAL"},
    "ROOT_LOGIN":        {"severity": "CRITICAL"},
    "MAX_AUTH_EXCEEDED": {"severity": "HIGH"},
    "PREAUTH_STORM":     {"count": 5,  "window_sec": 60,  "severity": "MEDIUM"},
}

# ── STATE: track already-fired alerts to avoid duplicates ────────────────────
# key = (rule_name, ip_or_identifier), value = last fired epoch
_fired: dict = {}
COOLDOWN = 60  # seconds before same alert can fire again for same IP


def cooldown_ok(rule: str, key: str) -> bool:
    ck = (rule, key)
    last = _fired.get(ck, 0)
    if time.time() - last >= COOLDOWN:
        _fired[ck] = time.time()
        return True
    return False


# ── ALERT WRITER ─────────────────────────────────────────────────────────────
def write_alert(rule: str, severity: str, src_ip: str, detail: dict):
    alert = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "rule":       rule,
        "severity":   severity,
        "src_ip":     src_ip,
        **detail
    }
    with open(ALERTS_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    tag = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "🔵")
    print(f"{tag} [{severity}] {rule} — {src_ip} — {detail}")


# ── BLOCKLIST ─────────────────────────────────────────────────────────────────
def load_blocklist() -> dict:
    if BLOCKLIST.exists():
        with open(BLOCKLIST) as f:
            return json.load(f)
    return {}


def block_ip(ip: str, reason: str, severity: str):
    bl = load_blocklist()
    if ip not in bl:
        bl[ip] = {
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "reason":     reason,
            "severity":   severity,
        }
        with open(BLOCKLIST, "w") as f:
            json.dump(bl, f, indent=2)
        print(f"🚫 BLOCKED {ip} — {reason}")


# ── ELASTICSEARCH HELPERS ─────────────────────────────────────────────────────
def now_minus(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def es_count_failed_by_ip(es: Elasticsearch, window_sec: int) -> list:
    """Return IPs and their failed login count within the window."""
    result = es.search(
        index=INDEX,
        size=0,
        query={
            "bool": {
                "filter": [
                    {"term":  {"event_type.keyword": "failed_password"}},
                    {"range": {"@timestamp": {"gte": now_minus(window_sec)}}}
                ]
            }
        },
        aggs={
            "by_ip": {
                "terms": {"field": "src_ip.keyword", "size": 100},
                "aggs": {
                    "usernames": {"terms": {"field": "username.keyword", "size": 5}}
                }
            }
        }
    )
    return result["aggregations"]["by_ip"]["buckets"]


def es_root_logins(es: Elasticsearch) -> list:
    """Return accepted root logins in the last LOOKBACK window."""
    result = es.search(
        index=INDEX,
        size=10,
        query={
            "bool": {
                "filter": [
                    {"term":  {"username.keyword": "root"}},
                    {"terms": {"event_type.keyword": ["accepted_password", "accepted_publickey"]}},
                    {"range": {"@timestamp": {"gte": now_minus(LOOKBACK)}}}
                ]
            }
        },
        source=["src_ip", "auth_method", "@timestamp", "event_type"]
    )
    return [h["_source"] for h in result["hits"]["hits"]]


def es_max_auth_exceeded(es: Elasticsearch) -> list:
    """Return max_auth_exceeded events in the last LOOKBACK window."""
    result = es.search(
        index=INDEX,
        size=20,
        query={
            "bool": {
                "filter": [
                    {"term":  {"event_type.keyword": "max_auth_exceeded"}},
                    {"range": {"@timestamp": {"gte": now_minus(LOOKBACK)}}}
                ]
            }
        },
        source=["src_ip", "username", "@timestamp"]
    )
    return [h["_source"] for h in result["hits"]["hits"]]


def es_preauth_by_ip(es: Elasticsearch, window_sec: int) -> list:
    """Return IPs with preauth disconnects in window."""
    result = es.search(
        index=INDEX,
        size=0,
        query={
            "bool": {
                "filter": [
                    {"term":  {"event_type.keyword": "preauth_disconnect"}},
                    {"range": {"@timestamp": {"gte": now_minus(window_sec)}}}
                ]
            }
        },
        aggs={
            "by_ip": {"terms": {"field": "src_ip.keyword", "size": 100}}
        }
    )
    return result["aggregations"]["by_ip"]["buckets"]


# ── RULE EVALUATORS ───────────────────────────────────────────────────────────
def rule_brute_force(es: Elasticsearch):
    cfg = RULES["BRUTE_FORCE"]
    for bucket in es_count_failed_by_ip(es, cfg["window_sec"]):
        ip    = bucket["key"]
        count = bucket["doc_count"]
        if count >= cfg["failed_in_window"] and cooldown_ok("BRUTE_FORCE", ip):
            users = [u["key"] for u in bucket["usernames"]["buckets"]]
            write_alert("BRUTE_FORCE", cfg["severity"], ip, {
                "failed_attempts": count,
                "window_sec":      cfg["window_sec"],
                "targeted_users":  users,
                "message":         f"{count} failed logins in {cfg['window_sec']}s"
            })
            # Auto-block if HIGH
            block_ip(ip, f"Brute force: {count} attempts in {cfg['window_sec']}s", cfg["severity"])


def rule_burst_attack(es: Elasticsearch):
    cfg = RULES["BURST_ATTACK"]
    for bucket in es_count_failed_by_ip(es, cfg["window_sec"]):
        ip    = bucket["key"]
        count = bucket["doc_count"]
        if count >= cfg["failed_in_window"] and cooldown_ok("BURST_ATTACK", ip):
            users = [u["key"] for u in bucket["usernames"]["buckets"]]
            write_alert("BURST_ATTACK", cfg["severity"], ip, {
                "failed_attempts": count,
                "window_sec":      cfg["window_sec"],
                "targeted_users":  users,
                "message":         f"Burst: {count} failed logins in {cfg['window_sec']}s"
            })
            block_ip(ip, f"Burst attack: {count} attempts in {cfg['window_sec']}s", cfg["severity"])


def rule_root_login(es: Elasticsearch):
    cfg = RULES["ROOT_LOGIN"]
    for event in es_root_logins(es):
        ip = event.get("src_ip", "unknown")
        ts = event.get("@timestamp", "")
        if cooldown_ok("ROOT_LOGIN", ip):
            write_alert("ROOT_LOGIN", cfg["severity"], ip, {
                "username":    "root",
                "auth_method": event.get("auth_method", "unknown"),
                "event_time":  ts,
                "message":     "Root login accepted — immediate investigation required"
            })


def rule_max_auth(es: Elasticsearch):
    cfg = RULES["MAX_AUTH_EXCEEDED"]
    for event in es_max_auth_exceeded(es):
        ip = event.get("src_ip", "unknown")
        if cooldown_ok("MAX_AUTH_EXCEEDED", ip):
            write_alert("MAX_AUTH_EXCEEDED", cfg["severity"], ip, {
                "username": event.get("username", "unknown"),
                "message":  "Max authentication attempts exceeded"
            })


def rule_preauth_storm(es: Elasticsearch):
    cfg = RULES["PREAUTH_STORM"]
    for bucket in es_preauth_by_ip(es, cfg["window_sec"]):
        ip    = bucket["key"]
        count = bucket["doc_count"]
        if count >= cfg["count"] and cooldown_ok("PREAUTH_STORM", ip):
            write_alert("PREAUTH_STORM", cfg["severity"], ip, {
                "preauth_disconnects": count,
                "window_sec":          cfg["window_sec"],
                "message":             f"{count} preauth disconnects — scanning detected"
            })


# ── MAIN LOOP ─────────────────────────────────────────────────────────────────
def main():
    print(f"[*] SIEM Alert Engine starting — polling every {POLL_INTERVAL}s")
    print(f"[*] Elasticsearch: {ES_URL}")
    print(f"[*] Alerts log:    {ALERTS_LOG}")
    print(f"[*] Blocklist:     {BLOCKLIST}\n")

    # Wait for Elasticsearch
    es = Elasticsearch(ES_URL)
    for i in range(20):
        try:
            es.ping()
            print("[*] Connected to Elasticsearch\n")
            break
        except Exception:
            print(f"[*] Waiting for Elasticsearch... ({i+1}/20)")
            time.sleep(3)

    ALERTS_LOG.parent.mkdir(exist_ok=True)

    while True:
        try:
            rule_brute_force(es)
            rule_burst_attack(es)
            rule_root_login(es)
            rule_max_auth(es)
            rule_preauth_storm(es)
        except Exception as e:
            print(f"[!] Rule evaluation error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
