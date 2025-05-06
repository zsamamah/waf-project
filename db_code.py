from mitmproxy import http
import sqlite3
from datetime import datetime

LOG_FILE = "waf_block_log.txt"

def load_blocked_keywords_from_db(db_path="blocklist.db"):
    blocked_keywords = set()
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT keyword FROM blocked_keywords")
        rows = cursor.fetchall()
        blocked_keywords = {row[0].lower() for row in rows}
        conn.close()
    except Exception as e:
        print(f"Error loading blocklist from database: {e}")
    return blocked_keywords

def log_blocked_request(reason, detail):
    try:
        with open(LOG_FILE, "a") as log_file:
            log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Blocked: {reason}, Detail: {detail}\n"
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error writing to log file: {e}")

BLOCKED_KEYWORDS = load_blocked_keywords_from_db()

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()
    full_url = flow.request.pretty_url.lower()

    # Block by DB keywords
    for keyword in BLOCKED_KEYWORDS:
        if keyword in host:
            log_blocked_request("Blocked Keyword", f"{host} matched {keyword}")
            flow.response = http.Response.make(
                403,
                b"Blocked by WAF (host match)",
                {"Content-Type": "text/plain"}
            )
            return

    # Detect simple XSS: if both 'script' and 'alert' in URL
    if ("script" in full_url and "alert" in full_url):
        log_blocked_request("Blocked XSS", f"Suspicious URL: {full_url}")
        flow.response = http.Response.make(
            403,
            b"Blocked by WAF: XSS-like pattern detected in URL.",
            {"Content-Type": "text/plain"}
        )
        return
    if ("%27" in full_url) or ('%22' in full_url):
        log_blocked_request("Blocked SQL Injection", f"Suspicious URL: {full_url}")
        flow.response = http.Response.make(
            403,
            b"Blocked by WAF: SQL Injection -like pattern detected in URL.",
            {"Content-Type": "text/plain"}
        )
        return