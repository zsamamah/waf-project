from mitmproxy import http
import sqlite3

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

BLOCKED_KEYWORDS = load_blocked_keywords_from_db()

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()

    for keyword in BLOCKED_KEYWORDS:
        if keyword in host:
            flow.response = http.Response.make(
                403,
                b"Access to this site is blocked by WAF (DB-driven).",
                {"Content-Type": "text/plain"}
            )
            return
