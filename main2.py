from mitmproxy import http
import re

def load_blocked_keywords(file_path="blocked_categories.txt"):
    category_keywords = {}
    current_category = None

    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current_category = line[1:-1].lower()
                    category_keywords[current_category] = []
                elif current_category:
                    category_keywords[current_category].append(line.lower())
    except FileNotFoundError:
        pass

    # Flatten all keywords from all categories
    blocked_keywords = set()
    for keywords in category_keywords.values():
        blocked_keywords.update(keywords)
    return blocked_keywords

BLOCKED_KEYWORDS = load_blocked_keywords()

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()

    for keyword in BLOCKED_KEYWORDS:
        if keyword in host:
            flow.response = http.Response.make(
                403,
                b"Access to this site is blocked by WAF (category-based).",
                {"Content-Type": "text/plain"}
            )
            return
