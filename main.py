from mitmproxy import http

# Load blocked websites from a file
def load_blocked_sites(file_path="blocked_sites.txt"):
    try:
        with open(file_path, "r") as file:
            return set(line.strip().lower() for line in file if line.strip())
    except FileNotFoundError:
        return set()

BLOCKED_SITES = load_blocked_sites()

def request(flow: http.HTTPFlow):
    """Intercepts requests and blocks specific sites."""
    host = flow.request.pretty_host.lower()

    if host in BLOCKED_SITES:
        flow.response = http.Response.make(
            403,  # HTTP status code: Forbidden
            b"Access to this site is blocked by WAF.",
            {"Content-Type": "text/plain"}
        )
