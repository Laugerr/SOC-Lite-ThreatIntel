import re
from urllib.parse import urlparse

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def detect_type(indicator: str) -> str:
    """Detect whether input is ip, domain, or url."""
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    if IP_RE.match(indicator) and all(0 <= int(x) <= 255 for x in indicator.split(".")):
        return "ip"
    return "domain"

def normalize_indicator(raw: str) -> str:
    """Normalize input for consistent scoring & storage."""
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urlparse(raw)
        path = p.path or "/"
        return f"{p.scheme}://{p.netloc}{path}"
    return raw.lower()