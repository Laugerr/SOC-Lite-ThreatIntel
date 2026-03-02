import json
import os
from urllib.parse import urlparse

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

def _load_json(name: str):
    path = os.path.join(DATA_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

BAD_IPS = set(_load_json("known_bad_ips.json"))
BAD_DOMAINS = set(_load_json("known_bad_domains.json"))
SUSP_TLDS = set(_load_json("suspicious_tlds.json"))

def simulate_intel(indicator: str, ind_type: str) -> dict:
    """
    Simulated enrichment:
    - local blocklist hit
    - suspicious TLD flag
    - provider heuristic (simulated datacenter)
    """
    domain = None
    if ind_type == "url":
        domain = urlparse(indicator).netloc.lower()
    elif ind_type == "domain":
        domain = indicator.lower()

    tld = None
    if domain and "." in domain:
        tld = "." + domain.split(".")[-1]

    is_blocklisted = (
        (ind_type == "ip" and indicator in BAD_IPS) or
        (domain is not None and domain in BAD_DOMAINS)
    )

    suspicious_tld = bool(tld and tld in SUSP_TLDS)

    provider = "residential/unknown"
    if ind_type == "ip":
        last_octet = int(indicator.split(".")[-1])
        if last_octet % 7 == 0:
            provider = "datacenter (simulated)"

    return {
        "blocklisted": is_blocklisted,
        "tld": tld,
        "suspicious_tld": suspicious_tld,
        "provider": provider,
        "confidence": "simulated"
    }