from urllib.parse import urlparse

RISKY_KEYWORDS = {
    "login": 10,
    "verify": 10,
    "secure": 10,
    "update": 8,
    "invoice": 12,
    "payment": 12,
    "reset": 10,
    "password": 12,
    "wallet": 15,
}

def score_indicator(indicator: str, ind_type: str, intel: dict, history_df):
    score = 0
    signals = []

    # 1) Blocklist
    if intel.get("blocklisted"):
        score += 50
        signals.append({"signal": "Blocklisted indicator", "points": 50, "detail": "Found in local simulated blocklist"})

    # 2) Suspicious TLD
    if intel.get("suspicious_tld"):
        score += 15
        signals.append({"signal": "Suspicious TLD", "points": 15, "detail": f"TLD {intel.get('tld')} is flagged"})

    # 3) Provider heuristic
    if intel.get("provider") == "datacenter (simulated)":
        score += 10
        signals.append({"signal": "Datacenter hosting (simulated)", "points": 10, "detail": "Heuristic provider flag"})

    # 4) Keyword scoring (URL/domain text)
    text = indicator.lower()
    if ind_type == "url":
        p = urlparse(indicator)
        text = f"{p.netloc}{p.path}".lower()

    kw_points = 0
    hit = []
    for kw, pts in RISKY_KEYWORDS.items():
        if kw in text:
            kw_points += pts
            hit.append(kw)

    if kw_points:
        kw_points = min(25, kw_points)
        score += kw_points
        signals.append({"signal": "Risky keywords", "points": kw_points, "detail": f"Matched: {', '.join(hit)}"})

    # 5) “Newly seen” bonus
    seen = False
    if history_df is not None and not history_df.empty:
        seen = (history_df["indicator"] == indicator).any()

    if not seen:
        score += 5
        signals.append({"signal": "Newly seen indicator", "points": 5, "detail": "Not present in local history"})

    score = min(100, score)
    signals = sorted(signals, key=lambda x: x["points"], reverse=True)
    return score, signals

def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"