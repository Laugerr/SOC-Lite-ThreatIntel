def recommendation(level: str) -> str:
    if level == "CRITICAL":
        return "Block immediately. Investigate logs. Hunt related indicators. Consider incident response."
    if level == "HIGH":
        return "Consider blocking. Hunt for related activity. Add detection rules."
    if level == "MEDIUM":
        return "Monitor and enrich. Add to watchlist."
    return "Log for reference. No immediate action."

def make_alert_json(timestamp, indicator, ind_type, score, level, signals, intel):
    return {
        "timestamp": timestamp,
        "alert_type": "simulated_threat_intel_match",
        "indicator": {"value": indicator, "type": ind_type},
        "risk": {"score": score, "level": level},
        "signals": signals,
        "intel_context": intel,
        "recommendation": recommendation(level),
    }