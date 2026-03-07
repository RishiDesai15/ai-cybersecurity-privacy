
from typing import Dict, Any, List

# Ordered from highest to lowest severity
_REASON_CHECKS = [
    ("dmarc_fail",           "Policy alignment failed (DMARC=fail) — sender's domain cannot be trusted."),
    ("spf_fail",             "Sender authentication failed (SPF=fail) — email may be spoofed."),
    ("dkim_fail",            "Signature validation failed (DKIM=fail) — message integrity cannot be verified."),
    ("idn_suspect",          "Suspicious internationalised (IDN/punycode) domain detected — possible lookalike attack."),
    ("link_anchor_mismatch", "Link display text and actual destination domain do not match — classic phishing deception."),
    ("suspicious_tld",       "At least one link uses an unusual/free TLD commonly associated with phishing."),
    ("urgent_language",      "Urgent or coercive language detected — designed to pressure you into acting quickly."),
    ("attachment_hint",      "Email references an attachment — be cautious about opening unexpected files."),
    ("subject_homoglyph",    "Subject line contains look-alike (homoglyph) characters — possible identity spoofing."),
    ("subject_all_caps",     "Subject contains multiple ALL-CAPS words — common attention-grabbing phishing tactic."),
    ("free_email_sender",    "Sender is using a free/consumer email provider — atypical for official communications."),
]

_RISK_KEYWORDS = [
    "urgent", "verify", "password", "account", "update", "click",
    "immediately", "suspended", "confirm", "validate", "limited",
    "24 hours", "action required", "login", "secure", "bank",
]


def build_explanation(feats: Dict[str, Any], _subject: str, _body: str) -> List[str]:
    """Return a ranked list of human-readable reasons the email may be phishing."""
    reasons: List[str] = []
    for key, message in _REASON_CHECKS:
        if feats.get(key):
            reasons.append(message)

    # Dynamic: high link density
    density = feats.get("link_density", 0)
    if density and density > 5:
        reasons.append(f"High link density ({density:.1f} links per 100 words) detected.")

    # Dynamic: many links
    lc = feats.get("link_count", 0)
    if lc and lc > 10:
        reasons.append(f"Email contains {lc} links — unusually high for a legitimate message.")

    if not reasons:
        reasons.append("No strong phishing signals detected in headers, links, or language.")

    return reasons


def highlight_tokens_simple(text: str, top_k: int = 10) -> List[Dict]:
    """Find ALL occurrences of risk keywords in the text body.

    Returns a list of {token, start, end} dicts sorted by position,
    capped at *top_k* to avoid overwhelming the UI.
    """
    found: List[Dict] = []
    lower = text.lower()
    for kw in _RISK_KEYWORDS:
        start = 0
        while True:
            idx = lower.find(kw, start)
            if idx == -1:
                break
            found.append({"token": kw, "start": idx, "end": idx + len(kw)})
            start = idx + 1
            if len(found) >= top_k * 3:  # safety cap before sort
                break

    # Sort by position, deduplicate overlapping spans, cap
    found.sort(key=lambda x: x["start"])
    deduped: List[Dict] = []
    last_end = -1
    for hit in found:
        if hit["start"] >= last_end:
            deduped.append(hit)
            last_end = hit["end"]
    return deduped[:top_k]
