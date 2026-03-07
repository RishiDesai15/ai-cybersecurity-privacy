
from typing import Dict, Any
import re
from utils.url_tools import extract_links, anchor_domain_mismatch, contains_idn_homograph

# Phishing urgency / social-engineering patterns
_URGENT_RE = re.compile(
    r"(urgent|verify\s*now|24\s*hours?|immediately|account\s*suspended"
    r"|confirm\s*your|validate\s*your|action\s*required|limited\s*time"
    r"|click\s*here\s*now|your\s*account\s*will)",
    re.I,
)

# Common free / disposable email domains used by attackers
_FREE_EMAIL_DOMAINS = frozenset([
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "icloud.com",
    "mail.com", "gmx.com",
])

# Very short TLDs often abused in phishing (xyz, tk, ml, cf, ga, gq …)
_SUSPICIOUS_TLD_RE = re.compile(r"\.(xyz|tk|ml|cf|ga|gq|club|top|work|site|online|click)(/|$)", re.I)

# Common homoglyph characters outside ASCII (quick check)
_HOMOGLYPH_RE = re.compile(r"[\u0430-\u044f\u00e0-\u00ff\u0100-\u017e]")


def _sender_domain(headers: Dict[str, Any]) -> str:
    """Extract the domain from the From header, lower-cased."""
    from_hdr = headers.get("From", "") or ""
    m = re.search(r"@([\w.-]+)", from_hdr)
    return m.group(1).lower() if m else ""


def quick_engineered_features(subject: str, body: str, headers: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a rich set of cybersecurity feature signals from email content."""
    # ---- Authentication ----
    auth = ""
    for key in ("Authentication-Results", "ARC-Authentication-Results"):
        auth += " " + (headers.get(key, "") or "")
    spf_fail  = "spf=fail"  in auth or "spf=softfail" in auth
    dkim_fail = "dkim=fail" in auth
    dmarc_fail = "dmarc=fail" in auth

    # ---- Link signals ----
    links = extract_links(body)
    mismatch_count = sum(1 for a, h in links if anchor_domain_mismatch(a, h))
    idn_count      = sum(1 for _, h in links if contains_idn_homograph(h))
    suspicious_tld_count = sum(1 for _, h in links if _SUSPICIOUS_TLD_RE.search(h))
    link_count = len(links)

    # ---- Sender reputation ----
    sender_domain = _sender_domain(headers)
    free_email_sender = sender_domain in _FREE_EMAIL_DOMAINS

    # ---- Subject signals ----
    subject_urgent = bool(_URGENT_RE.search(subject))
    subject_homoglyph = bool(_HOMOGLYPH_RE.search(subject))
    subject_all_caps_words = len(re.findall(r'\b[A-Z]{4,}\b', subject)) >= 2

    # ---- Body signals ----
    body_urgent = bool(_URGENT_RE.search(body))
    # HTML-only email (no plain-text fallback is a weak phish signal)
    appears_html = body.lstrip().startswith("<")
    # Attachment hint keywords in body
    attachment_hint = bool(re.search(r"(open\s*attachment|see\s*attached|attached\s*file|download\s*below)", body, re.I))
    # Excessive link density (links per 100 words)
    word_count = max(len(body.split()), 1)
    link_density = round(link_count / word_count * 100, 2)

    return {
        # Auth
        "spf_fail":  spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        # Links
        "link_count": link_count,
        "link_anchor_mismatch": mismatch_count > 0,
        "link_anchor_mismatch_count": mismatch_count,
        "idn_suspect": idn_count > 0,
        "idn_count": idn_count,
        "suspicious_tld": suspicious_tld_count > 0,
        "link_density": link_density,
        # Sender
        "free_email_sender": free_email_sender,
        "sender_domain": sender_domain,
        # Subject
        "subject_urgent": subject_urgent,
        "subject_homoglyph": subject_homoglyph,
        "subject_all_caps": subject_all_caps_words,
        # Body
        "urgent_language": body_urgent or subject_urgent,
        "appears_html": appears_html,
        "attachment_hint": attachment_hint,
        # Raw (for UI display)
        "links": [(a, h) for a, h in links[:20]],  # cap at 20 for API response size
    }
