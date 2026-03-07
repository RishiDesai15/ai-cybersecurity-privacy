
import re
from urllib.parse import urlparse

try:
    import tldextract
    _USE_TLD = True
except ImportError:
    _USE_TLD = False

try:
    from bs4 import BeautifulSoup
    _USE_BS4 = True
except ImportError:
    _USE_BS4 = False


def _registered_domain(url: str) -> str:
    """Return the registered domain (e.g. 'example.com') for comparison."""
    if _USE_TLD:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    return urlparse(url).netloc.lower()


def extract_links(text: str):
    """Extract (anchor_text, href) pairs from plain text and HTML.

    For plain-text bodies the anchor_text equals the href since there is no
    separate visible label.  For HTML bodies we pick up the real anchor text
    so mismatch detection can work properly.
    """
    links: list[tuple[str, str]] = []

    # --- HTML anchor tags (have visible text + href) ---
    if _USE_BS4 and ("<a " in text.lower() or "<a\t" in text.lower()):
        soup = BeautifulSoup(text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith("http"):
                anchor_text = tag.get_text(strip=True) or href
                links.append((anchor_text, href))

    # --- Plain-text URLs (anchor == href) ---
    url_regex = r'(https?://[^\s)>"<]+)'
    for u in re.findall(url_regex, text, flags=re.I):
        links.append((u, u))

    # Deduplicate preserving order
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for a, h in links:
        if h not in seen:
            seen.add(h)
            deduped.append((a, h))
    return deduped


def anchor_domain_mismatch(anchor_text: str, href: str) -> bool:
    """Return True when the visible anchor text looks like a URL whose
    registered domain differs from the actual href domain."""
    try:
        # Only meaningful when anchor text itself looks like a URL / domain
        if not re.search(r'\b\w+\.[a-z]{2,}\b', anchor_text, re.I):
            return False
        anchor_url = anchor_text if anchor_text.startswith("http") else f"https://{anchor_text}"
        return _registered_domain(anchor_url) != _registered_domain(href)
    except (ValueError, AttributeError):
        return False


def contains_idn_homograph(href: str) -> bool:
    """Return True when the hostname contains a punycode (xn--) label,
    which is a common IDN homograph indicator."""
    try:
        host = urlparse(href).netloc.lower()
        # strip port if present
        host = host.split(":")[0]
        return any(label.startswith("xn--") for label in host.split("."))
    except (ValueError, AttributeError):
        return False


def extract_domains(text: str) -> list[str]:
    """Return unique registered domains found in text."""
    return list({
        _registered_domain(href) for _, href in extract_links(text) if href
    })
