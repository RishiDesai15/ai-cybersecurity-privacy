
from utils.url_tools import (
    extract_links,
    anchor_domain_mismatch,
    contains_idn_homograph,
    extract_domains,
)


# ---------------------------------------------------------------------------
# extract_links
# ---------------------------------------------------------------------------

class TestExtractLinks:
    def test_plain_url(self):
        links = extract_links("Visit https://example.com/path today.")
        assert len(links) == 1
        _, href = links[0]
        assert "example.com" in href

    def test_multiple_urls(self):
        text = "https://a.com http://b.org https://c.net"
        assert len(extract_links(text)) == 3

    def test_no_urls(self):
        assert extract_links("No links here.") == []

    def test_deduplicates(self):
        text = "https://example.com https://example.com"
        assert len(extract_links(text)) == 1

    def test_html_anchor_parsed(self):
        html = '<a href="https://evil.xyz/login">Click to verify your PayPal</a>'
        links = extract_links(html)
        assert any("evil.xyz" in h for _, h in links)

    def test_html_anchor_text_captured(self):
        html = '<a href="https://evil.xyz/login">paypal.com</a>'
        links = extract_links(html)
        anchors = [a for a, _ in links]
        assert "paypal.com" in anchors


# ---------------------------------------------------------------------------
# anchor_domain_mismatch
# ---------------------------------------------------------------------------

class TestAnchorDomainMismatch:
    def test_mismatch_detected(self):
        # Visible text says paypal.com but actual link goes to evil.xyz
        assert anchor_domain_mismatch("paypal.com", "https://evil.xyz/login") is True

    def test_no_mismatch_same_domain(self):
        assert anchor_domain_mismatch("paypal.com", "https://paypal.com/login") is False

    def test_non_url_anchor_no_flag(self):
        # Anchor text that is not a URL → should not flag
        assert anchor_domain_mismatch("Click here", "https://paypal.com") is False

    def test_empty_strings_no_crash(self):
        assert anchor_domain_mismatch("", "") is False


# ---------------------------------------------------------------------------
# contains_idn_homograph
# ---------------------------------------------------------------------------

class TestContainsIDN:
    def test_punycode_host_flagged(self):
        assert contains_idn_homograph("https://xn--pypl-qpad.com/login") is True

    def test_subdomain_punycode_flagged(self):
        assert contains_idn_homograph("https://secure.xn--pypl-qpad.com/") is True

    def test_normal_url_not_flagged(self):
        assert contains_idn_homograph("https://paypal.com/login") is False

    def test_url_without_path_no_crash(self):
        # Previously crashed with IndexError
        assert isinstance(contains_idn_homograph("https://example.com"), bool)

    def test_malformed_url_no_crash(self):
        assert isinstance(contains_idn_homograph("not-a-url"), bool)

    def test_empty_string_no_crash(self):
        assert isinstance(contains_idn_homograph(""), bool)


# ---------------------------------------------------------------------------
# extract_domains
# ---------------------------------------------------------------------------

class TestExtractDomains:
    def test_returns_unique_domains(self):
        text = "https://example.com/a https://example.com/b https://other.org"
        domains = extract_domains(text)
        assert len(domains) == 2
