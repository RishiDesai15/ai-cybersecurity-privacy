
from app.features import quick_engineered_features


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _feats(subject="", body="", headers=None):
    return quick_engineered_features(subject, body, headers or {})


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestReturnShape:
    def test_returns_dict(self):
        assert isinstance(_feats(), dict)

    def test_required_keys_present(self):
        f = _feats()
        required = {
            "spf_fail", "dkim_fail", "dmarc_fail",
            "link_count", "link_anchor_mismatch", "idn_suspect",
            "urgent_language", "links",
        }
        assert required.issubset(f.keys())


# ---------------------------------------------------------------------------
# Authentication signals
# ---------------------------------------------------------------------------

class TestAuthSignals:
    def test_spf_fail_detected(self):
        h = {"Authentication-Results": "mx.example.com; spf=fail"}
        assert _feats(headers=h)["spf_fail"] is True

    def test_spf_pass_not_flagged(self):
        h = {"Authentication-Results": "mx.example.com; spf=pass"}
        assert _feats(headers=h)["spf_fail"] is False

    def test_dkim_fail_detected(self):
        h = {"Authentication-Results": "dkim=fail"}
        assert _feats(headers=h)["dkim_fail"] is True

    def test_dmarc_fail_detected(self):
        h = {"Authentication-Results": "dmarc=fail"}
        assert _feats(headers=h)["dmarc_fail"] is True

    def test_no_auth_header_no_flags(self):
        f = _feats(headers={})
        assert f["spf_fail"] is False
        assert f["dkim_fail"] is False
        assert f["dmarc_fail"] is False


# ---------------------------------------------------------------------------
# Link signals
# ---------------------------------------------------------------------------

class TestLinkSignals:
    def test_link_count_plain_text(self):
        body = "Visit https://example.com and https://other.org today."
        assert _feats(body=body)["link_count"] == 2

    def test_no_links(self):
        f = _feats(body="No links here.")
        assert f["link_count"] == 0

    def test_idn_punycode_detected(self):
        # xn-- label in hostname
        body = "Click here: https://xn--paypa1.com/login"
        assert _feats(body=body)["idn_suspect"] is True

    def test_normal_domain_no_idn(self):
        body = "Click here: https://paypal.com/login"
        assert _feats(body=body)["idn_suspect"] is False

    def test_suspicious_tld_xyz(self):
        body = "Visit https://free-prize.xyz/claim"
        assert _feats(body=body)["suspicious_tld"] is True

    def test_normal_tld_not_flagged(self):
        body = "Visit https://example.com/page"
        assert _feats(body=body)["suspicious_tld"] is False


# ---------------------------------------------------------------------------
# Language / urgency signals
# ---------------------------------------------------------------------------

class TestUrgencySignals:
    def test_urgent_body(self):
        body = "Your account will be suspended immediately unless you verify now."
        assert _feats(body=body)["urgent_language"] is True

    def test_urgent_subject(self):
        f = _feats(subject="ACTION REQUIRED: Verify your account", body="Normal text.")
        assert f["subject_urgent"] is True

    def test_no_urgency(self):
        f = _feats(subject="Weekly newsletter", body="Here is this week's news.")
        assert f["urgent_language"] is False

    def test_attachment_hint(self):
        body = "Please open attachment and review the document."
        assert _feats(body=body)["attachment_hint"] is True


# ---------------------------------------------------------------------------
# Sender signals
# ---------------------------------------------------------------------------

class TestSenderSignals:
    def test_free_email_sender_gmail(self):
        h = {"From": "support@gmail.com"}
        assert _feats(headers=h)["free_email_sender"] is True

    def test_corporate_sender_not_flagged(self):
        h = {"From": "no-reply@amazon.com"}
        assert _feats(headers=h)["free_email_sender"] is False

    def test_sender_domain_extracted(self):
        h = {"From": '"Acme" <info@acme.co.uk>'}
        assert _feats(headers=h)["sender_domain"] == "acme.co.uk"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_inputs_no_crash(self):
        f = _feats()
        assert isinstance(f, dict)

    def test_very_long_body(self):
        # Use unique URLs so deduplication does not collapse them
        body = "".join(f"Click here: https://evil-{i}.xyz/login\n" for i in range(100)) + "Normal text."
        f = _feats(body=body)
        assert f["link_count"] == 100
        # links list should be capped at 20 in return value
        assert len(f["links"]) <= 20

    def test_link_density_computed(self):
        body = " ".join(["word"] * 50) + " https://a.com https://b.com https://c.com"
        f = _feats(body=body)
        assert f["link_density"] > 0
