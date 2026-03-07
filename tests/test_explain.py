
from app.explain import build_explanation, highlight_tokens_simple


# ---------------------------------------------------------------------------
# build_explanation
# ---------------------------------------------------------------------------

class TestBuildExplanation:
    def _explain(self, **feat_overrides):
        base = {
            "spf_fail": False, "dkim_fail": False, "dmarc_fail": False,
            "link_anchor_mismatch": False, "idn_suspect": False,
            "suspicious_tld": False, "urgent_language": False,
            "subject_urgent": False, "subject_homoglyph": False,
            "subject_all_caps": False, "free_email_sender": False,
            "attachment_hint": False, "link_count": 1, "link_density": 0.0,
        }
        base.update(feat_overrides)
        return build_explanation(base, "subject", "body")

    def test_returns_list(self):
        assert isinstance(self._explain(), list)

    def test_no_flags_gives_safe_message(self):
        reasons = self._explain()
        assert len(reasons) == 1
        assert "No strong" in reasons[0]

    def test_spf_fail_reason_present(self):
        reasons = self._explain(spf_fail=True)
        assert any("SPF" in r for r in reasons)

    def test_dkim_fail_reason_present(self):
        reasons = self._explain(dkim_fail=True)
        assert any("DKIM" in r for r in reasons)

    def test_dmarc_fail_reason_present(self):
        reasons = self._explain(dmarc_fail=True)
        assert any("DMARC" in r for r in reasons)

    def test_urgent_language_reason_present(self):
        reasons = self._explain(urgent_language=True)
        assert any("urgent" in r.lower() or "coercive" in r.lower() for r in reasons)

    def test_idn_reason_present(self):
        reasons = self._explain(idn_suspect=True)
        assert any("IDN" in r or "punycode" in r.lower() for r in reasons)

    def test_multiple_flags_multiple_reasons(self):
        reasons = self._explain(spf_fail=True, dkim_fail=True, urgent_language=True)
        assert len(reasons) >= 3

    def test_free_email_reason_present(self):
        reasons = self._explain(free_email_sender=True)
        assert any("free" in r.lower() or "consumer" in r.lower() for r in reasons)

    def test_high_link_density_reason(self):
        reasons = self._explain(link_density=12.5)
        assert any("density" in r.lower() for r in reasons)


# ---------------------------------------------------------------------------
# highlight_tokens_simple
# ---------------------------------------------------------------------------

class TestHighlightTokens:
    def test_returns_list(self):
        assert isinstance(highlight_tokens_simple("hello"), list)

    def test_finds_urgent(self):
        hits = highlight_tokens_simple("This is urgent, act now!")
        tokens = [h["token"] for h in hits]
        assert "urgent" in tokens

    def test_finds_all_occurrences(self):
        text = "verify your account, then verify again to confirm."
        hits = highlight_tokens_simple(text, top_k=20)
        verify_hits = [h for h in hits if h["token"] == "verify"]
        assert len(verify_hits) == 2

    def test_hit_positions_correct(self):
        text = "Please verify your account now."
        hits = highlight_tokens_simple(text)
        for hit in hits:
            s, e = hit["start"], hit["end"]
            assert text[s:e].lower() == hit["token"]

    def test_results_sorted_by_position(self):
        text = "verify your account and update your password urgently"
        hits = highlight_tokens_simple(text)
        starts = [h["start"] for h in hits]
        assert starts == sorted(starts)

    def test_no_overlapping_spans(self):
        text = "account password account verify update"
        hits = highlight_tokens_simple(text, top_k=20)
        prev_end = -1
        for hit in hits:
            assert hit["start"] >= prev_end
            prev_end = hit["end"]

    def test_empty_body(self):
        assert highlight_tokens_simple("") == []

    def test_respects_top_k(self):
        # Many occurrences should be capped
        text = " ".join(["verify"] * 50)
        hits = highlight_tokens_simple(text, top_k=5)
        assert len(hits) <= 5
