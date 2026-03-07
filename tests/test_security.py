
from app.security import redact


class TestRedact:
    def test_returns_string(self):
        assert isinstance(redact("hello"), str)

    def test_contains_sha256_prefix(self):
        assert "sha256:" in redact("some text")

    def test_same_input_same_hash(self):
        assert redact("deterministic") == redact("deterministic")

    def test_different_inputs_different_hashes(self):
        assert redact("aaaa") != redact("bbbb")

    def test_empty_string_returns_empty(self):
        assert redact("") == ""

    def test_none_returns_empty(self):
        # Security module should handle None gracefully
        assert redact(None) == ""

    def test_keep_parameter_controls_length(self):
        result32 = redact("hello", keep=32)
        result8  = redact("hello", keep=8)
        # Both have <redacted sha256:HASH> format; the HASH length differs
        hash32 = result32.split("sha256:")[1].rstrip(">")
        hash8  = result8.split("sha256:")[1].rstrip(">")
        assert len(hash32) == 32
        assert len(hash8) == 8
