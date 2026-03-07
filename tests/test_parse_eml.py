
import textwrap
from pathlib import Path

import pytest
from app.parse_eml import parse_eml_bytes

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_emails"


class TestPlainText:
    def test_parse_simple(self):
        raw = b"Subject: Hello World\r\n\r\nThis is the body."
        subj, body, _ = parse_eml_bytes(raw)
        assert "Hello World" in subj
        assert "body" in body

    def test_returns_three_values(self):
        result = parse_eml_bytes(b"Subject: X\r\n\r\nY")
        assert len(result) == 3

    def test_subject_missing(self):
        raw = b"\r\nBody with no subject."
        subj, _, _ = parse_eml_bytes(raw)
        assert subj == ""

    def test_headers_dict(self):
        raw = b"Subject: S\r\nFrom: a@b.com\r\n\r\nBody"
        _, _, headers = parse_eml_bytes(raw)
        assert isinstance(headers, dict)
        assert "From" in headers


class TestHtmlBody:
    def test_html_stripped_to_text(self):
        html_body = "<html><body><p>Hello <b>world</b></p></body></html>"
        raw = (
            f"Subject: HTML test\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n\r\n"
            f"{html_body}"
        ).encode()
        _, body, _ = parse_eml_bytes(raw)
        assert "Hello" in body
        assert "<p>" not in body


class TestMultipart:
    def test_multipart_prefers_plain(self):
        raw = textwrap.dedent("""\
            Subject: Multipart test\r
            MIME-Version: 1.0\r
            Content-Type: multipart/alternative; boundary="BOUNDARY"\r
            \r
            --BOUNDARY\r
            Content-Type: text/plain; charset=utf-8\r
            \r
            Plain text part\r
            --BOUNDARY\r
            Content-Type: text/html; charset=utf-8\r
            \r
            <html><body>HTML part</body></html>\r
            --BOUNDARY--\r
        """).encode()
        _, body, _ = parse_eml_bytes(raw)
        assert "Plain text part" in body


class TestSampleFiles:
    @pytest.mark.parametrize("fname", ["001_phish.eml", "002_ham.eml"])
    def test_sample_files_parse(self, fname):
        path = DATA_DIR / fname
        if not path.exists():
            pytest.skip(f"{fname} not found")
        subj, body, headers = parse_eml_bytes(path.read_bytes())
        assert isinstance(subj, str)
        assert isinstance(body, str)
        assert isinstance(headers, dict)

    def test_phish_sample_has_content(self):
        path = DATA_DIR / "001_phish.eml"
        if not path.exists():
            pytest.skip("sample not found")
        subj, body, _ = parse_eml_bytes(path.read_bytes())
        assert len(subj) > 0 or len(body) > 0
