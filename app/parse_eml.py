
from typing import Tuple, Dict, Any
import email
from email import policy
from bs4 import BeautifulSoup

def parse_eml_bytes(raw: bytes) -> Tuple[str, str, Dict[str, Any]]:
    msg = email.message_from_bytes(raw, policy=policy.default)
    subject = msg.get("Subject", "") or ""
    headers = {k: v for (k, v) in msg.items()}

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                body_text = part.get_content()
                break
            elif ctype == "text/html" and not body_text:
                html = part.get_content()
                body_text = _html_to_text(html)
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            body_text = msg.get_content()
        elif ctype == "text/html":
            body_text = _html_to_text(msg.get_content())

    return subject, body_text, headers

def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text("\n")
