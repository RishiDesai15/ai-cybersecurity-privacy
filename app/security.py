
import hashlib
def redact(text: str, keep=32) -> str:
    if not text:
        return ""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"<redacted sha256:{h[:keep]}>"
