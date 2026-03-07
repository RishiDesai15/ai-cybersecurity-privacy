
import os, glob
from dataclasses import dataclass
from typing import List, Dict, Any
from app.parse_eml import parse_eml_bytes

@dataclass
class Example:
    subject: str
    body: str
    label: int   # 0 = ham, 1 = phish
    headers: Dict[str, Any]

def load_toy_dataset() -> List[Example]:
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_emails")
    examples: List[Example] = []
    for path in sorted(glob.glob(os.path.join(base, "*.eml"))):
        with open(path, "rb") as f:
            subj, body, headers = parse_eml_bytes(f.read())
        label = 1 if "phish" in os.path.basename(path).lower() else 0
        examples.append(Example(subj, body, label, headers))
    return examples
