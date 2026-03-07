"""
pytest conftest — adds the project root to sys.path so that
`app`, `model`, `utils` are importable without installing a package.
"""
import sys
from pathlib import Path

# Insert the workspace root (one level above `tests/`) at the front
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
