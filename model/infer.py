
import logging
import os
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logger = logging.getLogger(__name__)

_FALLBACK_MODEL = "distilbert-base-uncased"


def _best_device() -> torch.device:
    """Return the best available device: CUDA > MPS > CPU."""
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")

class PhishModel:
    """Thin wrapper around a DistilBERT sequence-classification model.

    If *path_or_name* points to a local directory that does not exist (or
    contains no model files) the loader falls back to the base pre-trained
    checkpoint so the application can still start without trained artifacts.
    """


    def __init__(self, path_or_name: str):
        resolved = self._resolve_path(path_or_name)
        logger.info("Loading PhishModel from: %s", resolved)
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(resolved)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                resolved, num_labels=2
            )
        except (OSError, ValueError, RuntimeError) as exc:
            logger.warning(
                "Could not load model from '%s' (%s); falling back to '%s'."
                " Predictions will be near-random until the model is trained.",
                resolved, exc, _FALLBACK_MODEL,
            )
            self.tokenizer = AutoTokenizer.from_pretrained(_FALLBACK_MODEL)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                _FALLBACK_MODEL, num_labels=2
            )

        self.device = _best_device()
        self.model.to(self.device)
        self.model.eval()
        self.model_path = resolved

    @staticmethod
    def _resolve_path(path_or_name: str) -> str:
        """If *path_or_name* is a local path that exists use it; otherwise
        return the fallback HuggingFace model name so the loader uses the hub."""
        candidate = Path(path_or_name)
        if candidate.is_absolute() or os.sep in path_or_name or "/" in path_or_name:
            # Looks like a local path
            if candidate.exists() and any(candidate.iterdir()):
                return str(candidate)
            logger.warning("Local model path '%s' not found or empty.", candidate)
            return _FALLBACK_MODEL
        return path_or_name  # Hub model name — pass through

    @torch.inference_mode()
    def predict(self, subject: str, body: str) -> dict:
        text = f"Subject: {subject}\n\n{body}"
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512,
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        out = self.model(**inputs)
        probs = out.logits.softmax(-1).cpu().numpy()[0]
        label = int(probs.argmax())
        return {
            "label": label,
            "probabilities": {
                "ham":   round(float(probs[0]), 4),
                "phish": round(float(probs[1]), 4),
            },
        }
