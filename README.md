
# AI Cybersecurity & Privacy — Phishing Email Classifier + Explainer (MVP)

A student-friendly, privacy-first phishing detector you can train and run locally in 2–3 weeks.
- Input: `.eml` files (or raw subject/body).
- Model: DistilBERT (binary classification).
- Extras: simple rules (SPF/DKIM/DMARC flags if present), link-text vs href mismatch, IDN (homograph) check.
- Explainability: rule-based reasons + token highlights via Integrated Gradients (Captum) or attention fallback.
- UI: Streamlit inbox-style viewer.
- API: FastAPI for programmatic inference.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python model/train.py --config model/config.yaml
uvicorn app.api:app --reload --port 8000
streamlit run ui/app_streamlit.py
```

## Project Structure
```
AI Cybersecurity & Privacy/
  app/            # API + feature extraction + explainability
  model/          # training and inference code
  ui/             # Streamlit frontend
  utils/          # parsing / URL tools
  tests/          # pytest unit tests
  data/           # raw/processed data and sample .eml
  notebooks/      # EDA & experiments
```
