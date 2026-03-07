"""
PhishAI — Cybersecurity & Privacy  |  Streamlit Front-end
==========================================================
Uploads one or more .eml files, calls the FastAPI back-end,
and renders a rich, privacy-first analysis report.
"""

import sys
from pathlib import Path

import requests
import streamlit as st

# make local imports work when launched with `streamlit run ui/app_streamlit.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---------------------------------------------------------------------------
# Page config (must be FIRST Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PhishAI — Cybersecurity & Privacy",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
.verdict-phish {
    background:#ff4b4b; color:white; padding:0.35rem 1rem;
    border-radius:8px; font-size:1.6rem; font-weight:700; display:inline-block;
}
.verdict-ham {
    background:#21c55d; color:white; padding:0.35rem 1rem;
    border-radius:8px; font-size:1.6rem; font-weight:700; display:inline-block;
}
.reason-item {
    background:#fff3cd; border-left:4px solid #ffc107;
    padding:0.4rem 0.8rem; margin:0.3rem 0; border-radius:4px;
    font-size:0.9rem;
}
.flag-on  { color:#ff4b4b; font-weight:600; }
.flag-off { color:#21c55d; }
mark.token-highlight {
    background:#ffe066; border-radius:3px; padding:0 2px; font-weight:600;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ PhishAI")
    st.caption("Privacy-first Phishing Classifier + Explainer")
    st.divider()

    api_url = st.text_input(
        "FastAPI backend URL",
        value="http://localhost:8000",
        help="URL where `uvicorn app.api:app` is running.",
    )

    if st.button("🔄 Check API health"):
        try:
            r = requests.get(f"{api_url}/health", timeout=5)
            r.raise_for_status()
            d = r.json()
            st.success(f"✅ API online  |  model: `{d.get('model_path', '?')}`")
        except (requests.exceptions.RequestException, OSError, ValueError) as exc:
            st.error(f"❌ API unreachable: {exc}")

    st.divider()
    st.caption(
        "🔒 Raw email bodies are **never stored**.  "
        "Only derived signals are displayed."
    )


# ---------------------------------------------------------------------------
# Main header
# ---------------------------------------------------------------------------
st.title("🛡️ AI Cybersecurity & Privacy")
st.subheader("Phishing Email Classifier + Explainer")
st.write(
    "Upload one or more `.eml` files to analyse them for phishing signals. "
    "The system combines **DistilBERT** classification with engineered "
    "security features (SPF/DKIM/DMARC, link mismatch, IDN homographs, "
    "urgency patterns)."
)

uploaded_files = st.file_uploader(
    "Drop .eml files here",
    type=["eml"],
    accept_multiple_files=True,
    label_visibility="collapsed",
)


# ---------------------------------------------------------------------------
# Helper renderers
# ---------------------------------------------------------------------------

def _confidence_bar(label: int, probs: dict) -> None:
    """Render a coloured confidence progress bar."""
    phish_p = probs.get("phish", 0.5)
    ham_p   = probs.get("ham",   0.5)
    pct     = max(phish_p, ham_p) * 100
    colour  = "#ff4b4b" if label == 1 else "#21c55d"
    display = f"{phish_p*100:.1f}% PHISH" if label == 1 else f"{ham_p*100:.1f}% HAM"
    st.markdown(
        f"""<div style='background:#e9ecef;border-radius:6px;height:24px;width:100%;'>
  <div style='width:{pct:.1f}%;background:{colour};border-radius:6px;height:24px;
              text-align:right;padding-right:10px;color:white;
              font-size:0.8rem;line-height:24px;font-weight:600;'>
    {display}
  </div>
</div>""",
        unsafe_allow_html=True,
    )


def _render_features(feats: dict) -> None:
    """Show boolean flags as a colour-coded grid plus key metric counters."""
    bool_flags = {k: v for k, v in feats.items() if isinstance(v, bool)}
    FLAG_LABELS = {
        "spf_fail":             "SPF Fail",
        "dkim_fail":            "DKIM Fail",
        "dmarc_fail":           "DMARC Fail",
        "link_anchor_mismatch": "Anchor Mismatch",
        "idn_suspect":          "IDN / Punycode",
        "suspicious_tld":       "Suspicious TLD",
        "urgent_language":      "Urgent Language",
        "subject_urgent":       "Urgent Subject",
        "subject_homoglyph":    "Subject Homoglyph",
        "subject_all_caps":     "All-Caps Subject",
        "free_email_sender":    "Free Email Sender",
        "attachment_hint":      "Attachment Hint",
        "appears_html":         "HTML-only Body",
    }

    cols = st.columns(3)
    for i, (k, v) in enumerate(bool_flags.items()):
        icon      = "🔴" if v else "✅"
        flag_label = FLAG_LABELS.get(k, k.replace("_", " ").title())
        css       = "flag-on" if v else "flag-off"
        cols[i % 3].markdown(
            f"<span class='{css}'>{icon} {flag_label}</span>",
            unsafe_allow_html=True,
        )

    st.divider()
    m = st.columns(4)
    m[0].metric("Links found",          feats.get("link_count", 0))
    m[1].metric("IDN domains",           feats.get("idn_count", 0))
    m[2].metric("Mismatched anchors",    feats.get("link_anchor_mismatch_count", 0))
    m[3].metric("Link density / 100 w",  f"{feats.get('link_density', 0):.1f}")

    if feats.get("sender_domain"):
        st.caption(f"Sender domain: `{feats['sender_domain']}`")

    links = feats.get("links", [])
    if links:
        with st.expander(f"📎 Detected links ({len(links)})"):
            for anchor, href in links:
                if anchor != href:
                    st.markdown(f"- Anchor: `{anchor[:80]}` → `{href[:80]}`")
                else:
                    st.markdown(f"- `{href[:100]}`")


def _highlight_body(body: str, tokens: list) -> str:
    """Wrap flagged keyword spans in HTML highlight marks."""
    if not tokens:
        return body
    spans = sorted(tokens, key=lambda t: t["start"])
    result, cursor = [], 0
    for span in spans:
        s, e = span["start"], span["end"]
        if s < cursor:
            continue
        result.append(body[cursor:s])
        result.append(f"<mark class='token-highlight'>{body[s:e]}</mark>")
        cursor = e
    result.append(body[cursor:])
    return "".join(result)


# ---------------------------------------------------------------------------
# Analysis loop
# ---------------------------------------------------------------------------

if not uploaded_files:
    st.info("📎 Upload one or more .eml files above to begin analysis.")

else:
    for up in uploaded_files:
        with st.expander(f"📧 {up.name}", expanded=True):
            raw = up.getvalue()

            with st.spinner(f"Analysing {up.name}…"):
                try:
                    r = requests.post(
                        f"{api_url}/classify_eml",
                        files={"file": (up.name, raw, "message/rfc822")},
                        timeout=45,
                    )
                    r.raise_for_status()
                    res = r.json()
                except requests.exceptions.ConnectionError:
                    st.error(
                        "❌ Cannot reach the FastAPI backend.  \n"
                        "Run `uvicorn app.api:app --reload --port 8000` first."
                    )
                    continue
                except requests.exceptions.HTTPError as exc:
                    st.error(f"❌ HTTP {exc.response.status_code}: {exc.response.text}")
                    continue
                except (requests.exceptions.RequestException, KeyError, ValueError) as exc:
                    st.error(f"❌ Unexpected error: {exc}")
                    continue

            pred          = res["prediction"]
            verdict_label = pred["label"]
            verdict_probs = pred["probabilities"]
            reasons       = res.get("reasons", [])
            email_feats   = res.get("features", {})
            flagged_tokens = res.get("tokens", [])
            subject       = res.get("subject", "(unknown)")

            # ---- Verdict header -------------------------------------------------------
            hcol1, hcol2 = st.columns([1, 3])

            with hcol1:
                css_cls      = "verdict-phish" if verdict_label == 1 else "verdict-ham"
                verdict_text = "⚠️ PHISH"      if verdict_label == 1 else "✅ HAM"
                st.markdown(
                    f"<div class='{css_cls}'>{verdict_text}</div>",
                    unsafe_allow_html=True,
                )
                st.write("")
                _confidence_bar(verdict_label, verdict_probs)

            with hcol2:
                st.caption(f"**Subject:** {subject}")
                if reasons:
                    st.write("**Why this verdict?**")
                    for reason in reasons:
                        st.markdown(
                            f"<div class='reason-item'>• {reason}</div>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.info("No strong phishing signals found.")

            st.write("")

            # ---- Detail tabs ----------------------------------------------------------
            tab_feat, tab_tokens, tab_raw = st.tabs(
                ["🔧 Security Features", "🔍 Flagged Keywords", "📄 Raw JSON"]
            )

            with tab_feat:
                _render_features(email_feats)

            with tab_tokens:
                from app.parse_eml import parse_eml_bytes as _parse
                _, body_text, _ = _parse(raw)
                snippet = body_text[:1500]
                visible_tokens = [t for t in flagged_tokens if t["start"] < 1500]

                if visible_tokens:
                    st.write(
                        f"Found **{len(flagged_tokens)}** suspicious keyword occurrence(s) "
                        "in the email body:"
                    )
                    highlighted = _highlight_body(snippet, visible_tokens)
                    st.markdown(
                        f"<div style='font-family:monospace;white-space:pre-wrap;"
                        f"background:#f8f9fa;padding:0.8rem;border-radius:6px;"
                        f"font-size:0.85rem;line-height:1.5'>{highlighted}</div>",
                        unsafe_allow_html=True,
                    )
                    if len(body_text) > 1500:
                        st.caption("(showing first 1 500 characters)")
                else:
                    st.info("No risk keywords found in the body.")

            with tab_raw:
                st.json(res)

            st.divider()
