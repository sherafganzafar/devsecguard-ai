"""DevSecGuard AI: live web demo (Streamlit).

Paste code, click Scan, and see what the guardrail would do to your push.
Secrets are detected locally and masked before any code reaches NVIDIA Nemotron on Nebius Token Factory.

Run locally:  streamlit run app.py
"""
import os

import streamlit as st

import core

MAX_CHARS = 6000
MAX_SCANS_PER_SESSION = 15
COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#38bdf8"}

st.set_page_config(page_title="DevSecGuard AI", page_icon="🛡️", layout="wide")


def _secret(name: str) -> str:
    value = os.getenv(name, "")
    if value:
        return value
    try:
        return str(st.secrets.get(name, ""))
    except Exception:  # no secrets file configured
        return ""


@st.cache_resource(show_spinner=False)
def get_llm():
    """Return (client, model, error). Cached so the model list is fetched once."""
    key = _secret("NEBIUS_API_KEY")
    if not key:
        return None, "", "NEBIUS_API_KEY is not configured, so only the regex layer is available."
    try:
        client = core.make_client(api_key=key)
        model = core.pick_model(client, _secret("NEBIUS_MODEL") or None)
        return client, model, ""
    except Exception as exc:
        return None, "", f"Could not start the model layer: {exc}"


st.title("🛡️ DevSecGuard AI")
st.caption("Real-time DevSecOps guardrail · NVIDIA Nemotron on Nebius Token Factory · blocks risky pushes")

client, model, llm_error = get_llm()
if llm_error:
    st.warning(llm_error)

left, right = st.columns(2)
with left:
    code = st.text_area("Code to scan", value=core.demo_code(), height=380, max_chars=MAX_CHARS)
    use_llm = st.checkbox(
        f"Also analyse with Nemotron ({model})" if model else "Nemotron layer unavailable",
        value=bool(model),
        disabled=not model,
    )
    fail_on = st.select_slider("Block the push at severity", options=list(core.SEVERITIES), value="high")
    scan = st.button("Scan code", type="primary")

with right:
    st.subheader("Result")
    if "scans" not in st.session_state:
        st.session_state.scans = 0
    if scan:
        if st.session_state.scans >= MAX_SCANS_PER_SESSION:
            st.error("Scan limit reached for this session. Please refresh the page.")
        elif not code.strip():
            st.info("Paste some code first.")
        else:
            st.session_state.scans += 1
            with st.spinner("Scanning..."):
                result = core.scan_text(
                    code, "pasted_code.py", client=client if use_llm else None, model=model if use_llm else None
                )
            blocked = core.is_blocked([result], fail_on)
            (st.error if blocked else st.success)(
                "PUSH BLOCKED" if blocked else "PUSH ALLOWED",
                icon="⛔" if blocked else "✅",
            )
            c1, c2, c3 = st.columns(3)
            c1.metric("Findings", len(result.findings))
            c2.metric("Scan time", f"{result.seconds:.2f}s")
            c3.metric("Model latency", f"{result.llm_seconds:.2f}s" if result.llm_used else "n/a")
            if result.llm_error:
                st.warning(f"Model layer skipped: {result.llm_error}")
            for f in result.findings:
                where = f" (line {f.line})" if f.line else ""
                with st.expander(f"{f.severity.upper()} · {f.title}{where} · {f.source}", expanded=True):
                    st.markdown(f"<span style='color:{COLORS[f.severity]}'>●</span> **{f.severity.upper()}**", unsafe_allow_html=True)
                    if f.snippet:
                        st.code(f.snippet)
                    if f.explanation:
                        st.write(f"**Risk:** {f.explanation}")
                    if f.fix:
                        st.write(f"**Fix:** {f.fix}")
            if not result.findings and not result.llm_error:
                st.write("No findings.")
    else:
        st.write("Click **Scan code** to see the report.")

st.divider()
st.caption("Detected secrets are masked locally before any code is sent to the model. Built for the Nebius x NVIDIA Global AI Hackathon.")
