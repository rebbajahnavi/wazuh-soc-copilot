"""
SOC Copilot Dashboard & Interactive Chat Interface.
Provides real-time alert triage, RAG context inspection, and AI playbook generation.
"""

import sys
import json
from pathlib import Path
import streamlit as st

# Setup pathing
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

from src.parser.alert_parser import WazuhAlertParser
from rag.retrieval.retriever import SOCRetriever
from src.llm.prompt_builder import SOCPromptBuilder
from src.llm.llm_client import SOCLLMClient

st.set_page_config(page_title="Wazuh SOC Copilot", layout="wide", page_icon="🛡️")

@st.cache_resource
def load_components():
    retriever = SOCRetriever()
    llm_client = SOCLLMClient()
    return retriever, llm_client

retriever, llm_client = load_components()

st.title("🛡️ Wazuh SOC Copilot (RAG-Driven Incident Response)")
st.caption("Grounding SIEM telemetry with NIST CSF 2.0 and MITRE ATT&CK knowledge bases")

# Sidebar: Alert Selection
st.sidebar.header("Alert Ingestion")
alerts_path = ROOT_DIR / "data" / "sample" / "wazuh_alerts.json"

if not alerts_path.exists():
    st.sidebar.error("Sample alerts file missing!")
    st.stop()

with open(alerts_path, "r", encoding="utf-8") as f:
    sample_alerts = json.load(f)

alert_options = [f"Alert #{i+1}: Level {a['rule']['level']} - {a['rule']['description'][:40]}..." for i, a in enumerate(sample_alerts)]
selected_index = st.sidebar.selectbox("Select Active Wazuh Alert:", range(len(alert_options)), format_func=lambda x: alert_options[x])

raw_alert = sample_alerts[selected_index]
parsed_alert = WazuhAlertParser.parse(raw_alert)

# Column layout for Alert Details & Actions
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📋 Alert Telemetry")
    st.markdown(f"**Timestamp:** `{parsed_alert.timestamp}`")
    st.markdown(f"**Agent:** `{parsed_alert.agent_name}` (`{parsed_alert.agent_ip}`)")
    st.markdown(f"**Rule ID:** `{parsed_alert.rule_id}` (Severity Level: **{parsed_alert.rule_level}**)")
    st.markdown(f"**Description:** {parsed_alert.rule_description}")
    
    if parsed_alert.mitre_ids:
        st.markdown(f"**MITRE ATT&CK:** `{', '.join(parsed_alert.mitre_ids)}`")
        st.caption(f"Techniques: {', '.join(parsed_alert.mitre_techniques)}")
    else:
        st.info("No MITRE TTP tags mapped.")

with col2:
    st.subheader("📚 RAG Grounding Context")
    query = parsed_alert.to_retrieval_query()
    with st.spinner("Retrieving semantic knowledge from Qdrant..."):
        rag_context = retriever.retrieve_unified_context(query=query, top_k_per_collection=1)

    with st.expander("Inspect Retrieved Knowledge Chunks", expanded=False):
        for col_name, hits in rag_context.items():
            st.markdown(f"**Collection: `{col_name}`**")
            for h in hits:
                st.markdown(f"- *Score:* `{h['score']}` | *Source:* `{h['source']}`")
                st.code(h["text"], language="text")

# Generate Playbook Section
st.divider()
st.subheader("⚡ Automated Incident Response Playbook")

if st.button("Generate Playbook", type="primary"):
    with st.spinner("Assembling context and consulting LLM..."):
        prompt = SOCPromptBuilder.build_grounded_prompt(parsed_alert, rag_context)
        playbook = llm_client.generate_playbook(prompt)
        st.session_state["current_playbook"] = playbook

if "current_playbook" in st.session_state:
    st.markdown(st.session_state["current_playbook"])

# Follow-up Chat
st.divider()
st.subheader("💬 Analyst Follow-Up Chat")
user_query = st.chat_input("Ask a follow-up question (e.g., 'What commands should I run to isolate this host?')...")

if user_query:
    st.chat_message("user").write(user_query)
    with st.spinner("Analyzing guidance..."):
        response = f"**SOC Copilot Recommendation regarding '{user_query}':**\n\nReferencing MITRE mitigation controls for `{', '.join(parsed_alert.mitre_ids)}`: Execute host containment via firewall isolation rules or host EDR sensor, verify integrity of surrounding event logs, and escalate according to NIST CSF Respond (RS.MA) procedures."
        st.chat_message("assistant").markdown(response)