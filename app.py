import streamlit as st
from predict import analyze_log
from detect import layer3_threat_intel
from rag import layer4_llm_rag   
#from rag import initialize_rag
from rag import load_rag_resources
from soar import execute_playbook


with st.spinner("Initializing AI engine..."):
    load_rag_resources()

# -------------------------------
# ✅ CACHE WRAPPERS
# -------------------------------
@st.cache_data(ttl=3600)
def cached_layer3(result):
    return layer3_threat_intel(result)

@st.cache_data(ttl=3600)
def cached_layer4(final_output):
    return layer4_llm_rag(final_output)

# -------------------------------
# 🎨 STREAMLIT UI
# -------------------------------
st.set_page_config(page_title="AI SOC Analyst", layout="centered")

st.title("🛡️ AI-Powered SOC Analyst")
st.markdown("Paste a security log below and let AI analyze it.")

st.markdown("### 🧪 Try Sample Attack Logs")

st.info(
    "You can test the system using the sample security logs below. "
    "👉 Copy **any one** log and paste it into the input box to analyze.\n\n"
    "⚠️ Note: Each log represents a different type of attack. "
    "**Do NOT paste all logs together**, as they must be analyzed individually.\n\n"
    "💡 Note:\n"
    "The IP addresses used in these examples are **known malicious IPs** sourced from public threat intelligence.\n"
    "These samples are included to demonstrate how this system detects and enriches threats using\n"
    "**OTX AlienVault** and **AbuseIPDB** integrations."
)

st.code(
"""Possible SYN flood from IP 89.190.156.118 – 9,700 half-open connections detected

Aggressive scan from IP 45.227.254.170 targeting ports 1–2048

Multiple failed login attempts detected from IP 194.164.107.5"""
)

log_input = st.text_area(
    "Enter Log:",
    placeholder="Example: Failed login attempts from IP 45.12.23.11 20 times"
)

if st.button("Analyze"):

    if log_input.strip() == "":
        st.warning("Please enter a log.")
    else:
        try:
            # =========================
            # 🔍 LAYER 2 - ML DETECTION
            # =========================
            result = analyze_log(log_input)

            st.subheader("🔍 Layer 2: Detection Engine")

            col1, col2 = st.columns(2)

            with col1:
                st.metric("IP Address", result.get("IP Address"))
                st.metric("Attack Type", result.get("Prediction"))
                st.metric("Confidence", result.get("Confidence"))

            with col2:
                st.metric("Anomaly Score", result.get("Anomaly Score"))
                st.metric("Initial Severity", result.get("Severity"))

            st.markdown("### 🧠 Detection Decision")
            st.success(result.get("Final Decision"))

            st.markdown("### 📜 Rule Triggered")
            st.info(result.get("Rule Triggered"))

            # =========================
            # 🌐 LAYER 3 - THREAT INTEL
            # =========================
            st.markdown("---")
            st.subheader("🌐 Layer 3: Threat Intelligence")

            with st.spinner("Fetching threat intelligence..."):
                layer3_output = cached_layer3(result) or {}

            final_output = {**result, **layer3_output}

            intel = final_output.get("Threat Intel", {})
            abuse = intel.get("AbuseIPDB")
            otx = intel.get("OTX")

            col3, col4 = st.columns(2)

            with col3:
                st.metric("IP Reputation", intel.get("IP Reputation", "Unknown"))

                if abuse:
                    st.metric("Abuse Score", abuse.get("abuse_score", 0))
                    st.metric("Reports", abuse.get("reports", 0))
                else:
                    st.caption("AbuseIPDB unavailable")

            with col4:
                if otx:
                    st.metric("OTX Pulses", otx.get("pulse_count", 0))
                else:
                    st.metric("OTX Pulses", "No data")

            # Threat context
            st.markdown("### 🧬 Threat Context")
            if otx and otx.get("malware_families"):
                for tag in otx["malware_families"]:
                    st.markdown(f"- {tag}")
            else:
                st.write("No malware data available")

            # Fusion decision
            st.markdown("### 🧠 Fusion Decision (L2 + L3)")
            st.success(final_output.get("Final Decision"))

            st.markdown("### ⚠️ Updated Severity (Post-Intel)")
            st.error(final_output.get("Severity"))

            st.info(intel.get("Fusion Note", "No additional context"))

            # =========================
            # 🧠 LAYER 4 - LLM (RAG)
            # =========================
            st.markdown("---")
            st.subheader("🧠 Layer 4: AI Incident Analysis")

            with st.spinner("Generating AI insights..."):
                layer4_output = cached_layer4(final_output) or {}

            st.markdown("### 📖 Incident Explanation")
            st.write(layer4_output.get("Incident Explanation"))

            # Severity from LLM
            st.markdown("### ⚠️ AI Severity Assessment")
            severity = layer4_output.get("Severity Assessment", "Unknown")

            if severity == "High":
                st.error(severity)
            elif severity == "Medium":
                st.warning(severity)
            else:
                st.info(severity)

            # MITRE
            st.markdown("### 🧬 MITRE ATT&CK Mapping")

            col5, col6 = st.columns(2)
            with col5:
                st.metric("Technique", layer4_output.get("MITRE Technique"))
            with col6:
                st.metric("MITRE ID", layer4_output.get("MITRE ID"))

            with st.expander("📚 MITRE Description"):
                st.write(layer4_output.get("MITRE Description"))

            # Actions
            st.markdown("### ✅ Recommended Actions")
            actions = layer4_output.get("Recommended Actions", [])

            if actions:
                for action in actions:
                    st.markdown(f"- {action}")
            else:
                st.write("No actions available")

            # =========================
            # 🤖 LAYER 5 - SOAR
            # =========================
            st.markdown("---")
            st.subheader("🤖 Layer 5: SOAR Automation")

            # ✅ Cached SOAR
            @st.cache_data(ttl=3600)
            def cached_soar(l3, l4):
                return execute_playbook(l3, l4)

            with st.spinner("Executing automated response..."):
                soar_output = cached_soar(final_output, layer4_output)

            # Incident summary
            st.markdown("### 🆔 Incident Summary")

            col7, col8 = st.columns(2)

            with col7:
                st.metric("Incident ID", soar_output.get("Incident ID"))
                st.metric("Risk Score", soar_output.get("Risk Score"))

                # ✅ Risk visualization
                st.progress(soar_output.get("Risk Score", 0))

            with col8:
                st.metric("Playbook", soar_output.get("Playbook Executed"))

                # ✅ Color-coded status
                status = soar_output.get("Incident Status")

                if status == "Escalated":
                    st.error(status)
                elif status == "Investigating":
                    st.warning(status)
                else:
                    st.success(status)

            # Actions performed
            st.markdown("### ⚙️ Actions Executed")
            for action in soar_output.get("Actions Performed", []):
                st.markdown(f"- {action}")

            # Compact MITRE (no repetition overload)
            st.markdown("### 🧬 Attack Mapping")
            st.info(soar_output.get("MITRE Technique"))

            # Execution log
            st.markdown("### 📜 Execution Timeline")

            for log in soar_output.get("Response Log", []):
                with st.expander(f"{log['action']} • {log['timestamp']}"):
                    st.write(f"**Executor:** {log['executor']}")
                    st.write(f"**Status:** {log['status']}")
                    st.write(f"**Result:** {log['result']}")

        except Exception as e:
            st.error(f"Error occurred: {e}")