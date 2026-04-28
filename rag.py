import re
import streamlit as st
import json
from openai import OpenAI
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import os

# -------------------------------
# 🔐 API KEY
# -------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

# -------------------------------
# 🧹 CLEAN JSON
# -------------------------------
def clean_llm_json(response_text):
    cleaned = re.sub(r"```json|```", "", response_text).strip()
    
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        print("⚠️ JSON parsing failed. Raw output returned.")
        return {"raw_output": response_text}


# ===============================
# 🚀 STEP 3 — LOAD (NOT BUILD)
# ===============================
@st.cache_resource
def load_rag_resources():

    # Load embedding model
    embedder = SentenceTransformer("all-MiniLM-L6-v2")

    # Load FAISS index
    index = faiss.read_index("mitre_index.faiss")

    # Load metadata
    with open("mitre_data.json", "r") as f:
        mitre_data = json.load(f)

    return embedder, index, mitre_data


# ===============================
# 🔎 STEP 4 — RETRIEVAL
# ===============================
def retrieve_mitre_context(query, embedder, index, mitre_data, top_k=1):

    query_vec = embedder.encode([query])
    distances, indices = index.search(np.array(query_vec), top_k)

    results = [mitre_data[i] for i in indices[0]]
    return results


# ===============================
# 🧠 STEP 5 — MAIN FUNCTION
# ===============================
def layer4_llm_rag(layer3_output):

    # ✅ Load precomputed resources
    embedder, index, mitre_data = load_rag_resources()

    # Extract info
    attack_type = layer3_output.get("Prediction")
    ip = layer3_output.get("IP Address")
    severity = layer3_output.get("Severity")
    anomaly_score = layer3_output.get("Anomaly Score")
    threat_intel = layer3_output.get("Threat Intel")

    # -------------------------------
    # 🔹 RAG Retrieval
    # -------------------------------
    query = f"{attack_type} attack behavior"

    mitre_context = retrieve_mitre_context(
        query,
        embedder,
        index,
        mitre_data,
        top_k=1
    )

    mitre_name = mitre_context[0]["name"]
    mitre_id = mitre_context[0]["mitre_id"]
    mitre_desc = mitre_context[0]["description"]
    mitre_full = f"{mitre_id} – {mitre_name}"

    # -------------------------------
    # 🔹 LLM Prompt
    # -------------------------------
    prompt = f"""
You are a SOC security analyst.

Analyze this security event:

IP Address: {ip}
Attack Type: {attack_type}
Severity: {severity}
Anomaly Score: {anomaly_score}

Threat Intelligence:
{threat_intel}

MITRE ATT&CK Context:
Technique ID: {mitre_id}
Description: {mitre_desc}

Tasks:
1. Explain the incident clearly
2. Validate or adjust severity (Low/Medium/High)
3. Recommend actions
4. Confirm MITRE mapping

Return STRICT JSON format:
{{
  "Incident Explanation": "...",
  "Severity Assessment": "...",
  "Recommended Actions": ["...", "..."],
  "MITRE Technique": "..."
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )

    llm_output = response.choices[0].message.content
    parsed_output = clean_llm_json(llm_output)

    return {
        **parsed_output,
        "MITRE Technique": mitre_full,
        "MITRE ID": mitre_id,
        "MITRE Description": mitre_desc
    }