import requests
import time
from dotenv import load_dotenv
import os
from predict import analyze_log
import streamlit as st

# DOCKER DOES NOT USE APIs LIKE STREAMLIT.
'''
ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]
OTX_API_KEY = st.secrets["OTX_API_KEY"]
'''
# STREAMLIT DOES NOT SUPPORT THIS THAT AND HAS IT'S OWN WAY
env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv(env_path)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")




def get_abuseipdb_data(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        data = response.json()

        if "data" in data:
            return {
                "abuse_score": data["data"]["abuseConfidenceScore"],
                "reports": data["data"]["totalReports"],
                "country": data["data"]["countryCode"]
            }
    except Exception as e:
        print("AbuseIPDB error:", e)

    return None

def get_otx_data(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        data = response.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        return {
            "pulse_count": len(pulses),
            "malware_families": list(set(
                tag for pulse in pulses for tag in pulse.get("tags", [])
            ))[:5]  # limit for readability
        }
    except Exception as e:
        print("OTX error:", e)

    return None

def calculate_reputation(abuse_data, otx_data):
    score = 0

    # AbuseIPDB weight (strong signal)
    if abuse_data:
        score += abuse_data["abuse_score"] * 0.6

    # OTX weight (context signal)
    if otx_data:
        score += min(otx_data["pulse_count"] * 4, 40)

    score = min(int(score), 100)

    # Classification
    if score >= 75:
        label = "Malicious"
    elif score >= 40:
        label = "Suspicious"
    else:
        label = "Clean"

    return label, score

def fuse_decision(layer2_output, reputation_label):
    final_decision = layer2_output["Final Decision"]
    severity = layer2_output["Severity"]

    # Case 1: ML says bad BUT intel says clean
    if final_decision == "Anomalous Activity" and reputation_label == "Clean":
        severity = "Medium"   # downgrade
        note = "No external threat intel found"

    # Case 2: Both agree it's bad
    elif final_decision == "Anomalous Activity" and reputation_label == "Malicious":
        severity = "Critical"
        note = "Confirmed by threat intelligence"

    # Case 3: Intel says bad but ML missed
    elif final_decision == "Normal" and reputation_label == "Malicious":
        final_decision = "Suspicious Activity"
        severity = "High"
        note = "Flagged by external threat intelligence"

    else:
        note = "No significant correlation"

    return final_decision, severity, note

def layer3_threat_intel(layer2_output):
    ip = layer2_output.get("IP Address")

    if not ip:
        return {"error": "No IP Address found in input"}

    print(f"🔍 Enriching IP: {ip}")

    abuse_data = get_abuseipdb_data(ip)
    time.sleep(1)  # avoid rate limit

    otx_data = get_otx_data(ip)

    label, score = calculate_reputation(abuse_data, otx_data)
    new_decision, new_severity, note = fuse_decision(layer2_output, label)


    enrichment = {
        "Threat Intel": {
            "AbuseIPDB": abuse_data,
            "OTX": otx_data,
            "IP Reputation": f"{label} ({score}%)",
            "Fusion Note": note
        },
        "Final Decision": new_decision,
        "Severity": new_severity
    }

    return enrichment
# FOLLOWING THINGS ARE NOT NEEDED FOR STREAMLIT APP AND ONLY REQUIRED WHEN WE RUN IT IN TERMINAL
'''
# Input box in terminal
user_input = input("Enter your log: ")

result = analyze_log(user_input)

layer3_output = layer3_threat_intel(result)

# Merge results
final_output = {**result, **layer3_output}

print(final_output)'''
