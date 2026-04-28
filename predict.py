import random
import pandas as pd
import re
from sklearn.ensemble import IsolationForest
import joblib

# Load models
model = joblib.load("rf_model.pkl")
iso_model = joblib.load("iso_model.pkl")
feature_columns = joblib.load("features.pkl")


# -------------------------------
# FEATURE EXTRACTION
# -------------------------------
def log_to_features(log):
    log_lower = log.lower()

    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
    ip = ip_match.group(0) if ip_match else "0.0.0.0"

    numbers = re.findall(r'\d+', log)
    count = int(numbers[-1]) if numbers else 0

    features = {
        "failed_logins": 0,
        "successful_logins": 0,
        "bytes_sent": 5000,
        "bytes_received": 5000,
        "request_rate": 10,
        "unique_ports": 1,
        "is_port_scan": 0,
        "suspicious_process": 0,
        "dns_queries": 10
    }

    # 🔐 Login patterns
    if ("fail" in log_lower and "login" in log_lower):
        features["failed_logins"] = count

        if count <= 3:
            features["request_rate"] = random.randint(1, 5)
        elif count <= 7:
            features["request_rate"] = random.randint(5, 15)
        else:
            features["request_rate"] = random.randint(20, 50)

    # 🌐 Port scan
    if "port" in log_lower and "scan" in log_lower:
        features["is_port_scan"] = 1
        features["unique_ports"] = count if count > 0 else 50

    # 💥 DoS detection (STRONGER)
    if ("dos" in log_lower or 
        "flood" in log_lower or 
        "traffic spike" in log_lower or 
        "high traffic" in log_lower):

        features["request_rate"] = max(count, 300)
        features["bytes_sent"] = 200000
        features["dns_queries"] = 300

    if "per second" in log_lower or "rapid" in log_lower:
        features["request_rate"] = count * 2

    # Suspicious IP simulation
    if ip.startswith("45"):
        features["dns_queries"] += 20

    return ip, features


# -------------------------------
# RULE ENGINE
# -------------------------------
def apply_rules(features):

    # Brute force
    if features["failed_logins"] > 7:
        return "Brute Force (Rule)"

    # Port scan
    if features["is_port_scan"] == 1:
        return "Port Scan (Rule)"

    # 🚨 NEW: DoS RULE
    if features["request_rate"] > 200:
        return "DoS (Rule)"

    return "No Rule Triggered"


# -------------------------------
# ANOMALY SCORE
# -------------------------------
def get_anomaly_score(model, df):
    raw_score = model.decision_function(df)[0]

    # better normalization
    normalized = max(0, min(1, (0.7 - raw_score)))

    return round(float(normalized), 2)


# -------------------------------
# FINAL DECISION ENGINE
# -------------------------------
def final_decision(prediction, confidence, rule, anomaly_score, features):

    # 🚫 prevent false positives
    if features["failed_logins"] <= 3 and confidence > 0.8:
        return "Suspicious", "Medium"

    # 🚨 DoS rule priority
    if "DoS" in rule:
        return "DoS", "High"

    # 🚨 anomaly
    if anomaly_score > 0.6:
        return "Anomalous Activity", "High"

    # 🚨 brute force
    if "Brute Force" in rule:
        return "Brute Force", "High"

    # 🎯 ML
    if confidence > 0.85:
        return prediction, "High"

    if confidence > 0.7:
        return prediction, "Medium"

    if confidence > 0.5:
        return "Suspicious", "Medium"

    return "Suspicious", "Low"


# -------------------------------
# MAIN PIPELINE
# -------------------------------
def analyze_log(log):
    ip, features = log_to_features(log)

    df_input = pd.DataFrame([features])
    df_input = df_input[feature_columns]

    prediction = model.predict(df_input)[0]
    confidence = model.predict_proba(df_input).max()

    rule = apply_rules(features)
    anomaly_score = get_anomaly_score(iso_model, df_input)

    final_label, severity = final_decision(
        prediction, confidence, rule, anomaly_score, features
    )

    return {
        "IP Address": ip,
        "Prediction": prediction,
        "Confidence": round(float(confidence), 2),
        "Rule Triggered": rule,
        "Anomaly Score": anomaly_score,
        "Final Decision": final_label,
        "Severity": severity
    }
