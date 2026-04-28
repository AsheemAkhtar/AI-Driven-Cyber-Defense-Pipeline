import datetime
import uuid
import time
from rag import layer4_llm_rag
from detect import layer3_threat_intel

# Simulated Integrations

def firewall_block_ip(ip):
    return f"[Firewall] Blocked IP: {ip}"

def send_alert(message, severity):
    return f"[Alerting] Alert sent | Severity: {severity} | Message: {message}"

def update_ticket(status, details):
    return f"[Ticketing] Status updated to '{status}' | Details: {details}"

# Playbook Definitions

SOAR_PLAYBOOKS = {
    "Critical": [
        {"action": "block_ip"},
        {"action": "send_alert"},
        {"action": "update_ticket", "status": "Escalated"}
    ],
    "High": [
        {"action": "block_ip"},
        {"action": "send_alert"},
        {"action": "update_ticket", "status": "Escalated"}
    ],
    "Medium": [
        {"action": "send_alert"},
        {"action": "update_ticket", "status": "Investigating"}
    ],
    "Low": [
        {"action": "update_ticket", "status": "Monitoring"}
    ]
}

# SOAR Engine

def execute_playbook(layer3_output, layer4_output):
    incident_id = str(uuid.uuid4())
    response_log = []
    actions_performed = []

    ip = layer3_output.get("IP Address")
    severity = layer3_output.get("Severity", "Low")
    incident_desc = layer4_output.get("Incident Explanation")
    attack_type = layer3_output.get("Prediction", "Unknown")

    confidence = layer3_output.get("Confidence", 0)
    anomaly = layer3_output.get("Anomaly Score", 0)
    abuse = layer3_output.get("Threat Intel", {}).get("AbuseIPDB", {}).get("abuse_score", 0)
    risk_score = round((confidence * 0.4 + anomaly * 0.3 + (abuse / 100) * 0.3), 2)
    
    playbook = SOAR_PLAYBOOKS.get(severity, SOAR_PLAYBOOKS["Low"])

    for step in playbook:
        action = step["action"]

        if action == "block_ip":
            result = firewall_block_ip(ip)
            actions_performed.append("Block IP")
        
        elif action == "send_alert":
            result = send_alert(incident_desc, severity)
            actions_performed.append("Send Alert")
        
        elif action == "update_ticket":
            status = step.get("status", "Open")
            result = update_ticket(status, incident_desc)
            actions_performed.append(f"Update Ticket ({status})")
        
        else:
            result = f"[Unknown Action] {action}"

        failed = any(log["status"] != "success" for log in response_log)
        if failed:
            incident_status = "Failed"

        elif severity == "High":
            incident_status = "Escalated"

        elif severity == "Medium":
            incident_status = "Investigating"

        else:
            incident_status = "Resolved"
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "executor": "SOAR Engine v1.0",
            "status": "success",
            "result": result
        }
        time.sleep(0.2)

        response_log.append(log_entry)

    return {
        "Incident ID": incident_id,
        "Playbook Executed": f"{attack_type} - {severity} Severity Playbook",
        "Risk Score": risk_score,
        "MITRE Technique": layer4_output.get("MITRE Technique"),
        "Actions Performed": actions_performed,
        "Incident Status": playbook[-1].get("status", "Completed"),
        "Response Log": response_log
    }