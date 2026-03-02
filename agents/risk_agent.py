from agents.state import AgentState
from memory.sqlite_manager import get_historical_recurrence_factor, update_entity_history

def calculate_risk_node(state: AgentState) -> dict:
    """Calculates an advanced risk score based on multi-factor weighted heuristics."""
    classification = state.get("attack_classification", "None")
    anomalies = state.get("anomalies", [])
    
    if not anomalies or classification == "None":
        return {"risk_score": 0, "risk_category": "Low"}
        
    # Factor 1: Attack Severity (0-100)
    severity_weight = 0
    if classification == "Ransomware":
        severity_weight = 100
    elif classification == "Brute Force":
        severity_weight = 60
    elif classification == "Port Scan":
        severity_weight = 30
    elif classification == "Suspicious IP Activity":
        severity_weight = 50
    elif classification == "DDoS":
        severity_weight = 90
    else:
        severity_weight = 40
        
    # Factor 2: Anomaly Confidence (0-100 proxy using volume)
    anomaly_confidence = min(100, len(anomalies) * 5)
    
    # Factor 3: Historical Recurrence (0-100 from memory)
    ips = list(set([a.get("source_ip") for a in anomalies if a.get("source_ip")]))
    users = list(set([a.get("username") for a in anomalies if a.get("username")]))
    historical_recurrence = get_historical_recurrence_factor(ips, users)
    
    # Factor 4: Graph Centrality (0-100 from state)
    graph_centrality = state.get("graph_centrality", 0.0)
    
    # Factor 5: Asset Criticality (0-100 heuristic based on ports)
    asset_criticality = 50 # Default baseline
    target_ports = [a.get("destination_port") for a in anomalies if a.get("destination_port")]
    if 22 in target_ports or 3389 in target_ports:
        asset_criticality = 90 # High for SSH/RDP
    elif 443 in target_ports or 80 in target_ports:
        asset_criticality = 70
        
    # Advanced Formula
    risk_score = (
        (anomaly_confidence * 0.25) +
        (severity_weight * 0.25) +
        (historical_recurrence * 0.20) +
        (graph_centrality * 0.15) +
        (asset_criticality * 0.15)
    )
    
    final_score = int(min(100, risk_score))
    
    if final_score >= 80:
        category = "Critical"
    elif final_score >= 60:
        category = "High"
    elif final_score >= 40:
        category = "Medium"
    else:
        category = "Low"
        
    # Update SQLite Memory with this latest offense
    update_entity_history(ips, users, final_score)
        
    return {
        "risk_score": final_score, 
        "risk_category": category,
        "historical_recurrence": historical_recurrence,
        "asset_criticality": asset_criticality
    }
