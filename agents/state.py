from typing import TypedDict, List, Dict, Any

class AgentState(TypedDict):
    # Log Layer
    raw_logs: List[Dict[str, Any]]
    
    # Analyzer Layer
    parsed_events: List[Dict[str, Any]]
    
    # Anomaly Layer
    anomalies: List[Dict[str, Any]]
    
    # Threat Intelligence
    threat_intel: Dict[str, Any]
    
    # Classification
    attack_classification: str
    last_attack_type: str
    
    # Correlation & History
    graph_centrality: float
    historical_recurrence: int
    asset_criticality: int
    
    # Risk
    risk_score: int
    risk_category: str
    
    # Mitigation
    mitigation_plan: List[str]
    
    # Report
    incident_id: str
    report_content: Dict[str, Any]
