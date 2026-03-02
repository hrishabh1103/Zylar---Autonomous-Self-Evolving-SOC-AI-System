import pandas as pd
from sklearn.ensemble import IsolationForest
from agents.state import AgentState

def detect_anomalies_node(state: AgentState) -> dict:
    """Uses scikit-learn Isolation Forest to detect statistical anomalies in log frequency and IP behavior."""
    events = state.get("parsed_events", [])
    if not events:
        return {"anomalies": []}
        
    df = pd.DataFrame(events)
    
    if len(df) < 5:
        # Not enough data for meaningful ML anomaly detection, fallback to simple heuristic
        anomalies = [e for e in events if e.get("status") in ["failed", "rejected"] or e.get("event_type") == "ransomware"]
        return {"anomalies": anomalies}
    
    # Feature engineering
    ip_counts = df['source_ip'].value_counts().to_dict()
    df['ip_frequency'] = df['source_ip'].map(ip_counts)
    
    status_map = {"failed": 1, "rejected": 1, "success": 0}
    df['status_num'] = df['status'].map(status_map).fillna(0)
    
    features = df[['ip_frequency', 'status_num']].fillna(0)
    
    clf = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    df['anomaly'] = clf.fit_predict(features)
    df['anomaly_score'] = clf.decision_function(features)
    
    # Filter anomalies (where anomaly == -1)
    anomalies_df = df[df['anomaly'] == -1]
    
    # Convert to standard dict (dropping non-serializable objects if necessary)
    anomalies = anomalies_df.drop(columns=['anomaly', 'anomaly_score']).to_dict(orient="records")
    
    return {"anomalies": anomalies}
