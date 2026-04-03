from agents.state import AgentState

def analyze_logs_node(state: AgentState) -> dict:
    """Parses raw logs and identifies actionable events."""
    print("\n[DEBUG] --- Executing analyze_logs_node ---")
    raw_logs = state.get("raw_logs", [])
    
    parsed_events = []
    for log in raw_logs:
        # Check if logs are coming directly from python objects or dicts
        source = log.get("_source", log) if isinstance(log, dict) else log
        
        parsed_events.append({
            "event_id": source.get("event_id"),
            "timestamp": source.get("timestamp"),
            "event_type": source.get("event_type"),
            "source_ip": source.get("source_ip"),
            "user": source.get("user"),
            "status": source.get("status"),
            "details": source.get("details"),
        })
    
    return {"parsed_events": parsed_events}
