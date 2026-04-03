import networkx as nx
from agents.state import AgentState

def build_threat_correlation_graph_node(state: AgentState) -> dict:
    """Uses NetworkX to build an attack graph from log events and identify highly connected entities."""
    print("\n[DEBUG] --- Executing build_threat_correlation_graph_node ---")
    events = state.get("anomalies", [])
    if not events:
        return {"graph_centrality": 0.0}
        
    G = nx.Graph()
    
    # Add edges based on log activity
    for event in events:
        src_ip = event.get("source_ip")
        user = event.get("username")
        dest_port = event.get("destination_port")
        action = event.get("action", event.get("event_type", "unknown"))
        
        if src_ip and user:
            # Login action binds IP to User
            G.add_edge(f"IP:{src_ip}", f"User:{user}", weight=1, type="login_attempt")
            
        if src_ip and dest_port:
            # IP attacking a specific port/service
            G.add_edge(f"IP:{src_ip}", f"Port:{dest_port}", weight=1, type="scan")

    if len(G.nodes) == 0:
        return {"graph_centrality": 0.0}
        
    # Calculate degree centrality - how connected a node is
    deg_centrality = nx.degree_centrality(G)
    
    # Calculate betweenness centrality - paths going through node
    # Add a try/except because betweenness can fail on certain graph shapes
    try:
        bet_centrality = nx.betweenness_centrality(G)
    except:
        bet_centrality = {node: 0.0 for node in G.nodes}
        
    max_centrality_score = 0.0
    for node in G.nodes:
        # Combine degree and betweenness for an overall importance score for the node
        score = (deg_centrality.get(node, 0.0) * 0.6) + (bet_centrality.get(node, 0.0) * 0.4)
        if score > max_centrality_score:
            max_centrality_score = score
            
    # Normalize our custom max score into a heuristic 0-100 metric broadly
    # High centrality means something is scanning many items or a user is logging from many IPs
    normalized_centrality = min(100.0, max_centrality_score * 100 * 5)
    
    return {"graph_centrality": normalized_centrality}
