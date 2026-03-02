from langgraph.graph import StateGraph, END
from agents.state import AgentState
from agents.log_analyzer import analyze_logs_node
from agents.anomaly_agent import detect_anomalies_node
from agents.threat_agent import extract_threat_intel_node
from agents.classifier_agent import classify_attack_node
from agents.correlation_agent import build_threat_correlation_graph_node
from agents.risk_agent import calculate_risk_node
from agents.mitigation_agent import generate_mitigation_node
from agents.report_agent import generate_report_node

def build_workflow() -> StateGraph:
    """Builds the LangGraph deterministic workflow for ZYLAR."""
    workflow = StateGraph(AgentState)
    
    # Add Nodes
    workflow.add_node("analyze_logs", analyze_logs_node)
    workflow.add_node("detect_anomalies", detect_anomalies_node)
    workflow.add_node("extract_threat_intel", extract_threat_intel_node)
    workflow.add_node("classify_attack", classify_attack_node)
    workflow.add_node("build_correlation_graph", build_threat_correlation_graph_node)
    workflow.add_node("calculate_risk", calculate_risk_node)
    workflow.add_node("generate_mitigation", generate_mitigation_node)
    workflow.add_node("generate_report", generate_report_node)
    
    # Define Edges (Deterministic path)
    workflow.set_entry_point("analyze_logs")
    workflow.add_edge("analyze_logs", "detect_anomalies")
    workflow.add_edge("detect_anomalies", "extract_threat_intel")
    workflow.add_edge("extract_threat_intel", "classify_attack")
    workflow.add_edge("classify_attack", "build_correlation_graph")
    workflow.add_edge("build_correlation_graph", "calculate_risk")
    workflow.add_edge("calculate_risk", "generate_mitigation")
    workflow.add_edge("generate_mitigation", "generate_report")
    workflow.add_edge("generate_report", END)
    
    return workflow.compile()
