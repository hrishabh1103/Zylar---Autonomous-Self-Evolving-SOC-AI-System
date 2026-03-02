import os
import json
import ollama
from agents.state import AgentState

def extract_threat_intel_node(state: AgentState) -> dict:
    """Uses LLM to evaluate the TTPs from the anomalous events."""
    anomalies = state.get("anomalies", [])
    if not anomalies:
        return {"threat_intel": {"status": "No anomalies found", "summary": "System appears secure."}}
        
    prompt = f"""You are a Threat Intelligence AI. 
Analyze the following anomalous events and identify potential TTPs (Tactics, Techniques, and Procedures).
Return a concise summary of the threat landscape in JSON format with keys: "summary", "attacker_ips", "targeted_users".
Anomalies: {anomalies[:50]}""" # Limit to avoid context bloom

    try:
        response = ollama.chat(
            model='mistral',
            messages=[
                {'role': 'system', 'content': 'You are a senior cybersecurity threat intelligence analyst. Always respond in valid JSON.'},
                {'role': 'user', 'content': prompt}
            ],
            options={'temperature': 0.1}
        )
        content = response['message']['content']
        # attempt to parse JSON
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].strip()
        intel = json.loads(content)
    except Exception as e:
        intel = {"summary": "Error parsing local LLM response", "raw_response": str(e), "attacker_ips": [], "targeted_users": []}
        
    return {"threat_intel": intel}
