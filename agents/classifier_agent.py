import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from agents.state import AgentState

def classify_attack_node(state: AgentState) -> dict:
    """Classifies the attack type based on anomalies and threat intel."""
    intel = state.get("threat_intel", {})
    anomalies = state.get("anomalies", [])
    
    if not anomalies:
        return {"attack_classification": "None"}
        
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
    
    prompt = f"""You are an Attack Classification Agent. 
Based on the following threat intel and anomalous events, classify the attack into ONE of these categories:
- Brute Force
- Port Scan
- Ransomware
- Suspicious IP Activity
- DDoS
- Unknown

Threat Intel: {json.dumps(intel)}
Number of Anomalous Events: {len(anomalies)}
Sample anomaly details: {[a.get('details') for a in anomalies[:3]]}

Return ONLY the classification string from the list above."""

    messages = [
        SystemMessage(content="You are a strict classifier. Respond ONLY with the attack category name."),
        HumanMessage(content=prompt)
    ]
    
    response = llm.invoke(messages)
    classification = response.content.strip()
    
    return {"attack_classification": classification}
