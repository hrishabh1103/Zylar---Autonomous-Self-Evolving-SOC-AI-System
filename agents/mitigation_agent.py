import json
import ollama
from agents.state import AgentState

def generate_mitigation_node(state: AgentState) -> dict:
    """Generates an action plan to mitigate the threat."""
    classification = state.get("attack_classification", "None")
    risk_score = state.get("risk_score", 0)
    intel = state.get("threat_intel", {})
    
    if classification == "None" or risk_score < 20:
        return {"mitigation_plan": ["Monitor logs for future suspicious activity."]}
        
    prompt = f"""You are an Autonomous Cybersecurity Responder. 
Generate a list of exactly 3 concise, actionable mitigation steps for the following scenario:
Attack Type: {classification}
Risk Score: {risk_score}/100
Context: {json.dumps(intel)}

Return the steps as a JSON list of strings."""

    try:
        response = ollama.chat(
            model='mistral',
            messages=[
                {'role': 'system', 'content': 'You are a mitigation planner. Respond with a valid JSON array of strings.'},
                {'role': 'user', 'content': prompt}
            ],
            options={'temperature': 0.1}
        )
        content = response['message']['content']
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].strip()
        plan = json.loads(content)
        if not isinstance(plan, list):
            plan = [str(x) for x in plan.values()]
    except Exception as e:
        plan = [f"Block offending IP addresses manually", "Isolate affected hosts", f"Investigate {classification} activity"]
        
    return {"mitigation_plan": plan}
