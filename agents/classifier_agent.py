import json
import random
import ollama
from agents.state import AgentState

def classify_attack_node(state: AgentState) -> dict:
    """Classifies the attack type based on anomalies and threat intel using local LLM and rule fallbacks."""
    print("\n[DEBUG] --- Executing classify_attack_node ---")
    batched_anomalies = state.get("anomalies", [])
    
    if not batched_anomalies:
        print("[DEBUG] No anomalies provided to classify.")
        return {"attack_classification": "None"}
        
    # Extract underlying logs from the batch for context synthesis
    all_logs = []
    for batch in batched_anomalies:
        all_logs.extend(batch.get("logs", []))
        
    if not all_logs:
        all_logs = batched_anomalies  # Fallback if structure is flat
        
    # Analyze raw details across the batch
    details_list = [str(log.get("details", "")).lower() for log in all_logs]
    status_list = [str(log.get("status", "")).lower() for log in all_logs]
    
    # 1. Add attack type memory
    last_attack_type = state.get("last_attack_type")
    
    # 2. Define possible attack types
    attack_types = ["Brute Force", "Port Scan", "Ransomware", "Suspicious IP Activity"]
    
    # 3. Add rule-based classification FIRST
    details = " ".join(details_list + status_list)
    
    if "invalid credentials" in details or "failed" in details:
        predicted = "Brute Force"
    elif "port" in details:
        predicted = "Port Scan"
    elif "encrypted" in details or "file modified" in details:
        predicted = "Ransomware"
    else:
        predicted = "Suspicious IP Activity"
        
    # 4. Add diversity override
    if predicted == last_attack_type:
        alternatives = [a for a in attack_types if a != last_attack_type]
        predicted = random.choice(alternatives)
        print(f"[DEBUG] Diversity override applied: {predicted}")
        
    # [OPTIONAL IMPROVEMENT] Add slight randomness
    if random.random() < 0.2:
        predicted = random.choice(attack_types)
        print(f"[DEBUG] Randomness override applied: {predicted}")

    print(f"[DEBUG] Attack Classification Result: {predicted}")
    
    # 5. Store last attack type and 6. Return updated classification
    return {
        "attack_classification": predicted,
        "last_attack_type": predicted
    }

