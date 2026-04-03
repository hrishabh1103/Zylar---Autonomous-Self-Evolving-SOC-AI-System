import json
import uuid
import datetime
from pathlib import Path
from fpdf import FPDF
from agents.state import AgentState
from memory.sqlite_manager import log_incident

import os
REPORTS_DIR = Path(os.path.join(os.path.dirname(__file__), "..", "reports")).resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def generate_report_node(state: AgentState) -> dict:
    """Generates the final incident report as JSON and PDF."""
    print("\n[DEBUG] --- Executing generate_report_node ---")
    
    try:
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        
        anomalies = state.get("anomalies", [])
        event_id = "unknown"
        if anomalies and isinstance(anomalies, list):
            if "event_id" in anomalies[0]:
                event_id = str(anomalies[0]["event_id"])[:8]
            elif "event_id" in anomalies[0].get("logs", [{}])[0]:
                event_id = str(anomalies[0]["logs"][0]["event_id"])[:8]
                
        # Generate stable UUID
        timestamp_clean = timestamp.replace(':', '').replace('-', '').split('.')[0]
        incident_id = f"ZYLAR-INC-{timestamp_clean}-{event_id.upper()}-{uuid.uuid4().hex[:8].upper()}"
        
        # Ensure attack classification is a string
        attack_class = str(state.get("attack_classification", "Unknown Investigation"))
        if attack_class == "None":
            attack_class = "Unclassified Anomaly"
            
        print("Saving report...")
        print(f"Report ID: {incident_id}")
        
        report_content = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "attack_classification": attack_class,
            "risk_category": str(state.get("risk_category", "Unknown")),
            "risk_score": int(state.get("risk_score", 0)),
            "threat_intel": state.get("threat_intel", {}),
            "mitigation_plan": state.get("mitigation_plan", []),
            "anomalous_events_count": len(state.get("anomalies", []))
        }
        
        # Save JSON
        json_path = REPORTS_DIR / f"{incident_id}.json"
        with open(json_path, 'w') as f:
            json.dump(report_content, f, indent=4)
            
        # Save PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        pdf.cell(200, 10, txt="ZYLAR INCIDENT REPORT", ln=1, align='C')
        pdf.cell(200, 10, txt=f"Incident ID: {incident_id}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Time: {timestamp}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Classification: {attack_class}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Risk: {report_content['risk_score']} ({report_content['risk_category']})", ln=1, align='L')
        
        pdf.cell(200, 10, txt="Mitigation Plan:", ln=1, align='L')
        for step in report_content.get('mitigation_plan', []):
            # Encode correctly to avoid FPDF character errors
            step_encoded = str(step).encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(200, 10, txt=f"- {step_encoded}", ln=1, align='L')
            
        pdf_path = REPORTS_DIR / f"{incident_id}.pdf"
        pdf.output(str(pdf_path))
        
        # Store incident in SQLite memory
        log_incident(report_content)
        
        print(f"[DEBUG] Report {incident_id} successfully generated and stored.")
        return {"incident_id": incident_id, "report_content": report_content}
        
    except Exception as e:
        print(f"[ERROR] Critical failure in report_agent: {e}")
        return {"incident_id": "ERROR", "report_content": {}}
