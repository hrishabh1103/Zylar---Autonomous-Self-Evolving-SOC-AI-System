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
    if state.get("attack_classification") == "None":
        return {"incident_id": "None", "report_content": {}}
        
    incident_id = f"ZYLAR-INC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    report_content = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "attack_classification": state.get("attack_classification"),
        "risk_category": state.get("risk_category"),
        "risk_score": state.get("risk_score"),
        "threat_intel": state.get("threat_intel"),
        "mitigation_plan": state.get("mitigation_plan"),
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
    pdf.cell(200, 10, txt=f"Classification: {state.get('attack_classification')}", ln=1, align='L')
    pdf.cell(200, 10, txt=f"Risk: {state.get('risk_score')} ({state.get('risk_category')})", ln=1, align='L')
    
    pdf.cell(200, 10, txt="Mitigation Plan:", ln=1, align='L')
    for step in state.get('mitigation_plan', []):
        pdf.cell(200, 10, txt=f"- {step}", ln=1, align='L')
        
    pdf_path = REPORTS_DIR / f"{incident_id}.pdf"
    pdf.output(str(pdf_path))
    
    # Store incident in SQLite memory
    log_incident(report_content)
    
    return {"incident_id": incident_id, "report_content": report_content}
