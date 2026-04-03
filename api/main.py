import os
import json
import logging
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from elasticsearch import Elasticsearch
from orchestrator.workflow_graph import build_workflow
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from agents.log_analyzer import analyze_logs_node
from agents.anomaly_agent import detect_anomalies_node
from memory.sqlite_manager import get_top_offenders, is_event_processed, mark_event_processed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ZYLAR-Autonomous")

app = FastAPI(title="ZYLAR API - Autonomous Cybersecurity Platform")
ES_HOST = "http://localhost:9200"
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

anomaly_queue = []

class RunWorkflowRequest(BaseModel):
    logs: List[Dict[str, Any]]

@app.post("/api/workflow/run")
async def run_workflow(req: RunWorkflowRequest):
    """Triggers the full agentic workflow on a set of logs."""
    try:
        graph = build_workflow()
        final_state = graph.invoke({"raw_logs": req.logs})
        
        return {
            "incident_id": final_state.get("incident_id"),
            "attack_classification": final_state.get("attack_classification"),
            "risk_score": final_state.get("risk_score"),
            "risk_category": final_state.get("risk_category"),
            "mitigation_plan": final_state.get("mitigation_plan")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs/recent")
async def get_recent_logs(minutes: int = 5):
    """Fetches recent logs from Elasticsearch."""
    try:
        es = Elasticsearch([ES_HOST])
        now = datetime.utcnow()
        past = now - timedelta(minutes=minutes)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": past.isoformat() + "Z",
                        "lte": now.isoformat() + "Z"
                    }
                }
            },
            "size": 1000,
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        res = es.search(index="zylar-logs", body=query)
        return {"logs": [hit["_source"] for hit in res["hits"]["hits"]]}
    except Exception as e:
        return {"error": str(e), "logs": []}

@app.get("/api/reports")
async def get_reports():
    """Fetches generated incident reports."""
    reports = []
    if os.path.exists(REPORTS_DIR):
        for file in os.listdir(REPORTS_DIR):
            if file.endswith(".json"):
                with open(os.path.join(REPORTS_DIR, file), 'r') as f:
                    try:
                        reports.append(json.load(f))
                    except:
                        pass
    
    # Sort by timestamp descending
    reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    print(f"Returning {len(reports)} reports")
    return {"reports": reports}

@app.get("/api/offenders")
async def get_offenders():
    """Fetches top offenders from SQLite memory."""
    try:
        data = get_top_offenders(limit=5)
        return {"status": "success", "data": data}
    except Exception as e:
        logger.error(f"Error fetching offenders: {e}")
        return {"status": "error", "data": {"top_ips": [], "top_users": []}}

def check_for_threats():
    global anomaly_queue
    logger.info("Autonomous System: Scanning for threats...")
    try:
        es = Elasticsearch([ES_HOST])
        now = datetime.utcnow()
        past = now - timedelta(seconds=120)  # Extend to 120s to match scheduler
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": past.isoformat() + "Z",
                        "lte": now.isoformat() + "Z"
                    }
                }
            },
            "size": 500
        }
        res = es.search(index="zylar-logs", body=query)
        logs = [hit["_source"] for hit in res["hits"]["hits"]]
        
        if not logs:
            logger.info("No logs in the last 120s. Proceeding with empty list for debugging pipeline.")
            # return # TEMPORARILY DISABLED FOR DEBUGGING

        # Pre-check for anomalies locally before running the full LLM heavy graph
        state = analyze_logs_node({"raw_logs": logs})
        state = detect_anomalies_node(state)
        
        anomalies = state.get("anomalies", [])
        if anomalies:
            logger.warning(f"Detected {len(anomalies)} anomalies! Queuing individually...")
            
            for anomaly in anomalies:
                event_id = anomaly.get("event_id")
                if event_id and is_event_processed(event_id):
                    continue
                # Only add if not already in queue
                if not any(a.get("event_id") == event_id for a in anomaly_queue):
                    anomaly_queue.append(anomaly)
                    
        print(f"Queue size: {len(anomaly_queue)}")
        print(f"Processing 1 anomaly per cycle")
        
        if anomaly_queue:
            graph = build_workflow()
            anomaly = anomaly_queue.pop(0)
            event_id = anomaly.get("event_id")
                
            if event_id:
                print(f"Processing queued anomaly: {event_id} with {len(anomaly.get('logs', []))} logs")
            else:
                print("Processing queued fallback anomaly...")
                
            # Invoke the pipeline independently for this specific grouped anomaly
            # Pass both the raw logs and the manually grouped anomaly array to bypass ML clearing
            final_state = graph.invoke({
                "raw_logs": anomaly.get("logs", [anomaly]),
                "anomalies": [anomaly]
            })
            print("Generating incident...")
            
            risk_score = final_state.get('risk_score', 0)
            incident_id = final_state.get('incident_id')
            
            if incident_id and incident_id != "None":
                print(f"Incident created with risk: {risk_score}")
                print("Report successfully generated and stored")
            
            if event_id:
                mark_event_processed(event_id)
                
        else:
            logger.info("Logs analyzed. No statistical anomalies found and queue is empty.")
            
    except Exception as e:
        logger.error(f"Error in autonomous check: {e}")

@app.on_event("startup")
def start_scheduler():
    scheduler = BackgroundScheduler()
    # Run every 120 seconds, coalesce runs, only 1 instance
    scheduler.add_job(
        check_for_threats, 
        'interval', 
        seconds=120, 
        max_instances=1, 
        coalesce=True
    )
    scheduler.start()
    logger.info("Autonomous background scheduler started.")
