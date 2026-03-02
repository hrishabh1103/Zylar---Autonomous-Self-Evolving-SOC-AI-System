import time
import random
import uuid
import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Configure Elasticsearch client (Local instance, security disabled)
ES_HOST = "http://localhost:9200"
INDEX_NAME = "zylar-logs"

es = Elasticsearch([ES_HOST])

def setup_index():
    """Create the index if it doesn't exist."""
    try:
        es.indices.create(index=INDEX_NAME)
        print(f"Created index: {INDEX_NAME}")
    except Exception as e:
        # Index already exists or error
        pass

def generate_log(event_type: str, ip: str, user: str, status: str, details: str) -> dict:
    """Helper to structure log document."""
    return {
        "_index": INDEX_NAME,
        "_source": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "source_ip": ip,
            "user": user,
            "status": status,
            "details": details
        }
    }

def simulate_brute_force(ip: str, user: str, count: int = 15):
    """Generate multiple failed login attempts followed perhaps by a success."""
    logs = []
    for _ in range(count):
        logs.append(generate_log("authentication", ip, user, "failed", "Invalid credentials"))
        time.sleep(0.01)
    return logs

def simulate_port_scan(ip: str):
    """Generate connection attempts to multiple unusual ports sequentially."""
    logs = []
    ports = random.sample(range(1, 1024), 20)
    for port in ports:
        logs.append(generate_log("network", ip, "system", "rejected", f"Connection attempt to closed port {port}"))
        time.sleep(0.01)
    return logs

def simulate_ransomware_access(ip: str, user: str):
    """Generate high volume of file read/write/encrypt operations."""
    logs = []
    for i in range(25):
        ext = random.choice([".doc", ".pdf", ".xls", ".jpg"])
        logs.append(generate_log("file_access", ip, user, "success", f"File modified: /shared/docs/file_{i}{ext}.encrypted"))
        time.sleep(0.01)
    return logs

def simulate_normal_activity():
    """Generate standard web access or safe login."""
    users = ["alice", "bob", "charlie", "david"]
    ips = [f"192.168.1.{random.randint(10, 50)}" for _ in range(5)]
    return [generate_log(
        "web_access",
        random.choice(ips),
        random.choice(users),
        "success",
        f"Accessed page {random.choice(['/home', '/dashboard', '/profile', '/api/data'])}"
    )]

def simulate_suspicious_ip_activity():
    """Activity from a known bad IP subnet or strange geo (simulated by IP string)."""
    malicious_ip = f"185.15.{random.randint(1, 255)}.{random.randint(1, 255)}"
    return [generate_log("authentication", malicious_ip, "admin", "failed", "Geo-policy violation")]

def run_simulation(duration_seconds: int = 60, batch_size: int = 1):
    """Runs a continuous stream of logs mixing normal and attack activity."""
    setup_index()
    print(f"Starting simulation for {duration_seconds} seconds...")
    start_time = time.time()
    
    attack_ips = ["203.0.113.45", "198.51.100.22", "10.0.0.99"]
    users = ["root", "admin", "service_account"]
    
    while time.time() - start_time < duration_seconds:
        logs_to_push = []
        
        # 80% normal activity, 20% attacks
        if random.random() < 0.8:
            for _ in range(batch_size):
                logs_to_push.extend(simulate_normal_activity())
        else:
            attack_type = random.choice(["brute_force", "port_scan", "ransomware", "suspicious_ip"])
            if attack_type == "brute_force":
                logs_to_push.extend(simulate_brute_force(random.choice(attack_ips), random.choice(users), random.randint(10, 30)))
            elif attack_type == "port_scan":
                logs_to_push.extend(simulate_port_scan(random.choice(attack_ips)))
            elif attack_type == "ransomware":
                logs_to_push.extend(simulate_ransomware_access(random.choice(attack_ips), "compromised_user"))
            elif attack_type == "suspicious_ip":
                logs_to_push.extend(simulate_suspicious_ip_activity())
        
        # Push to Elasticsearch
        if logs_to_push:
            try:
                bulk(es, logs_to_push)
                print(f"Pushed {len(logs_to_push)} logs. Timestamp: {datetime.datetime.utcnow().time()}")
            except Exception as e:
                print(f"Error pushing logs: {e}")
        
        time.sleep(random.uniform(0.5, 2.0))
        
    print("Simulation finished.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=300, help="Duration to run simulation in seconds")
    args = parser.parse_args()
    
    run_simulation(args.duration)
