import unittest
from agents.anomaly_agent import detect_anomalies_node

class TestAnomalyAgent(unittest.TestCase):
    def test_detect_anomalies_empty(self):
        """Test with no events"""
        state = {"parsed_events": []}
        result = detect_anomalies_node(state)
        self.assertEqual(result["anomalies"], [])

    def test_detect_anomalies_few_events(self):
        """Test fallback heuristic when data is insufficient for ML (< 5 logs)"""
        state = {
            "parsed_events": [
                {"source_ip": "1.1.1.1", "status": "failed", "event_type": "auth"},
                {"source_ip": "2.2.2.2", "status": "success", "event_type": "auth"},
            ]
        }
        result = detect_anomalies_node(state)
        # Should flag the failed event based on heuristic
        self.assertEqual(len(result["anomalies"]), 1)
        self.assertEqual(result["anomalies"][0]["source_ip"], "1.1.1.1")

    def test_detect_anomalies_ml(self):
        """Test Isolation Forest with synthetic batch data"""
        events = []
        # Normal behavior
        for i in range(50):
            for _ in range(10):
                events.append({"source_ip": f"192.168.1.{i}", "status": "success", "event_type": "web_access"})
        # Anomalous behavior (Brute force from single IP)
        for _ in range(15):
            events.append({"source_ip": "10.0.0.99", "status": "failed", "event_type": "authentication"})
            
        state = {"parsed_events": events}
        result = detect_anomalies_node(state)
        
        # ML model should flag the repetitive failed logins as anomalous
        self.assertTrue(len(result["anomalies"]) > 0)
        self.assertEqual(result["anomalies"][0]["source_ip"], "10.0.0.99")

if __name__ == '__main__':
    unittest.main()
