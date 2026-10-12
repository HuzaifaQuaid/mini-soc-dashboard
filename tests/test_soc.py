import json
import unittest

from soc import analyze_events, load_events


class ParserTests(unittest.TestCase):
    def test_csv_normalization(self):
        raw = "timestamp,type,src_ip,user,result,message\n2026-10-07T12:00:00Z,ssh,198.51.100.2,admin,failed,Failed SSH password"
        events = load_events(raw, "events.csv")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_ip, "198.51.100.2")
        self.assertEqual(events[0].status, "failed")

    def test_json_array(self):
        raw = json.dumps([{"timestamp": "2026-10-07T12:00:00Z", "event_type": "authentication", "source_ip": "198.51.100.2", "status": "success"}])
        self.assertEqual(len(load_events(raw, "events.json")), 1)


class DetectionTests(unittest.TestCase):
    def test_brute_force_and_success_after_failures(self):
        events = load_events(None, None)
        alerts = analyze_events(events, threshold=5, window_minutes=10)
        titles = {a.title for a in alerts}
        self.assertIn("Repeated failed logins", titles)
        self.assertIn("Successful login after repeated failures", titles)
        self.assertIn("Possible port scan", titles)

    def test_threshold_is_configurable(self):
        events = load_events(None, None)
        alerts = analyze_events(events, threshold=50, window_minutes=10)
        self.assertFalse(any(a.rule_id == "AUTH-001" for a in alerts))


if __name__ == "__main__":
    unittest.main()
