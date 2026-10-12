import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from soc import analyze_events, sample_events
from triage import TriageStore, alert_id


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "data" / "soc.db"
        self.store = TriageStore(self.path)

    def test_save_survives_reopening_and_updates(self):
        self.store.save("alert-1", "Investigating", "Validate the source 'IP'.")
        reopened = TriageStore(self.path)
        self.assertEqual(reopened.records()["alert-1"].notes, "Validate the source 'IP'.")
        reopened.save("alert-1", "Resolved", "Expected activity")
        records = self.store.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records["alert-1"].status, "Resolved")
        self.assertIsNotNone(records["alert-1"].updated_at)

    def test_invalid_decisions_do_not_save(self):
        with self.assertRaises(ValueError):
            self.store.save("alert-1", "Invalid", "")
        with self.assertRaises(ValueError):
            self.store.save("alert-1", "Open", "x" * 10001)
        self.assertEqual(self.store.records(), {})

    def test_identity_is_stable_and_dataset_scoped(self):
        alert = analyze_events(sample_events())[0]
        self.assertEqual(alert_id(alert, "one"), alert_id(alert, "one"))
        self.assertNotEqual(alert_id(alert, "one"), alert_id(alert, "two"))
        self.assertNotEqual(alert_id(alert, "one"), alert_id(replace(alert, event_count=999), "one"))
