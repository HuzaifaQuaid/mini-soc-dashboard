import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


class DashboardTests(unittest.TestCase):
    def test_public_demo_is_session_only_and_has_no_uploads(self):
        path = str(Path(__file__).parents[1] / "public_app.py")
        with patch("app.TriageStore", side_effect=AssertionError("Public demo must not use SQLite")):
            first = AppTest.from_file(path, default_timeout=30).run()
            self.assertEqual(len(first.exception), 0)
            self.assertEqual(first.radio[0].options, ["Demo dataset"])
            self.assertEqual(len(first.get("file_uploader")), 0)
            next(s for s in first.selectbox if s.label == "Analyst status").select("Resolved")
            next(t for t in first.text_area if t.label == "Investigation notes").input("Practice review")
            next(b for b in first.button if b.label == "Save triage").click()
            first.run()
            self.assertEqual(len(first.exception), 0)
            self.assertEqual(next(iter(first.session_state["public_triage"].values())).notes, "Practice review")
            second = AppTest.from_file(path, default_timeout=30).run()
            self.assertEqual(len(second.exception), 0)
            self.assertEqual(second.session_state["public_triage"], {})

    def test_dashboard_runs_and_search_accepts_regex_characters(self):
        from triage import TriageStore
        with tempfile.TemporaryDirectory() as temp:
            store = TriageStore(Path(temp) / "soc.db")
            with patch("triage.TriageStore", return_value=store):
                app = AppTest.from_file(str(Path(__file__).parents[1] / "app.py"), default_timeout=30).run()
                self.assertEqual(len(app.exception), 0)
                next(s for s in app.selectbox if s.label == "Analyst status").select("Resolved")
                next(t for t in app.text_area if t.label == "Investigation notes").input("Reviewed locally")
                next(b for b in app.button if b.label == "Save triage").click()
                app.run()
                self.assertEqual(len(app.exception), 0)
                self.assertEqual(next(iter(store.records().values())).status, "Resolved")
                next(t for t in app.text_input if t.label == "Search").input("[")
                app.run()
                self.assertEqual(len(app.exception), 0)
                self.assertTrue(any("No alerts match" in message.value for message in app.info))
