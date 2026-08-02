import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "honeypot-scripts" / "cowrie_to_sqlite.py"


class CowrieIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.log = root / "cowrie.json"
        self.db = root / "alerts.db"
        self.state = root / "offset.json"
        os.environ.update(
            COWRIE_JSON_LOG=str(self.log),
            ALERTS_DB_PATH=str(self.db),
            INGEST_STATE_FILE=str(self.state),
            ENABLE_REMOTE_GEO="false",
        )
        spec = importlib.util.spec_from_file_location("cowrie_to_sqlite_test", MODULE_PATH)
        self.module = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(self.module)
        self.module.init_db()

    def tearDown(self):
        self.temp.cleanup()

    def append(self, event):
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")

    def test_connection_is_deduplicated_and_login_updates_row(self):
        connect = {
            "eventid": "cowrie.session.connect",
            "session": "abc",
            "src_ip": "203.0.113.10",
            "src_port": 45000,
            "timestamp": "2026-08-02T13:00:00Z",
        }
        self.append(connect)
        self.assertEqual(self.module.process_available(), 1)
        self.assertEqual(self.module.process_available(), 0)

        self.append(
            {
                "eventid": "cowrie.login.failed",
                "session": "abc",
                "src_ip": "203.0.113.10",
                "username": "root",
                "password": "test",
                "timestamp": "2026-08-02T13:00:03Z",
            }
        )
        self.assertEqual(self.module.process_available(), 1)
        self.append(
            {
                "eventid": "cowrie.command.input",
                "session": "abc",
                "src_ip": "203.0.113.10",
                "input": "uname -a",
                "message": "Command found: uname -a",
                "timestamp": "2026-08-02T13:00:04Z",
            }
        )
        self.assertEqual(self.module.process_available(), 1)
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute(
                "SELECT event_type, username, password, command, message FROM alerts"
            ).fetchall()
            attempts = conn.execute(
                "SELECT username, password, success FROM login_attempts"
            ).fetchall()
        self.assertEqual(
            rows,
            [("cowrie.login.failed", "root", "test", "uname -a", "Command found: uname -a")],
        )
        self.assertEqual(attempts, [("root", "test", 0)])


if __name__ == "__main__":
    unittest.main()
