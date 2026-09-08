import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = ""
os.environ["DATABASE_SCHEMA"] = "sentinel_ai"

from app import database


class DatabaseAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.original_db_file = database.DB_FILE
        database.DB_FILE = str(Path(self.temp_directory.name) / "sentinel.db")
        self.environment = patch.dict(
            os.environ,
            {"DATABASE_URL": "", "DATABASE_SCHEMA": "sentinel_ai"},
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        database.DB_FILE = self.original_db_file
        self.temp_directory.cleanup()

    def test_sqlite_initialization_and_persistence(self) -> None:
        database.init_db()

        with sqlite3.connect(database.DB_FILE) as connection:
            table_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        self.assertTrue(
            {
                "events",
                "incidents",
                "analyst_feedback",
                "sandboxed_actions",
            }.issubset(table_names)
        )

        database.save_feedback(
            "TRUE_POSITIVE",
            "incident-1",
            None,
            "confirmed",
            "2026-01-01T00:00:00+00:00",
        )
        database.log_sandboxed_action(
            "action-1",
            "BLOCK_IP",
            "192.0.2.1",
            "incident-1",
            "SIMULATED",
            "No external action executed.",
            "2026-01-01T00:00:00+00:00",
        )

        actions = database.get_sandboxed_actions()
        self.assertEqual(["action-1"], [action["action_id"] for action in actions])
        self.assertEqual(
            {
                "backend": "sqlite",
                "connected": True,
                "schema": "main",
                "error": None,
            },
            database.get_database_status(),
        )

    def test_invalid_postgresql_schema_fails_without_connecting(self) -> None:
        placeholder_url = (
            "postgresql://user:password@example.invalid:5432/database"
            "?sslmode=require"
        )
        with patch.dict(
            os.environ,
            {"DATABASE_URL": placeholder_url, "DATABASE_SCHEMA": "unsafe-name"},
            clear=False,
        ):
            status = database.get_database_status()
            self.assertEqual("postgresql", status["backend"])
            self.assertFalse(status["connected"])
            self.assertIsNone(status["schema"])
            self.assertEqual("invalid_schema", status["error"])
            with self.assertRaisesRegex(RuntimeError, "invalid_schema"):
                database.init_db()


if __name__ == "__main__":
    unittest.main()
