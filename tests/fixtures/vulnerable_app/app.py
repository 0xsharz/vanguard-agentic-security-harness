"""Tiny vulnerable Flask app — smoke target for the audit agent.

Two intentional bugs:
  - SQL injection at /lookup?name=...
  - Command injection at /ping?host=...

NOT FOR PRODUCTION. NOT FOR DEPLOYMENT. EDUCATIONAL FIXTURE ONLY.
"""
from __future__ import annotations

import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
DB_PATH = "users.db"


def _init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, name) VALUES (1, 'alice')")
    conn.commit()
    conn.close()


@app.route("/lookup")
def lookup() -> str:
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # BUG: f-string SQL — classic SQLi (CWE-89)
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return str(rows)


@app.route("/ping")
def ping() -> bytes:
    host = request.args.get("host", "localhost")
    # BUG: shell=True with attacker-controlled host — OS command injection (CWE-78)
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return out


if __name__ == "__main__":
    _init_db()
    app.run(host="127.0.0.1", port=5000)
