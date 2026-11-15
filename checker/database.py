"""كل التعامل مع SQLite في مكان واحد."""
import sqlite3
import time
from contextlib import contextmanager

import config

# هاش ملف EICAR الاختباري المعروف (ملف آمن بيستخدمه الكل لتجربة برامج الحماية)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _ensure_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS threats (
        url TEXT PRIMARY KEY, domain TEXT, source TEXT, added_at INTEGER)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON threats(domain)")
    conn.execute("""CREATE TABLE IF NOT EXISTS file_hashes (
        sha256 TEXT PRIMARY KEY, name TEXT, source TEXT, added_at INTEGER)""")
    conn.execute("INSERT OR IGNORE INTO file_hashes VALUES (?,?,?,?)",
                 (EICAR_SHA256, "EICAR test file", "builtin", int(time.time())))


@contextmanager
def db_conn():
    conn = sqlite3.connect(config.DB_PATH)
    try:
        _ensure_schema(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def find_exact(norm_url):
    with db_conn() as c:
        row = c.execute("SELECT source FROM threats WHERE url=?", (norm_url,)).fetchone()
    return row[0] if row else None


def domain_stats(domain):
    with db_conn() as c:
        return c.execute(
            "SELECT COUNT(*), GROUP_CONCAT(DISTINCT source) FROM threats WHERE domain=?",
            (domain,)).fetchone()


def insert_threats(rows):
    with db_conn() as c:
        c.executemany("INSERT OR REPLACE INTO threats VALUES (?,?,?,?)", rows)


def count_threats():
    with db_conn() as c:
        return c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]


def find_hash(sha256):
    with db_conn() as c:
        row = c.execute("SELECT name FROM file_hashes WHERE sha256=?", (sha256,)).fetchone()
    return row[0] if row else None


def add_hash(sha256, name, source="manual"):
    with db_conn() as c:
        c.execute("INSERT OR REPLACE INTO file_hashes VALUES (?,?,?,?)",
                  (sha256.lower(), name, source, int(time.time())))
