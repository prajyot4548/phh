"""
Oracle database layer (python-oracledb, thin mode — no Oracle client install needed).
Every function here opens its own short-lived connection, which keeps the Flask app
simple and safe under multiple simultaneous requests.
"""
import os
import oracledb
from dotenv import load_dotenv
from logger_setup import get_logger
import config

load_dotenv()
log = get_logger("db")


def conn():
    return oracledb.connect(
        user=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN", config.DEFAULT_DSN),
    )


DDL = [
    """CREATE TABLE vault_files (
         id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
         original_path VARCHAR2(1000) NOT NULL,
         enc_path      VARCHAR2(1000) NOT NULL,
         pii_types     VARCHAR2(300),
         risk_level    VARCHAR2(10) DEFAULT 'medium',
         size_bytes    NUMBER,
         sha256        VARCHAR2(64),
         status        VARCHAR2(12) DEFAULT 'ENCRYPTED' NOT NULL,
         created_at    TIMESTAMP DEFAULT SYSTIMESTAMP,
         restored_at   TIMESTAMP)""",
    """CREATE TABLE activity_log (
         id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
         action     VARCHAR2(30) NOT NULL,
         detail     VARCHAR2(1000),
         created_at TIMESTAMP DEFAULT SYSTIMESTAMP)""",
    """CREATE TABLE app_settings (
         key_name  VARCHAR2(100) PRIMARY KEY,
         value     VARCHAR2(500))""",
    """CREATE INDEX idx_vault_status ON vault_files(status)""",
    """CREATE INDEX idx_log_created ON activity_log(created_at)""",
]


def init_db():
    with conn() as c:
        cur = c.cursor()
        for stmt in DDL:
            try:
                cur.execute(stmt)
            except oracledb.DatabaseError as e:
                code = str(e)
                if "ORA-00955" not in code and "ORA-01408" not in code:   # already exists
                    log.warning("DDL skipped: %s", e)
        c.commit()
    log.info("Database ready.")


def _rows(cur):
    cols = [d[0].lower() for d in cur.description]
    out = []
    for r in cur.fetchall():
        row = dict(zip(cols, r))
        for k, v in row.items():
            if hasattr(v, "strftime"):
                row[k] = v.strftime("%d %b %Y, %H:%M")
        out.append(row)
    return out


# ---------------------------------------------------------------- vault_files
def add_file(original, enc, types, risk, size, sha256):
    with conn() as c:
        c.cursor().execute(
            """INSERT INTO vault_files
               (original_path, enc_path, pii_types, risk_level, size_bytes, sha256)
               VALUES (:1,:2,:3,:4,:5,:6)""",
            [original, enc, types, risk, size, sha256])
        c.commit()


def list_files(status=None, search=None, page=1, page_size=config.RESULTS_PAGE_SIZE):
    offset = max(0, (page - 1) * page_size)
    where, params = [], {}
    if status:
        where.append("status = :status"); params["status"] = status
    if search:
        where.append("UPPER(original_path) LIKE :search"); params["search"] = f"%{search.upper()}%"
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with conn() as c:
        cur = c.cursor()
        cur.execute(f"SELECT COUNT(*) FROM vault_files {clause}", params)
        total = cur.fetchone()[0]
        cur.execute(
            f"""SELECT id, original_path, enc_path, pii_types, risk_level, size_bytes,
                       status, created_at, restored_at
                FROM vault_files {clause}
                ORDER BY id DESC OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY""",
            {**params, "off": offset, "lim": page_size})
        return {"rows": _rows(cur), "total": total, "page": page, "page_size": page_size}


def get_file(fid):
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            "SELECT id, original_path, enc_path, status, sha256 FROM vault_files WHERE id = :1",
            [fid])
        rows = _rows(cur)
        return rows[0] if rows else None


def mark_restored(fid):
    with conn() as c:
        c.cursor().execute(
            "UPDATE vault_files SET status='RESTORED', restored_at=SYSTIMESTAMP WHERE id=:1",
            [fid])
        c.commit()


def delete_record(fid):
    """Remove a row from the vault list only. Never touches a file on disk."""
    with conn() as c:
        c.cursor().execute("DELETE FROM vault_files WHERE id = :1", [fid])
        c.commit()


def stats():
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """SELECT
                 COUNT(CASE WHEN status='ENCRYPTED' THEN 1 END),
                 COUNT(CASE WHEN status='RESTORED' THEN 1 END),
                 COUNT(CASE WHEN risk_level='high' AND status='ENCRYPTED' THEN 1 END),
                 COALESCE(SUM(CASE WHEN status='ENCRYPTED' THEN size_bytes END), 0)
               FROM vault_files""")
        enc, rest, high, bytes_locked = cur.fetchone()
        return {"encrypted": enc, "restored": rest, "high_risk": high, "bytes_locked": int(bytes_locked)}


def pii_type_breakdown():
    """How many locked files mention each PII type — powers the little bar chart in Settings."""
    with conn() as c:
        cur = c.cursor()
        cur.execute("SELECT pii_types FROM vault_files WHERE status='ENCRYPTED'")
        counts = {}
        for (types,) in cur.fetchall():
            for t in (types or "").split(", "):
                if t:
                    counts[t] = counts.get(t, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------- activity_log
def log(action, detail=""):
    with conn() as c:
        c.cursor().execute(
            "INSERT INTO activity_log (action, detail) VALUES (:1,:2)",
            [action, (detail or "")[:1000]])
        c.commit()


def list_logs(limit=100, page=1):
    offset = max(0, (page - 1) * limit)
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """SELECT id, action, detail, created_at FROM activity_log
               ORDER BY id DESC OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY""",
            {"off": offset, "lim": limit})
        return _rows(cur)


def export_logs_csv():
    """Return the full activity log as CSV text for download."""
    import csv, io
    with conn() as c:
        cur = c.cursor()
        cur.execute("SELECT id, action, detail, created_at FROM activity_log ORDER BY id DESC")
        rows = _rows(cur)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "action", "detail", "created_at"])
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


# ---------------------------------------------------------------- app_settings
def get_setting(key, default=None):
    with conn() as c:
        cur = c.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key_name = :1", [key])
        row = cur.fetchone()
        return row[0] if row else default


def set_setting(key, value):
    with conn() as c:
        cur = c.cursor()
        cur.execute("UPDATE app_settings SET value = :1 WHERE key_name = :2", [value, key])
        if cur.rowcount == 0:
            cur.execute("INSERT INTO app_settings (key_name, value) VALUES (:1,:2)", [key, value])
        c.commit()
