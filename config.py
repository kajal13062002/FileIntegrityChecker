"""
ONE place that decides which database the whole project uses
(app.py, create_admin.py, db_check.py, reset_all.py all read from here).

Priority:
  1. DATABASE_URL   (Aiven / Render)  e.g. mysql://avnadmin:PASS@host:port/defaultdb
  2. FIC_DB_HOST / FIC_DB_PORT / FIC_DB_USER / FIC_DB_PASSWORD / FIC_DB_NAME
  3. local XAMPP  (localhost / root / file_integrity)

Put these in the .env file next to app.py - it is loaded automatically.
"""
import os
import urllib.parse
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:  # python-dotenv: pip install python-dotenv
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"), override=False)
except ImportError:
    pass


def get_db():
    """Return the database settings the project must use."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        u = urlparse(url)
        ca = os.path.join(BASE_DIR, "ca.pem")
        return {
            "host": u.hostname,
            "port": u.port or 3306,
            "user": urllib.parse.unquote(u.username or ""),
            "password": urllib.parse.unquote(u.password or ""),
            "db": (u.path or "/defaultdb").lstrip("/") or "defaultdb",
            "ssl_ca": ca if os.path.isfile(ca) else None,
            "label": "AIVEN / DATABASE_URL",
        }
    return {
        "host": os.environ.get("FIC_DB_HOST", "localhost"),
        "port": int(os.environ.get("FIC_DB_PORT", "3306")),
        "user": os.environ.get("FIC_DB_USER", "root"),
        "password": os.environ.get("FIC_DB_PASSWORD", ""),
        "db": os.environ.get("FIC_DB_NAME", "file_integrity"),
        "ssl_ca": None,
        "label": "LOCAL (XAMPP / FIC_DB_*)",
    }


def connect():
    """pymysql connection for the helper scripts (same DB as the app)."""
    import pymysql
    d = get_db()
    kwargs = dict(host=d["host"], port=d["port"], user=d["user"],
                  password=d["password"], database=d["db"])
    if d["ssl_ca"]:
        kwargs["ssl"] = {"ca": d["ssl_ca"]}
    return pymysql.connect(**kwargs)


_D = get_db()
MYSQL_HOST = _D["host"]
MYSQL_PORT = _D["port"]
MYSQL_USER = _D["user"]
MYSQL_PASSWORD = _D["password"]
MYSQL_DB = _D["db"]

SECRET_KEY = os.environ.get("FIC_SECRET_KEY", "change-this-secret-key")
