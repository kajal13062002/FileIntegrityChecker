from flask import (Flask, request, render_template, redirect, url_for,
                   session, jsonify, send_file)
from flask_mysqldb import MySQL
from urllib.parse import urlparse
import MySQLdb.cursors
import bcrypt
import config
import csv
import hashlib
import os
import urllib.parse
import platform
import re
import uuid
from datetime import datetime, date
from functools import wraps
from importlib.metadata import version as package_version
from urllib.parse import urlparse
app = Flask(__name__)

# =========================================================
# APP CONFIG - LOCAL XAMPP OR RENDER + AIVEN
# =========================================================

app.secret_key = os.environ.get("FIC_SECRET_KEY", config.SECRET_KEY)

db_url = os.environ.get("DATABASE_URL")

if db_url:
    # Render + Aiven: paste the Aiven MySQL connection URL
    # into Render as DATABASE_URL.
    u = urlparse(db_url)
    app.config["MYSQL_HOST"] = u.hostname
    app.config["MYSQL_PORT"] = u.port or 3306
    app.config["MYSQL_USER"] = urllib.parse.unquote(u.username or "")
    app.config["MYSQL_PASSWORD"] = urllib.parse.unquote(u.password or "")
    app.config["MYSQL_DB"] = (u.path or "/defaultdb").lstrip("/") or "defaultdb"

    # Aiven requires TLS. The bundled CA certificate is used when available.
    ca_path = os.path.join(app.root_path, "ca.pem")
    if os.path.isfile(ca_path):
        app.config["MYSQL_CUSTOM_OPTIONS"] = {"ssl": {"ca": ca_path}}
else:
    # Local XAMPP fallback.
    app.config["MYSQL_HOST"] = config.MYSQL_HOST
    app.config["MYSQL_PORT"] = config.MYSQL_PORT
    app.config["MYSQL_USER"] = config.MYSQL_USER
    app.config["MYSQL_PASSWORD"] = config.MYSQL_PASSWORD
    app.config["MYSQL_DB"] = config.MYSQL_DB

mysql = MySQL(app)



def log_activity(user_id, username, activity, activity_type):
    try:
        cursor = mysql.connection.cursor()

        ip_address = request.remote_addr

        cursor.execute("""
            INSERT INTO system_activity_log
            (user_id, username, activity, activity_type, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            user_id,
            username,
            activity,
            activity_type,
            ip_address
        ))

        mysql.connection.commit()
        cursor.close()

    except Exception as e:
        print("Activity Log Error:", e)

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
REPORT_FOLDER = os.path.join(app.root_path, "reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")
REPORT_TYPES = ("System Integrity Report", "Security Audit Report")

ALGORITHM_NAMES = {
    "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
    "SHA-384": "sha384", "SHA-512": "sha512",
    "SHA-512/224": "sha512_224", "SHA-512/256": "sha512_256",
    "SHA3-224": "sha3_224", "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
}
# only offer what this Python/OpenSSL build can really compute
ALLOWED_ALGORITHMS = [a for a, n in ALGORITHM_NAMES.items()
                      if n in hashlib.algorithms_available]


# =========================================================
# SMALL HELPERS
# =========================================================

def conn():
    return mysql.connection


def dict_cursor():
    """Rows come back as dicts keyed by the real column names."""
    return conn().cursor(MySQLdb.cursors.DictCursor)


def iso(value):
    """datetime/date -> ISO text (JS reads it as local time)."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value or None


def client_ip():
    return request.remote_addr or ""


def hash_bytes(data, algorithm):
    return hashlib.new(ALGORITHM_NAMES[algorithm], data).hexdigest()


def hash_file(path, algorithm):
    digest = hashlib.new(ALGORITHM_NAMES[algorithm])
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_hash(func, *args):
    try:
        return func(*args)
    except (KeyError, ValueError, OSError):
        return None


def resolve_path(stored_path):
    """files.file_path is stored relative to the project folder."""
    if not stored_path:
        return ""
    if os.path.isabs(stored_path):
        return stored_path
    return os.path.join(app.root_path, stored_path)


def remove_quietly(path):
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def csv_safe(value):
    """Stop spreadsheet formula injection from file names."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


# ---------- logging tables (never allowed to break the main request) ------

def _safe_write(sql, params):
    cursor = None
    try:
        cursor = conn().cursor()
        cursor.execute(sql, params)
        conn().commit()
        return cursor.lastrowid
    except Exception as exc:
        try:
            conn().rollback()
        except Exception:
            pass
        app.logger.warning("DB log write skipped: %s", exc)
        return None
    finally:
        if cursor is not None:
            cursor.close()


def log_activity(text, activity_type, user_id=None, username=None):
    """-> system_activity_log"""
    if user_id is None:
        user_id = session.get("db_user_id") or session.get("admin_id")
    if username is None:
        username = (session.get("user_name") or session.get("admin_name")
                    or "System")
    _safe_write(
        """INSERT INTO system_activity_log
           (user_id, username, activity, activity_type, activity_time, ip_address)
           VALUES (%s,%s,%s,%s,%s,%s)""",
        (user_id, username, text, activity_type, datetime.now(), client_ip()))


def log_login(user_id, email, role, status):
    """-> login_history (returns the row id so logout can stamp it)"""
    return _safe_write(
        """INSERT INTO login_history
           (user_id, email, role, status, ip_address, login_time)
           VALUES (%s,%s,%s,%s,%s,%s)""",
        (user_id, email, role, status, client_ip(), datetime.now()))


def log_logout():
    row_id = session.get("login_row")
    if row_id:
        _safe_write("UPDATE login_history SET logout_time=%s WHERE id=%s",
                    (datetime.now(), row_id))


# ---------- integrity checking ---------------------------------------------

def classify(matched, total):
    """all hashes match -> safe | none match -> modified | some match -> tampered"""
    if total and matched == total:
        return "safe", "No change"
    if matched == 0:
        return "modified", "Content modified"
    return "tampered", "Partial hash mismatch"


def expected_hashes(cursor, file_row):
    """{algorithm: stored_hash} from hash_records (fallback: files.original_hash)."""
    cursor.execute(
        "SELECT algorithm, hash_value FROM hash_records WHERE file_id=%s "
        "ORDER BY hash_id", (file_row["id"],))
    expected = {r["algorithm"]: r["hash_value"] for r in cursor.fetchall()}
    if not expected and file_row.get("original_hash"):
        expected = {file_row.get("hash_algorithm") or "SHA-256":
                    file_row["original_hash"]}
    return expected


def compare_hashes(expected, calculate):
    rows, matched = [], 0
    for algorithm, stored in expected.items():
        calculated = calculate(algorithm)
        ok = (calculated is not None and
              calculated.lower() == (stored or "").lower())
        matched += int(ok)
        rows.append({"algorithm": algorithm, "stored": stored,
                     "calculated": calculated or "", "match": ok})
    status, change = classify(matched, len(rows))
    primary = next((r for r in rows if r["algorithm"] == "SHA-256"), rows[0])
    return {"status": status, "change": change, "matched": matched,
            "total": len(rows), "rows": rows, "primary": primary,
            "remarks": f"{matched}/{len(rows)} algorithms matched"}


def record_check(file_row, result, verification_type):
    """Write one finished check into files, integrity_logs,
    verification_history and monitoring."""
    now = datetime.now()
    file_id, owner = file_row["id"], file_row["user_id"]
    name, status = file_row["file_name"], result["status"]
    primary = result["primary"]

    _safe_write("UPDATE files SET status=%s, last_checked=%s WHERE id=%s",
                (status, now, file_id))

    _safe_write(
        """INSERT INTO integrity_logs
           (file_id, user_id, old_hash, new_hash, algorithm, status,
            change_type, remarks, checked_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (file_id, owner, primary["stored"], primary["calculated"],
         primary["algorithm"], status, result["change"], result["remarks"], now))

    history_sql = """INSERT INTO verification_history
        (file_id, user_id, result, algorithm, old_hash, current_hash,
         verification_type, verified_at, remarks)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    if verification_type == "manual":
        for row in result["rows"]:
            _safe_write(history_sql, (
                file_id, owner, "safe" if row["match"] else "modified",
                row["algorithm"], row["stored"], row["calculated"],
                verification_type, now,
                "Hash matched" if row["match"] else "Hash mismatch"))
    else:
        _safe_write(history_sql, (
            file_id, owner, status, primary["algorithm"], primary["stored"],
            primary["calculated"], verification_type, now, result["remarks"]))

    if status != "safe":
        event = "Missing" if result["change"] == "File missing" else status.capitalize()
        # monitoring.alert is a severity: low/medium/high/critical/safe
        severity = ("critical" if event == "Missing"
                    else "high" if status == "tampered" else "medium")
        _safe_write(
            """INSERT INTO monitoring
               (file_id, user_id, file_name, event, alert, detected_at, details)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (file_id, owner, name, event, severity, now,
             f"{result['change']} - {result['remarks']}"))


# ---------- users / users1 -------------------------------------------------
# users1 = registration profile (mobile, dob, city ...).
# users  = account table the admin panel and every user_id column point to.

def ensure_mirror(cursor, name, email, password_hash, role="user"):
    """Return users.id for this email; create the row if it is missing."""
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    row = cursor.fetchone()
    if row:
        return row["id"]
    cursor.execute(
        "INSERT INTO users (name, email, password, role) VALUES (%s,%s,%s,%s)",
        (name, email, password_hash, role))
    conn().commit()
    return cursor.lastrowid


def sync_user_mirror(cursor):
    """Give every registered users1 row a matching users row."""
    cursor.execute("SELECT email FROM users")
    have = {(r["email"] or "").lower() for r in cursor.fetchall()}
    cursor.execute("SELECT name, email, password, role FROM users1")
    added = False
    for p in cursor.fetchall():
        if (p["email"] or "").lower() not in have:
            cursor.execute(
                "INSERT INTO users (name, email, password, role) "
                "VALUES (%s,%s,%s,%s)",
                (p["name"], p["email"], p["password"], p["role"] or "user"))
            added = True
    if added:
        conn().commit()


def email_taken(cursor, email):
    for table in ("users", "users1"):
        cursor.execute(f"SELECT id FROM {table} WHERE email=%s", (email,))
        if cursor.fetchone():
            return True
    return False


def delete_file_rows(cursor, file_id):
    """Delete one file and everything that points at it. Returns its path."""
    cursor.execute("SELECT file_path FROM files WHERE id=%s", (file_id,))
    row = cursor.fetchone()
    for table in ("hash_records", "verification_history",
                  "integrity_logs", "monitoring"):
        cursor.execute(f"DELETE FROM {table} WHERE file_id=%s", (file_id,))
    cursor.execute("DELETE FROM files WHERE id=%s", (file_id,))
    return resolve_path(row["file_path"]) if row else ""


def user_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return {"error": "Unauthorized"}, 401
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return {"error": "Unauthorized"}, 401
        return view(*args, **kwargs)
    return wrapper


# =========================================================
# HOME & SHORTCUTS
# =========================================================

@app.route("/")
def home():
    return redirect(url_for("user_login"))


@app.route("/login")
def login_shortcut():
    return redirect(url_for("user_login"))


@app.route("/register")
def register_shortcut():
    return redirect(url_for("user_register"))


# =========================================================
# ADMIN LOGIN                                 URL: /admin
# =========================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("admin/login.html",
                                   error="Email and password are required")

        cursor = dict_cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s AND role='admin'",
                       (email,))
        admin = cursor.fetchone()
        cursor.close()

        ok = False
        if admin:
            try:
                ok = bcrypt.checkpw(password.encode("utf-8"),
                                    admin["password"].encode("utf-8"))
            except Exception:
                ok = False

        if not ok:
            log_login(admin["id"] if admin else None, email, "admin", "failed")
            return render_template("admin/login.html",
                                   error="Invalid Email or Password")

        session.clear()
        session["admin_id"] = admin["id"]
        session["admin_name"] = admin["email"]
        session["login_row"] = log_login(admin["id"], email, "admin", "success")
        log_activity(
           admin["id"],
           admin["email"],
           "Admin logged in",
           "LOGIN"
)
        return redirect(url_for("admin_dashboard"))

    return render_template("admin/login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin/dashboard.html",
                           username=session.get("admin_name", "Admin"))


# =========================================================
# USER REGISTRATION                      URL: /user/register
# =========================================================

@app.route("/user/register", methods=["GET", "POST"])
def user_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        mobile = request.form.get("mobile", "").strip()
        gender = request.form.get("gender", "").strip()
        dob = request.form.get("dob")
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        password = request.form.get("password", "")

        if not all([name, email, mobile, gender, dob, city, state, password]):
            return render_template("user/user_register.html",
                                   error="All fields are required")

        cursor = dict_cursor()
        # checks BOTH tables, so nobody can register over an existing
        # account (e.g. the admin's email)
        if email_taken(cursor, email):
            cursor.close()
            return render_template("user/user_register.html",
                                   error="Email already registered")

        hashed = bcrypt.hashpw(password.encode("utf-8"),
                               bcrypt.gensalt()).decode("utf-8")
        try:
            cursor.execute(
                """INSERT INTO users1
                   (name, email, mobile, gender, dob, city, state, password, role)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (name, email, mobile, gender, dob, city, state, hashed, "user"))
            cursor.execute(
                "INSERT INTO users (name, email, password, role) "
                "VALUES (%s,%s,%s,'user')", (name, email, hashed))
            new_id = cursor.lastrowid
            conn().commit()
        except Exception as exc:
            conn().rollback()
            cursor.close()
            app.logger.error("Registration failed: %s", exc)
            return render_template("user/user_register.html",
                                   error="Could not create the account. Please try again.")
        cursor.close()

        log_activity("Registered a new account", "USER",
                     user_id=new_id, username=name)
        return render_template("user/register_success.html", username=name)

    return render_template("user/user_register.html")


# =========================================================
# USER LOGIN                                URL: /user/login
# =========================================================

@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("user/login.html",
                                   error="Email and password are required")

        cursor = dict_cursor()
        cursor.execute("SELECT * FROM users1 WHERE email=%s AND role='user'",
                       (email,))
        user = cursor.fetchone()

        ok = False
        if user:
            try:
                ok = bcrypt.checkpw(password.encode("utf-8"),
                                    user["password"].encode("utf-8"))
            except Exception:
                ok = False

        if not ok:
            cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
            known = cursor.fetchone()
            cursor.close()
            log_login(known["id"] if known else None, email, "user", "failed")
            return render_template("user/login.html",
                                   error="Invalid Email or Password")

        mirror_id = ensure_mirror(cursor, user["name"], user["email"],
                                  user["password"], "user")
        cursor.close()

        if (user.get("status") or "active").lower() == "inactive":
            log_login(mirror_id, email, "user", "failed")
            return render_template(
                "user/login.html",
                error="Your account is inactive. Please contact the administrator.")

        session.clear()
        session["user_id"] = user["id"]
        session["db_user_id"] = mirror_id
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        session["login_row"] = log_login(mirror_id, email, "user", "success")
        log_activity("Logged in", "LOGIN")
        return redirect(url_for("user_dashboard"))

    return render_template("user/login.html")


@app.route("/user/dashboard")
def user_dashboard():
    if "user_id" not in session:
        return redirect(url_for("user_login"))
    return render_template("user/dashboard.html")


# =========================================================
# USER APIs  (used by static/js/das.js)
# =========================================================

@app.route("/api/user/me")
@user_required
def api_user_me():
    cursor = dict_cursor()
    cursor.execute(
        """SELECT id, name, email, mobile, gender, dob, city, state, role,
                  status, created_at FROM users1 WHERE id=%s""",
        (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        return {"error": "User not found"}, 404
    user["dob"] = iso(user["dob"])
    user["created_at"] = iso(user["created_at"])
    return user


@app.route("/api/user/files")
@user_required
def api_user_files():
    db_user_id = session.get("user_id")
    if not db_user_id:
        return []

    cursor = dict_cursor()
    cursor.execute(
        """SELECT id, file_name, file_path, file_size, original_hash,
                  upload_at, status, last_checked
           FROM files WHERE user_id=%s ORDER BY id DESC""", (db_user_id,))
    files = cursor.fetchall()

    hashes = {}
    if files:
        marks = ",".join(["%s"] * len(files))
        cursor.execute(
            f"""SELECT file_id, algorithm, hash_value FROM hash_records
                WHERE file_id IN ({marks}) ORDER BY hash_id""",
            [f["id"] for f in files])
        for row in cursor.fetchall():
            hashes.setdefault(row["file_id"], {})[row["algorithm"]] = row["hash_value"]
    cursor.close()

    return [{
        "id": f["id"], "name": f["file_name"], "size": f["file_size"] or 0,
        "filepath": f["file_path"], "sha256_hash": f["original_hash"],
        "upload_date": iso(f["upload_at"]), "status": f["status"] or "safe",
        "last_checked": iso(f["last_checked"]),
        "hashes": hashes.get(f["id"], {}),
    } for f in files]


@app.route("/api/user/history")
@user_required
def api_user_history():
    cursor = dict_cursor()
    cursor.execute(
        """SELECT v.id, v.file_id, f.file_name, v.algorithm, v.old_hash,
                  v.current_hash, v.result, v.verification_type,
                  v.verified_at, v.remarks
           FROM verification_history v
           LEFT JOIN files f ON f.id = v.file_id
           WHERE v.user_id=%s ORDER BY v.id DESC LIMIT 500""",
        (session.get("db_user_id"),))
    rows = cursor.fetchall()
    cursor.close()
    rows = list(rows)
    rows.reverse()      # oldest first; the page shows newest on top

    return [{
        "id": r["id"], "file_id": r["file_id"],
        "file": r["file_name"] or f"file #{r['file_id']}",
        "algorithm": r["algorithm"], "stored_hash": r["old_hash"] or "",
        "calculated_hash": r["current_hash"] or "", "result": r["result"],
        "verification_type": r["verification_type"],
        "verified_at": iso(r["verified_at"]), "remarks": r["remarks"],
    } for r in rows]


@app.route("/api/user/upload", methods=["POST"])
@user_required
def api_user_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return {"error": "No file selected"}, 400

    algorithms = [a for a in request.form.getlist("algorithms") or ["SHA-256"]
                  if a in ALLOWED_ALGORITHMS]
    algorithms = list(dict.fromkeys(algorithms))
    if not algorithms:
        return {"error": "No valid hash algorithm selected"}, 400

    db_user_id = session.get("db_user_id")
    print("DB USER ID:", db_user_id)
    if not db_user_id:
        return {"error": "User mapping not found"}, 500

    data = upload.read()
    safe_name = os.path.basename(upload.filename.replace("\\", "/"))
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    disk_path = os.path.join(UPLOAD_FOLDER, stored_name)
    with open(disk_path, "wb") as handle:
        handle.write(data)

    hashes = {a: hash_bytes(data, a) for a in algorithms}
    sha256 = hashes.get("SHA-256") or hash_bytes(data, "SHA-256")
    extension = os.path.splitext(safe_name)[1].lstrip(".").lower()[:20] or "unknown"
    now = datetime.now()

    print("DB USER ID:", db_user_id, )
    cursor = conn().cursor()
    try:

        cursor.execute(
            """INSERT INTO files
               (user_id, file_name, file_path, file_size, file_type,
                original_hash, hash_algorithm, upload_at, status, last_checked)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (db_user_id, safe_name, "uploads/" + stored_name, len(data),
             extension, sha256, "SHA-256", now, "safe", now))
        file_id = cursor.lastrowid
        for algorithm, value in hashes.items():
            cursor.execute(
                """INSERT INTO hash_records
                   (file_id, algorithm, hash_value, hash_version, file_size,
                    generated_by, generated_at, hash_status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (file_id, algorithm, value, 1, len(data), db_user_id, now,
                 "active"))
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        remove_quietly(disk_path)
        return {"error": str(exc)}, 500
    cursor.close()

    _safe_write(
        """INSERT INTO monitoring
           (file_id, user_id, file_name, event, alert, detected_at, details)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (file_id, db_user_id, safe_name, "Created", "safe", now,
         f"Uploaded with {len(hashes)} hash(es)"))
    log_activity(f"Uploaded {safe_name}", "UPLOAD")

    return {"id": file_id, "name": safe_name, "size": len(data),
            "hashes": hashes, "status": "safe"}


@app.route("/api/user/verify", methods=["POST"])
@user_required
def api_user_verify():
    file_id = request.form.get("file_id", type=int)
    upload = request.files.get("file")
    if not file_id or not upload:
        return {"error": "File and file_id are required"}, 400

    cursor = dict_cursor()
    cursor.execute(
        """SELECT id, user_id, file_name, original_hash, hash_algorithm
           FROM files WHERE id=%s AND user_id=%s""",
        (file_id, session.get("db_user_id")))
    file_row = cursor.fetchone()
    if not file_row:
        cursor.close()
        return {"error": "File not found"}, 404

    expected = expected_hashes(cursor, file_row)
    cursor.close()
    if not expected:
        return {"error": "No stored hash found for this file"}, 409

    data = upload.read()
    result = compare_hashes(expected, lambda a: safe_hash(hash_bytes, data, a))
    record_check(file_row, result, "manual")
    log_activity(f"Verified {file_row['file_name']} -> {result['status']}",
                 "VERIFY")

    return {
        "file_id": file_id, "file": file_row["file_name"],
        "result": "Original" if result["status"] == "safe"
                  else result["status"].capitalize(),
        "status": result["status"], "matched": result["matched"],
        "total": result["total"], "rows": result["rows"],
    }


# =========================================================
# LOGOUT                                      URL: /logout
# =========================================================

@app.route("/logout", methods=["GET"])
def logout():
    was_user = "user_id" in session
    if session:
        log_activity("Logged out", "LOGOUT")
        log_logout()
    session.clear()
    return redirect(url_for("user_login" if was_user else "admin_login"))


# =========================================================
# ADMIN APIs  (used by static/js/admin_app.js)
# =========================================================

def build_user_list(cursor):
    sync_user_mirror(cursor)
    cursor.execute("SELECT id, name, email, role FROM users ORDER BY id")
    accounts = cursor.fetchall()
    cursor.execute("SELECT * FROM users1")
    profiles = {(p["email"] or "").lower(): p for p in cursor.fetchall()}

    users = []
    for u in accounts:
        p = profiles.get((u["email"] or "").lower()) or {}
        users.append({
            "id": u["id"], "name": u["name"], "email": u["email"],
            "role": u["role"], "phone": p.get("mobile") or "",
            "gender": p.get("gender") or "", "dob": iso(p.get("dob")),
            "city": p.get("city") or "", "state": p.get("state") or "",
            "status": p.get("status") or "active",
            "createdAt": iso(p.get("created_at")),
        })
    return users


def package_label(name):
    try:
        return package_version(name)
    except Exception:
        return "?"


@app.route("/api/admin/data")
@admin_required
def api_admin_data():
    cursor = dict_cursor()
    try:
        users = build_user_list(cursor)
    except Exception as exc:
        conn().rollback()
        app.logger.warning("user mirror sync skipped: %s", exc)
        cursor.execute("SELECT id, name, email, role FROM users ORDER BY id")
        users = [{**u, "phone": "", "gender": "", "dob": None, "city": "",
                  "state": "", "status": "active", "createdAt": None}
                 for u in cursor.fetchall()]
    names = {u["id"]: u["name"] for u in users}

    # files + their hashes
    cursor.execute(
        """SELECT id, user_id, file_name, file_size, file_type, original_hash,
                  hash_algorithm, upload_at, status, last_checked
           FROM files ORDER BY id""")
    file_rows = cursor.fetchall()
    cursor.execute("SELECT file_id, algorithm, hash_value FROM hash_records "
                   "ORDER BY hash_id")
    hashes = {}
    for h in cursor.fetchall():
        hashes.setdefault(h["file_id"], {})[h["algorithm"]] = h["hash_value"]
    files = []
    for f in file_rows:
        file_hashes = hashes.get(f["id"]) or (
            {f["hash_algorithm"] or "SHA-256": f["original_hash"]}
            if f["original_hash"] else {})
        files.append({
            "id": f["id"], "userId": f["user_id"], "name": f["file_name"],
            "size": f["file_size"] or 0, "type": f["file_type"],
            "algorithms": list(file_hashes), "hashes": file_hashes,
            "status": f["status"] or "safe", "uploadedAt": iso(f["upload_at"]),
            "lastChecked": iso(f["last_checked"]),
        })
    file_names = {f["id"]: f["name"] for f in files}

    cursor.execute(
        """SELECT id, file_id, user_id, algorithm, status, change_type,
                  remarks, checked_at FROM integrity_logs
           ORDER BY id DESC LIMIT 500""")
    integrity_logs = [{
        "id": r["id"], "fileId": r["file_id"], "userId": r["user_id"],
        "algorithm": r["algorithm"], "status": r["status"],
        "change": r["change_type"] or "", "remarks": r["remarks"] or "",
        "checkedAt": iso(r["checked_at"]),
    } for r in reversed(cursor.fetchall())]

    cursor.execute(
        """SELECT id, file_id, file_name, event, alert, detected_at, details
           FROM monitoring ORDER BY id DESC LIMIT 500""")
    monitor_events = [{
        "id": r["id"], "fileId": r["file_id"],
        "file": r["file_name"] or file_names.get(r["file_id"], "-"),
        "event": r["event"], "alert": r["alert"],
        "detectedAt": iso(r["detected_at"]), "details": r["details"] or "",
    } for r in reversed(cursor.fetchall())]

    cursor.execute(
        """SELECT id, username, activity, activity_type, activity_time,
                  ip_address FROM system_activity_log
           ORDER BY id DESC LIMIT 300""")
    activities = [{
        "id": r["id"], "user": r["username"] or "-", "text": r["activity"],
        "type": r["activity_type"] or "", "time": iso(r["activity_time"]),
        "ip": r["ip_address"] or "",
    } for r in reversed(cursor.fetchall())]

    cursor.execute(
        """SELECT id, user_id, email, role, status, ip_address, login_time,
                  logout_time FROM login_history
           ORDER BY id DESC LIMIT 200""")
    login_rows = cursor.fetchall()
    logins = [{
        "id": r["id"], "email": r["email"], "role": r["role"] or "-",
        "status": r["status"], "ip": r["ip_address"] or "",
        "time": iso(r["login_time"]), "logout": iso(r["logout_time"]),
    } for r in login_rows]

    cursor.execute(
        """SELECT id, report_type, generated_by, total, safe, modified,
                  tampered, created_at, status FROM reports ORDER BY id""")
    reports = []
    for r in cursor.fetchall():
        by = r["generated_by"]
        if str(by).isdigit():
            by = names.get(int(by), by)
        reports.append({
            "id": r["id"], "type": r["report_type"], "by": by,
            "total": r["total"], "safe": r["safe"], "modified": r["modified"],
            "tampered": r["tampered"], "createdAt": iso(r["created_at"]),
            "status": r["status"],
        })

    me = next((u for u in users if u["id"] == session["admin_id"]), None) or {
        "id": session["admin_id"], "name": session.get("admin_name", "Admin"),
        "email": "", "role": "admin", "phone": "", "gender": "", "dob": None,
        "city": "", "state": "", "status": "active", "createdAt": None}
    mine = next((l for l in login_rows
                 if l["user_id"] == me["id"] and l["status"] == "success"), None)
    me["lastLogin"] = {
        "status": mine["status"], "ip": mine["ip_address"],
        "time": iso(mine["login_time"]), "logout": iso(mine["logout_time"]),
    } if mine else None

    cursor.execute("SELECT VERSION() AS v")
    system = {
        "database": "MySQL " + cursor.fetchone()["v"],
        "backend": f"Python {platform.python_version()} \u00b7 Flask "
                   f"{package_label('flask')}",
    }
    cursor.close()

    return jsonify(users=users, files=files, integrityLogs=integrity_logs,
                   monitorEvents=monitor_events, activities=activities,
                   logins=logins, reports=reports, me=me, system=system)


# ---------- users -----------------------------------------------------------

def read_user_form(data, creating):
    """Validate the admin's Add/Edit form. Returns (values, error)."""
    v = {k: str(data.get(k) or "").strip() for k in
         ("name", "email", "phone", "gender", "dob", "city", "state",
          "role", "status")}
    v["email"] = v["email"].lower()
    v["password"] = str(data.get("password") or "")

    if not v["name"] or not EMAIL_RE.match(v["email"]):
        return None, "Enter a name and a valid email."
    if v["role"] not in ("user", "admin"):
        return None, "Role must be user or admin."
    if v["status"] not in ("active", "inactive"):
        v["status"] = "active"
    if creating and len(v["password"]) < 6:
        return None, "Password must be at least 6 characters."
    if v["password"] and len(v["password"]) < 6:
        return None, "Password must be at least 6 characters."
    if v["phone"] and not re.fullmatch(r"\d{10}", v["phone"]):
        return None, "Phone must be 10 digits."
    if v["role"] == "user" and not all(
            [v["phone"], v["gender"], v["dob"], v["city"], v["state"]]):
        return None, ("Phone, gender, date of birth, city and state "
                      "are required for user accounts.")
    return v, None


def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def api_admin_add_user():
    v, error = read_user_form(request.get_json(silent=True) or {}, True)
    if error:
        return {"error": error}, 400

    cursor = dict_cursor()
    if email_taken(cursor, v["email"]):
        cursor.close()
        return {"error": "Email already exists."}, 409

    hashed = hash_password(v["password"])
    try:
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s,%s,%s,%s)",
            (v["name"], v["email"], hashed, v["role"]))
        new_id = cursor.lastrowid
        if v["role"] == "user":
            cursor.execute(
                """INSERT INTO users1
                   (name, email, mobile, gender, dob, city, state, password,
                    role, status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (v["name"], v["email"], v["phone"], v["gender"], v["dob"],
                 v["city"], v["state"], hashed, "user", v["status"]))
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        return {"error": str(exc)}, 500
    cursor.close()

    log_activity(f"Added user {v['name']}", "USER")
    return {"id": new_id}


@app.route("/api/admin/users/<int:user_id>", methods=["PUT"])
@admin_required
def api_admin_edit_user(user_id):
    v, error = read_user_form(request.get_json(silent=True) or {}, False)
    if error:
        return {"error": error}, 400

    cursor = dict_cursor()
    cursor.execute("SELECT id, name, email, password, role FROM users WHERE id=%s",
                   (user_id,))
    account = cursor.fetchone()
    if not account:
        cursor.close()
        return {"error": "User not found"}, 404
    if user_id == session["admin_id"] and v["role"] != "admin":
        cursor.close()
        return {"error": "You cannot change your own role."}, 400

    old_email = account["email"]
    if v["email"] != (old_email or "").lower() and email_taken(cursor, v["email"]):
        cursor.close()
        return {"error": "Email already exists."}, 409

    new_hash = hash_password(v["password"]) if v["password"] else account["password"]
    try:
        cursor.execute("SELECT id FROM users1 WHERE email=%s", (old_email,))
        profile = cursor.fetchone()

        cursor.execute(
            "UPDATE users SET name=%s, email=%s, password=%s, role=%s WHERE id=%s",
            (v["name"], v["email"], new_hash, v["role"], user_id))

        if v["role"] == "user" and not profile:
            cursor.execute(
                """INSERT INTO users1
                   (name, email, mobile, gender, dob, city, state, password,
                    role, status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (v["name"], v["email"], v["phone"], v["gender"], v["dob"],
                 v["city"], v["state"], new_hash, "user", v["status"]))
        elif profile and v["role"] == "user":
            cursor.execute(
                """UPDATE users1 SET name=%s, email=%s, mobile=%s, gender=%s,
                          dob=%s, city=%s, state=%s, password=%s, role='user',
                          status=%s WHERE id=%s""",
                (v["name"], v["email"], v["phone"], v["gender"], v["dob"],
                 v["city"], v["state"], new_hash, v["status"], profile["id"]))
        elif profile:       # promoted to admin: keep the profile, block user login
            cursor.execute(
                "UPDATE users1 SET name=%s, email=%s, password=%s, role='admin', "
                "status=%s WHERE id=%s",
                (v["name"], v["email"], new_hash, v["status"], profile["id"]))
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        return {"error": str(exc)}, 500
    cursor.close()

    log_activity(f"Updated user {v['name']}", "USER")
    return {"id": user_id}


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_user(user_id):
    if user_id == session["admin_id"]:
        return {"error": "You cannot delete your own admin account."}, 400

    cursor = dict_cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id=%s", (user_id,))
    account = cursor.fetchone()
    if not account:
        cursor.close()
        return {"error": "User not found"}, 404

    try:
        cursor.execute("SELECT id FROM files WHERE user_id=%s", (user_id,))
        paths = [delete_file_rows(cursor, f["id"]) for f in cursor.fetchall()]
        cursor.execute("DELETE FROM users1 WHERE email=%s", (account["email"],))
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        return {"error": f"Could not delete user: {exc}"}, 409
    cursor.close()

    for path in paths:
        remove_quietly(path)
    log_activity(f"Deleted user {account['name']}", "USER")
    return {"deleted": user_id}


# ---------- files / scan ---------------------------------------------------

@app.route("/api/admin/files/<int:file_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_file(file_id):
    cursor = dict_cursor()
    cursor.execute("SELECT id, file_name FROM files WHERE id=%s", (file_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        return {"error": "File not found"}, 404
    try:
        path = delete_file_rows(cursor, file_id)
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        return {"error": f"Could not delete file: {exc}"}, 409
    cursor.close()

    remove_quietly(path)
    log_activity(f"Deleted file {row['file_name']}", "DELETE")
    return {"deleted": file_id}


@app.route("/api/admin/scan", methods=["POST"])
@admin_required
def api_admin_scan():
    """Re-hash every stored file on disk and compare with its stored hashes."""
    cursor = dict_cursor()
    cursor.execute(
        """SELECT id, user_id, file_name, file_path, original_hash,
                  hash_algorithm FROM files ORDER BY id""")
    files = cursor.fetchall()

    counts = {"safe": 0, "modified": 0, "tampered": 0, "skipped": 0}
    for f in files:
        expected = expected_hashes(cursor, f)
        if not expected:
            counts["skipped"] += 1
            continue
        path = resolve_path(f["file_path"])
        if os.path.isfile(path):
            result = compare_hashes(expected, lambda a: safe_hash(hash_file, path, a))
        else:
            result = compare_hashes(expected, lambda a: None)
            result.update(status="tampered", change="File missing",
                          remarks="File not found on disk")
        record_check(f, result, "admin_scan")
        counts[result["status"]] += 1
    cursor.close()

    log_activity(
        f"Scanned {len(files)} files: {counts['safe']} safe, "
        f"{counts['modified']} modified, {counts['tampered']} tampered", "SCAN")
    return {"scanned": len(files), **counts}


# ---------- reports ----------------------------------------------------------

@app.route("/api/admin/reports", methods=["POST"])
@admin_required
def api_admin_generate_report():
    report_type = (request.get_json(silent=True) or {}).get("type")
    if report_type not in REPORT_TYPES:
        return {"error": "Unknown report type"}, 400

    cursor = dict_cursor()
    cursor.execute(
        """SELECT f.id, f.file_name, u.name AS owner, f.status, f.upload_at,
                  f.last_checked FROM files f
           LEFT JOIN users u ON u.id = f.user_id ORDER BY f.id""")
    rows = cursor.fetchall()
    cursor.close()

    counts = {"safe": 0, "modified": 0, "tampered": 0}
    for r in rows:
        counts[r["status"] if r["status"] in counts else "safe"] += 1

    now = datetime.now()
    file_name = f"report_{now:%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}.csv"
    disk_path = os.path.join(REPORT_FOLDER, file_name)
    with open(disk_path, "w", newline="", encoding="utf-8") as handle:
        out = csv.writer(handle)
        out.writerow([report_type])
        out.writerow(["Generated", now.strftime("%Y-%m-%d %H:%M:%S")])
        out.writerow(["Generated by", session.get("admin_name", "Admin")])
        out.writerow(["Total", len(rows), "Safe", counts["safe"],
                      "Modified", counts["modified"],
                      "Tampered", counts["tampered"]])
        out.writerow([])
        out.writerow(["File ID", "File", "Owner", "Status", "Uploaded",
                      "Last checked"])
        for r in rows:
            out.writerow([r["id"], csv_safe(r["file_name"]), csv_safe(r["owner"]),
                          r["status"], iso(r["upload_at"]), iso(r["last_checked"])])

    cursor = conn().cursor()
    try:
        cursor.execute(
            """INSERT INTO reports
               (report_type, generated_by, total, safe, modified, tampered,
                created_at, status, file_path)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (report_type, session["admin_id"], len(rows), counts["safe"],
             counts["modified"], counts["tampered"], now, "generated",
             "reports/" + file_name))
        report_id = cursor.lastrowid
        conn().commit()
    except Exception as exc:
        conn().rollback()
        cursor.close()
        remove_quietly(disk_path)
        return {"error": str(exc)}, 500
    cursor.close()

    log_activity(f"Generated {report_type}", "REPORT")
    return {"id": report_id}


def report_disk_path(stored_path):
    path = os.path.abspath(resolve_path(stored_path))
    inside = os.path.abspath(REPORT_FOLDER)
    return path if os.path.commonpath([path, inside]) == inside else ""


@app.route("/api/admin/reports/<int:report_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_report(report_id):
    cursor = dict_cursor()
    cursor.execute("SELECT file_path FROM reports WHERE id=%s", (report_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        return {"error": "Report not found"}, 404
    cursor.execute("DELETE FROM reports WHERE id=%s", (report_id,))
    conn().commit()
    cursor.close()
    remove_quietly(report_disk_path(row["file_path"]))
    log_activity(f"Deleted report #{report_id}", "REPORT")
    return {"deleted": report_id}


@app.route("/api/admin/reports/<int:report_id>/download")
@admin_required
def api_admin_download_report(report_id):
    cursor = dict_cursor()
    cursor.execute("SELECT file_path FROM reports WHERE id=%s", (report_id,))
    row = cursor.fetchone()
    cursor.close()
    path = report_disk_path(row["file_path"]) if row else ""
    if not path or not os.path.isfile(path):
        return {"error": "Report file not found"}, 404
    return send_file(path, as_attachment=True,
                     download_name=f"report_{report_id}.csv")


# ---------- password ---------------------------------------------------------

@app.route("/api/admin/password", methods=["POST"])
@admin_required
def api_admin_password():
    data = request.get_json(silent=True) or {}
    current, new = data.get("current") or "", data.get("new") or ""

    cursor = dict_cursor()
    cursor.execute("SELECT email, password FROM users WHERE id=%s",
                   (session["admin_id"],))
    row = cursor.fetchone()
    try:
        correct = bool(row) and bcrypt.checkpw(current.encode("utf-8"),
                                               row["password"].encode("utf-8"))
    except Exception:
        correct = False
    if not correct:
        cursor.close()
        return {"error": "Current password is incorrect."}, 400
    if len(new) < 6:
        cursor.close()
        return {"error": "New password must be at least 6 characters."}, 400

    hashed = hash_password(new)
    cursor.execute("UPDATE users SET password=%s WHERE id=%s",
                   (hashed, session["admin_id"]))
    cursor.execute("UPDATE users1 SET password=%s WHERE email=%s",
                   (hashed, row["email"]))
    conn().commit()
    cursor.close()
    log_activity("Changed admin password", "SECURITY")
    return {"ok": True}


# =========================================================
# OLDER SERVER-RENDERED ADMIN PAGES (kept; now use the real columns)
# =========================================================

@app.route("/admin/users")
def admin_users():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    cursor = conn().cursor()
    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    cursor.close()
    return render_template("admin/users.html", users=users)


@app.route("/admin/add_user", methods=["GET", "POST"])
def add_user():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        if not all([name, email, password, role]):
            return "Missing fields", 400
        cursor = dict_cursor()
        if email_taken(cursor, email):
            cursor.close()
            return render_template("admin/add_user.html",
                                   error="Email already exists")
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s,%s,%s,%s)",
            (name, email, hash_password(password), role))
        conn().commit()
        cursor.close()
        return redirect(url_for("admin_users"))
    return render_template("admin/add_user.html")


@app.route("/admin/edit-user/<int:id>", methods=["GET", "POST"])
def edit_user(id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    cursor = conn().cursor()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        role = request.form.get("role", "").strip()
        if not all([name, email, role]):
            cursor.close()
            return render_template("admin/edit_user.html",
                                   error="All fields are required")
        cursor.execute("UPDATE users SET name=%s, email=%s, role=%s WHERE id=%s",
                       (name, email, role, id))
        conn().commit()
        cursor.close()
        return redirect(url_for("admin_users"))
    cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
    user = cursor.fetchone()
    cursor.close()
    if not user:
        return "User not found", 404
    return render_template("admin/edit_user.html", user=user)


@app.route("/admin/delete-user/<int:id>")
def delete_user(id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    if id == session.get("admin_id"):
        return "You cannot delete your own admin account", 400
    cursor = dict_cursor()
    cursor.execute("SELECT id, email FROM users WHERE id=%s", (id,))
    account = cursor.fetchone()
    if account:
        try:
            cursor.execute("SELECT id FROM files WHERE user_id=%s", (id,))
            paths = [delete_file_rows(cursor, f["id"]) for f in cursor.fetchall()]
            cursor.execute("DELETE FROM users1 WHERE email=%s", (account["email"],))
            cursor.execute("DELETE FROM users WHERE id=%s", (id,))
            conn().commit()
            for path in paths:
                remove_quietly(path)
        except Exception as exc:
            conn().rollback()
            cursor.close()
            return f"Could not delete user: {exc}", 409
    cursor.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/files")
def admin_files():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    cursor = conn().cursor()
    cursor.execute(
        """SELECT files.id, users.name, files.file_name, files.file_path,
                  files.original_hash, files.upload_at
           FROM files JOIN users ON files.user_id = users.id
           ORDER BY files.id DESC""")
    files = cursor.fetchall()
    cursor.close()
    return render_template("admin/files.html", files=files)


@app.route("/admin/delete-file/<int:id>")
def delete_file(id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    cursor = dict_cursor()
    try:
        path = delete_file_rows(cursor, id)
        conn().commit()
        remove_quietly(path)
    except Exception as exc:
        conn().rollback()
        cursor.close()
        return f"Could not delete file: {exc}", 409
    cursor.close()
    return redirect(url_for("admin_files"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    # 127.0.0.1 = only this PC. Set FIC_HOST=0.0.0.0 to reach it from your
    # phone/LAN, but then turn the debugger off (FIC_DEBUG=0).
    app.run(
        debug=os.environ.get("FIC_DEBUG", "0") == "1",
        host=os.environ.get("FIC_HOST", "127.0.0.1"),
        port=int(os.environ.get("FIC_PORT", "5000")),
    )
