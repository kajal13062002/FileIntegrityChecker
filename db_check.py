"""
Run once:  python db_check.py
Connects with config.py and checks that every table/column the app uses
really exists in your MySQL database, and warns about column types that
could make an INSERT fail.
"""
import pymysql
import config

# table -> columns the app reads/writes
EXPECTED = {
    "users": ["id", "name", "email", "password", "role"],
    "users1": ["id", "name", "email", "mobile", "gender", "dob", "city",
               "state", "password", "role", "status", "created_at"],
    "files": ["id", "user_id", "file_name", "file_path", "file_size",
              "file_type", "original_hash", "hash_algorithm", "upload_at",
              "status", "last_checked"],
    "hash_records": ["hash_id", "file_id", "algorithm", "hash_value",
                     "hash_version", "file_size", "generated_by",
                     "generated_at", "hash_status"],
    "integrity_logs": ["id", "file_id", "user_id", "old_hash", "new_hash",
                       "algorithm", "status", "change_type", "remarks",
                       "checked_at"],
    "verification_history": ["id", "file_id", "user_id", "result", "algorithm",
                             "old_hash", "current_hash", "verification_type",
                             "verified_at", "remarks"],
    "monitoring": ["id", "file_id", "user_id", "file_name", "event", "alert",
                   "detected_at", "details"],
    "login_history": ["id", "user_id", "email", "role", "status",
                      "ip_address", "login_time", "logout_time"],
    "system_activity_log": ["id", "user_id", "username", "activity",
                            "activity_type", "activity_time", "ip_address"],
    "reports": ["id", "report_type", "generated_by", "total", "safe",
                "modified", "tampered", "created_at", "status", "file_path"],
}

# values the app writes into ENUM-like columns
VALUES_WRITTEN = {
    ("files", "status"): ["safe", "modified", "tampered"],
    ("hash_records", "hash_status"): ["active"],
    ("integrity_logs", "status"): ["safe", "modified", "tampered"],
    ("verification_history", "result"): ["safe", "modified", "tampered"],
    ("verification_history", "verification_type"): ["manual", "admin_scan"],
    ("monitoring", "event"): ["Created", "Modified", "Tampered", "Missing"],
    ("monitoring", "alert"): ["generated", "not_generated"],
    ("login_history", "status"): ["success", "failed"],
    ("reports", "status"): ["completed"],
}

# columns that hold a hash: need room for 128 hex chars (SHA-512 / SHA3-512)
HASH_COLUMNS = [("hash_records", "hash_value"), ("integrity_logs", "old_hash"),
                ("integrity_logs", "new_hash"),
                ("verification_history", "old_hash"),
                ("verification_history", "current_hash")]


def main():
    conn = pymysql.connect(host=config.MYSQL_HOST, user=config.MYSQL_USER,
                           password=config.MYSQL_PASSWORD,
                           database=config.MYSQL_DB,
                           port=getattr(config, "MYSQL_PORT", 3306))
    cur = conn.cursor()
    problems = warnings = 0
    print(f"Connected to {config.MYSQL_HOST}/{config.MYSQL_DB}\n")

    for table, wanted in EXPECTED.items():
        try:
            cur.execute(f"SHOW COLUMNS FROM `{table}`")
        except pymysql.err.ProgrammingError:
            print(f"[MISSING TABLE] {table}")
            problems += 1
            continue
        found = {r[0]: r for r in cur.fetchall()}
        missing = [c for c in wanted if c not in found]
        if missing:
            print(f"[PROBLEM] {table}: missing columns {missing}")
            problems += 1
        else:
            print(f"[ok]      {table}")

        for (t, col), values in VALUES_WRITTEN.items():
            if t != table or col not in found:
                continue
            col_type = found[col][1]
            if isinstance(col_type, bytes):
                col_type = col_type.decode()
            if col_type.lower().startswith("enum("):
                allowed = [v.strip("'") for v in col_type[5:-1].split(",")]
                bad = [v for v in values if v not in allowed]
                if bad:
                    print(f"[WARN]    {t}.{col} is {col_type}; the app writes {bad}")
                    warnings += 1

        for (t, col) in HASH_COLUMNS:
            if t != table or col not in found:
                continue
            col_type = str(found[col][1]).lower()
            if col_type.startswith("varchar("):
                size = int(col_type[8:-1])
                if size < 128:
                    print(f"[WARN]    {t}.{col} is {col_type}; SHA-512/SHA3-512 "
                          f"need varchar(128) or more")
                    warnings += 1

    print()
    if problems:
        print(f"{problems} problem(s): fix these before running the app.")
    elif warnings:
        print(f"Schema OK, {warnings} warning(s) above.")
    else:
        print("All tables and columns match. You are good to go.")
    conn.close()


if __name__ == "__main__":
    main()
