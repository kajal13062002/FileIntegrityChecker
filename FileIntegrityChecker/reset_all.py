"""
FULL RESET  -  python reset_all.py

Wipes ALL user data in the SAME database the app uses (config.get_db()):
  users1 (login table), non-admin rows of users, files, hashes, logs,
  monitoring, reports, plus the files inside uploads/ and reports/.
The admin account (users.role='admin') is kept.

It first prints WHICH database it will wipe (LOCAL or AIVEN) and asks you
to type RESET. Run it once for local and once for Aiven if you use both
(change DATABASE_URL in .env between the two runs).
"""
import os
import config

TABLES = ["verification_history", "integrity_logs", "monitoring", "hash_records",
          "reports", "files", "login_history", "system_activity_log"]


def clear_folder(path):
    n = 0
    if os.path.isdir(path):
        for name in os.listdir(path):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                os.remove(full)
                n += 1
    return n


def main():
    d = config.get_db()
    print(f"\nTARGET DATABASE : {d['label']}")
    print(f"Host / DB       : {d['host']}:{d['port']} / {d['db']}\n")
    if input("Type RESET to delete all user data there: ").strip() != "RESET":
        print("Cancelled. Nothing changed.")
        return

    conn = config.connect()
    cur = conn.cursor()
    cur.execute("SET FOREIGN_KEY_CHECKS=0")
    for table in TABLES:
        try:
            cur.execute(f"TRUNCATE TABLE `{table}`")
            print(f"[cleared] {table}")
        except Exception as exc:
            print(f"[skip]    {table}: {exc}")
    try:
        cur.execute("DELETE FROM users WHERE role <> 'admin'")
        print(f"[cleared] users (non-admin) - {cur.rowcount} rows")
        cur.execute("DELETE FROM users1")
        print(f"[cleared] users1 (login table) - {cur.rowcount} rows")
    except Exception as exc:
        print("[error]  users tables:", exc)
    cur.execute("SET FOREIGN_KEY_CHECKS=1")
    conn.commit()
    cur.close()
    conn.close()

    up = clear_folder(os.path.join(config.BASE_DIR, "uploads"))
    rp = clear_folder(os.path.join(config.BASE_DIR, "reports"))
    print(f"[cleared] uploads/ ({up} files), reports/ ({rp} files)")
    print("\nDone. Now restart the app, logout in browser (or open a private window).")


if __name__ == "__main__":
    main()
