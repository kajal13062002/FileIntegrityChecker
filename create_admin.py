import bcrypt
import pymysql
import config  # uses the same config.py your app.py already imports

print("SCRIPT STARTED", flush=True)

# ---- Admin details you want to create ----
ADMIN_NAME = "Admin"
ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"   # plain text here; we hash it below
ADMIN_ROLE = "admin"
# --------------------------------------------

def main():
    print("Before hashing", flush=True)
    hashed_password = bcrypt.hashpw(
        ADMIN_PASSWORD.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")
    print("After hashing", flush=True)

    # Connect to MySQL using the same config your Flask app uses
    conn = pymysql.connect(
        host=config.MYSQL_HOST,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DB
    )
    print("After connect", flush=True)
    cursor = conn.cursor()
    print("DIAGNOSTIC: Connected to", config.MYSQL_HOST, config.MYSQL_DB, flush=True)

    try:
        # Check if this email already exists in users
        cursor.execute("SELECT id FROM users WHERE email=%s", (ADMIN_EMAIL,))
        existing = cursor.fetchone()
        print("After SELECT check", flush=True)

        if existing:
            # Update existing row's password + role instead of duplicating
            cursor.execute(
                "UPDATE users SET password=%s, role=%s, name=%s WHERE email=%s",
                (hashed_password, ADMIN_ROLE, ADMIN_NAME, ADMIN_EMAIL)
            )
            print(f"Updated existing user '{ADMIN_EMAIL}' with hashed password and role='admin'.", flush=True)
        else:
            # Insert new admin row
            cursor.execute(
                """
                INSERT INTO users (name, email, password, role)
                VALUES (%s, %s, %s, %s)
                """,
                (ADMIN_NAME, ADMIN_EMAIL, hashed_password, ADMIN_ROLE)
            )
            print(f"Created new admin user '{ADMIN_EMAIL}' in users table.", flush=True)

        conn.commit()
        print("Done. You can now log in with:", flush=True)
        print(f"  Email:    {ADMIN_EMAIL}", flush=True)
        print(f"  Password: {ADMIN_PASSWORD}", flush=True)

    except Exception as e:
        conn.rollback()
        print(f"Error: {e}", flush=True)
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()