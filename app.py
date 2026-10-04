from flask import Flask, request, render_template, redirect, url_for, session
from flask_mysqldb import MySQL
import bcrypt
import config

app = Flask(__name__)

# =========================================================
# APP CONFIG
# =========================================================

app.secret_key = config.SECRET_KEY

app.config["MYSQL_HOST"] = config.MYSQL_HOST
app.config["MYSQL_USER"] = config.MYSQL_USER
app.config["MYSQL_PASSWORD"] = config.MYSQL_PASSWORD
app.config["MYSQL_DB"] = config.MYSQL_DB

mysql = MySQL(app)


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
# ADMIN LOGIN
# URL: /admin
# =========================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template(
                "admin/login.html",
                error="Email and password are required"
            )

        cursor = mysql.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE email=%s AND role='admin'
            """,
            (email,)
        )

        admin = cursor.fetchone()
        cursor.close()

        if admin:

            try:
                password_hash = admin[3]

                if bcrypt.checkpw(
                    password.encode("utf-8"),
                    password_hash.encode("utf-8")
                ):

                    session.clear()

                    session["admin_id"] = admin[0]
                    session["admin_name"] = admin[1]

                    return redirect(
                        url_for("admin_dashboard")
                    )

            except Exception:
                pass

        return render_template(
            "admin/login.html",
            error="Invalid Email or Password"
        )

    return render_template("admin/login.html")


# =========================================================
# ADMIN DASHBOARD
# URL: /admin/dashboard
# =========================================================

@app.route("/admin/dashboard")
def admin_dashboard():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    return render_template(
        "admin/dashboard.html",
        username=session.get("admin_name", "Admin")
    )


# =========================================================
# ADMIN USERS
# URL: /admin/users
# =========================================================

@app.route("/admin/users")
def admin_users():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    cursor = mysql.connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        ORDER BY id DESC
        """
    )

    users = cursor.fetchall()

    cursor.close()

    return render_template(
        "admin/users.html",
        users=users
    )


# =========================================================
# ADMIN ADD USER
# URL: /admin/add_user
# =========================================================

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

        cursor = mysql.connection.cursor()

        # Check duplicate email
        cursor.execute(
            "SELECT id FROM users WHERE email=%s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()

            return render_template(
                "admin/add_user.html",
                error="Email already exists"
            )

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute(
            """
            INSERT INTO users
            (name, email, password, role)
            VALUES (%s, %s, %s, %s)
            """,
            (
                name,
                email,
                hashed_password,
                role
            )
        )

        mysql.connection.commit()
        cursor.close()

        return redirect(url_for("admin_users"))

    return render_template("admin/add_user.html")


# =========================================================
# ADMIN EDIT USER
# URL: /admin/edit-user/<id>
# =========================================================

@app.route(
    "/admin/edit-user/<int:id>",
    methods=["GET", "POST"]
)
def edit_user(id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    cursor = mysql.connection.cursor()

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        role = request.form.get("role", "").strip()

        if not all([name, email, role]):
            cursor.close()

            return render_template(
                "admin/edit_user.html",
                error="All fields are required"
            )

        cursor.execute(
            """
            UPDATE users
            SET name=%s,
                email=%s,
                role=%s
            WHERE id=%s
            """,
            (
                name,
                email,
                role,
                id
            )
        )

        mysql.connection.commit()
        cursor.close()

        return redirect(url_for("admin_users"))

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (id,)
    )

    user = cursor.fetchone()

    cursor.close()

    if not user:
        return "User not found", 404

    return render_template(
        "admin/edit_user.html",
        user=user
    )


# =========================================================
# ADMIN DELETE USER
# URL: /admin/delete-user/<id>
# =========================================================

@app.route("/admin/delete-user/<int:id>")
def delete_user(id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    # Don't allow admin to delete himself
    if id == session.get("admin_id"):
        return "You cannot delete your own admin account", 400

    cursor = mysql.connection.cursor()

    cursor.execute(
        """
        DELETE FROM users
        WHERE id=%s
        """,
        (id,)
    )

    mysql.connection.commit()
    cursor.close()

    return redirect(url_for("admin_users"))


# =========================================================
# ADMIN FILES
# URL: /admin/files
# =========================================================

@app.route("/admin/files")
def admin_files():

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    cursor = mysql.connection.cursor()

    cursor.execute(
        """
        SELECT
            files.id,
            users.name,
            files.filename,
            files.filepath,
            files.sha256_hash,
            files.upload_date
        FROM files
        JOIN users
            ON files.user_id = users.id
        ORDER BY files.id DESC
        """
    )

    files = cursor.fetchall()

    cursor.close()

    return render_template(
        "admin/files.html",
        files=files
    )


# =========================================================
# ADMIN DELETE FILE
# URL: /admin/delete-file/<id>
# =========================================================

@app.route("/admin/delete-file/<int:id>")
def delete_file(id):

    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    cursor = mysql.connection.cursor()

    cursor.execute(
        """
        DELETE FROM files
        WHERE id=%s
        """,
        (id,)
    )

    mysql.connection.commit()
    cursor.close()

    return redirect(url_for("admin_files"))


# =========================================================
# USER REGISTRATION
# URL: /user/register
# =========================================================

@app.route("/user/register", methods=["GET", "POST"])
def user_register():

    if request.method == "POST":

        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        mobile = request.form.get(
            "mobile", ""
        ).strip()

        gender = request.form.get(
            "gender", ""
        ).strip()

        dob = request.form.get("dob")

        city = request.form.get(
            "city", ""
        ).strip()

        state = request.form.get(
            "state", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not all([
            name,
            email,
            mobile,
            gender,
            dob,
            city,
            state,
            password
        ]):
            return render_template(
                "user/user_register.html",
                error="All fields are required"
            )

        cursor = mysql.connection.cursor()

        # Check duplicate email
        cursor.execute(
            "SELECT id FROM users1 WHERE email=%s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()

            return render_template(
                "user/user_register.html",
                error="Email already registered"
            )

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute(
            """
            INSERT INTO users1
            (
                name,
                email,
                mobile,
                gender,
                dob,
                city,
                state,
                password,
                role
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                name,
                email,
                mobile,
                gender,
                dob,
                city,
                state,
                hashed_password,
                "user"
            )
        )

        mysql.connection.commit()
        cursor.close()

        return render_template(
            "user/register_success.html",
            username=name
        )

    return render_template(
        "user/user_register.html"
    )


# =========================================================
# USER LOGIN
# URL: /user/login
# =========================================================

@app.route("/user/login", methods=["GET", "POST"])
def user_login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not email or not password:
            return render_template(
                "user/login.html",
                error="Email and password are required"
            )

        cursor = mysql.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users1
            WHERE email=%s AND role='user'
            """,
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()

        if user:

            try:
                password_hash = user[8]

                if bcrypt.checkpw(
                    password.encode("utf-8"),
                    password_hash.encode("utf-8")
                ):

                    session.clear()

                    session["user_id"] = user[0]
                    session["user_name"] = user[1]

                    return redirect(
                        url_for("user_dashboard")
                    )

            except Exception:
                pass

        return render_template(
            "user/login.html",
            error="Invalid Email or Password"
        )

    return render_template(
        "user/login.html"
    )


# =========================================================
# USER DASHBOARD
# URL: /user/dashboard
# =========================================================

@app.route("/user/dashboard")
def user_dashboard():

    if "user_id" not in session:
        return redirect(url_for("user_login"))

    user_id = session["user_id"]

    cursor = mysql.connection.cursor()

    # Total files
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM file_integrity_logs
        WHERE user_id=%s
        """,
        (user_id,)
    )

    total_files = cursor.fetchone()[0]

    # Original files
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM verification_history
        WHERE user_id=%s
        AND result='Original'
        """,
        (user_id,)
    )

    original_files = cursor.fetchone()[0]

    # Tampered files
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM verification_history
        WHERE user_id=%s
        AND result='Tampered'
        """,
        (user_id,)
    )

    tampered_files = cursor.fetchone()[0]

    cursor.close()

    return render_template(
        "user/dashboard.html",
        total_files=total_files,
        original_files=original_files,
        tampered_files=tampered_files
    )


# =========================================================
# LOGOUT
# URL: /logout
# =========================================================

@app.route("/logout", methods=["GET"])
def logout():

    session.clear()

    return redirect(
        url_for("admin_login")
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )