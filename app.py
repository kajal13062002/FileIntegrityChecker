from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import bcrypt
import config

app = Flask(__name__)

app.secret_key = config.SECRET_KEY

@app.route("/")
def home():
    return redirect(url_for("user_login"))

app.config["MYSQL_HOST"] = config.MYSQL_HOST
app.config["MYSQL_USER"] = config.MYSQL_USER
app.config["MYSQL_PASSWORD"] = config.MYSQL_PASSWORD
app.config["MYSQL_DB"] = config.MYSQL_DB

mysql = MySQL(app)


# =========================================================
# ADMIN LOGIN
# =========================================================


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email=%s AND role='admin'",
            (email,)
        )
        admin = cursor.fetchone()
        cursor.close()

        if admin:
            if bcrypt.checkpw(
                password.encode("utf-8"),
                admin[3].encode("utf-8")
            ):
                session["admin_id"] = admin[0]
                session["admin_name"] = admin[1]
                return redirect(url_for("admin_dashboard"))

        return render_template(
            "admin/login.html",
            error="Invalid Email or Password"
        )

    return render_template("admin/login.html")


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    return render_template(
        "admin/dashboard.html",
        username=session["admin_name"]
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_login"))


# =========================================================
# ADMIN - USERS
# =========================================================

@app.route("/admin/users")
def admin_users():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()

    return render_template(
        "admin/users.html",
        users=users
    )


# =========================================================
# ADMIN - ADD USER
# =========================================================

@app.route("/admin/add_user", methods=["GET", "POST"])
def add_user():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        if not all([name, email, password, role]):
            return "Missing fields", 400

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor = mysql.connection.cursor()
        cursor.execute(
            """
            INSERT INTO users
            (name, email, password, role)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, hashed_password, role)
        )
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for("admin_users"))

    return render_template("admin/add_user.html")


# =========================================================
# ADMIN - EDIT USER
# =========================================================

@app.route("/admin/edit-user/<int:id>", methods=["GET", "POST"])
def edit_user(id):
    cursor = mysql.connection.cursor()

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"]

        cursor.execute(
            """
            UPDATE users
            SET name=%s, email=%s, role=%s
            WHERE id=%s
            """,
            (name, email, role, id)
        )
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for("admin_users"))

    cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
    user = cursor.fetchone()
    cursor.close()

    return render_template(
        "admin/edit_user.html",
        user=user
    )


# =========================================================
# ADMIN - DELETE USER
# =========================================================

@app.route("/admin/delete-user/<int:id>")
def delete_user(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (id,))
    mysql.connection.commit()
    cursor.close()

    return redirect(url_for("admin_users"))


# =========================================================
# ADMIN - FILES
# =========================================================

@app.route("/admin/files")
def admin_files():
    cursor = mysql.connection.cursor()
    cursor.execute(
        """
        SELECT files.id, users.name, files.filename, files.filepath, files.sha256_hash, files.upload_date
        FROM files
        JOIN users ON files.user_id = users.id
        """
    )
    files = cursor.fetchall()
    cursor.close()

    return render_template(
        "admin/files.html",
        files=files
    )


# =========================================================
# ADMIN - DELETE FILE
# =========================================================

@app.route("/admin/delete-file/<int:id>")
def delete_file(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM files WHERE id=%s", (id,))
    mysql.connection.commit()
    cursor.close()

    return redirect(url_for("admin_files"))


# =========================================================
# USER REGISTRATION
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
        password = request.form.get("password")
        
        # Database insert logic...
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        
        cursor = mysql.connection.cursor()
        cursor.execute(
            """
            INSERT INTO users1 (name, email, mobile, gender, dob, city, state, password, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (name, email, mobile, gender, dob, city, state, hashed_password, "user")
        )
        mysql.connection.commit()
        cursor.close()

        # Success page par naam bhej rahe hain
        return render_template("user/register_success.html", username=name)

    return render_template("user/user_register.html")

# =========================================================
# USER LOGIN
# =========================================================

@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT * FROM users1 WHERE email=%s AND role='user'",
            (email,)
        )
        user = cursor.fetchone()
        cursor.close()

        if user:
            if bcrypt.checkpw(
                password.encode("utf-8"),
                user[8].encode("utf-8")
            ):
                session["user_id"] = user[0]
                session["user_name"] = user[1]
                return redirect(url_for("user_dashboard"))

        return render_template(
            "user/login.html",
            error="Invalid Email or Password"
        )

    return render_template("user/login.html")


# =========================================================
# USER DASHBOARD
# =========================================================

@app.route("/user/dashboard")
def user_dashboard():

    if "user_id" not in session:
        return redirect(url_for("user_login"))

    user_id = session["user_id"]

    cursor = mysql.connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM file_integrity_logs WHERE user_id=%s",
        (user_id,)
    )
    total_files = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM verification_history WHERE user_id=%s AND result='Original'",
        (user_id,)
    )
    original_files = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM verification_history WHERE user_id=%s AND result='Tampered'",
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
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)