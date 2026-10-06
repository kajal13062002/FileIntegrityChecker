from flask import Flask
from flask_mysqldb import MySQL
import config

app = Flask(__name__)

app.config["MYSQL_HOST"] = config.MYSQL_HOST
app.config["MYSQL_PORT"] = config.MYSQL_PORT
app.config["MYSQL_USER"] = config.MYSQL_USER
app.config["MYSQL_PASSWORD"] = config.MYSQL_PASSWORD
app.config["MYSQL_DB"] = config.MYSQL_DB

mysql = MySQL(app)

try:
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("SELECT DATABASE()")
        print("Connected database:", cur.fetchone()[0])
        cur.execute("SHOW TABLES")
        print("Tables:", cur.fetchall())
        cur.close()
        print("✅ Aiven connection successful!")
except Exception as e:
    print("❌ Connection failed:", e)