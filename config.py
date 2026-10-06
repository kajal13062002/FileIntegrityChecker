import os

MYSQL_HOST = os.environ.get(
    "FIC_DB_HOST",
    "file-integrity-db-file-integrity-checker.l.aivencloud.com"
)

MYSQL_PORT = int(os.environ.get("FIC_DB_PORT", "20288"))

MYSQL_USER = os.environ.get(
    "FIC_DB_USER",
    "fileapp"
)

MYSQL_PASSWORD = os.environ.get(
    "FIC_DB_PASSWORD",
    "kajal1306"
)

MYSQL_DB = os.environ.get(
    "FIC_DB_NAME",
    "defaultdb"
)

SECRET_KEY = os.environ.get(
    "FIC_SECRET_KEY",
    "your-secret-key-here"
)