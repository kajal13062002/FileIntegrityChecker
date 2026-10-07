import os

MYSQL_HOST = os.environ.get("FIC_DB_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("FIC_DB_PORT", "3306"))
MYSQL_USER = os.environ.get("FIC_DB_USER", "root")
MYSQL_PASSWORD = os.environ.get("FIC_DB_PASSWORD", "")
MYSQL_DB = os.environ.get("FIC_DB_NAME", "file_integrity")

SECRET_KEY = os.environ.get("FIC_SECRET_KEY", "change-this-secret-key")
