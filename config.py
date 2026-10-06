import os

# Defaults match your current local setup. Override with environment
# variables instead of editing this file (e.g. on a server).
MYSQL_HOST = os.environ.get("FIC_DB_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("FIC_DB_PORT", "3306"))
MYSQL_USER = os.environ.get("FIC_DB_USER", "root")
MYSQL_PASSWORD = os.environ.get("FIC_DB_PASSWORD", "")
MYSQL_DB = os.environ.get("FIC_DB_NAME", "file_integrity")

# CHANGE THIS: it signs the login session cookie.
SECRET_KEY = os.environ.get("FIC_SECRET_KEY", "your-secret-key-here")
