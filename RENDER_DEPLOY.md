# File Integrity Checker - Render Deployment

## Render
Build command:
pip install -r requirements.txt

Start command:
gunicorn app:app

Python:
3.13.5

## Database
This project supports:
- Local XAMPP MySQL when DATABASE_URL is not set.
- Aiven MySQL on Render when DATABASE_URL is set.

On Render, add DATABASE_URL using your Aiven MySQL connection URL.
Also set FIC_SECRET_KEY if you do not use the generated Render secret.

Do not commit passwords or connection URLs to GitHub.
