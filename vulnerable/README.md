# Vulnerable Web Application – Comunication_LTD

This intentionally vulnerable Flask web app demonstrates common web security flaws such as:
- SQL Injection (SQLi)
- Stored Cross-Site Scripting (XSS)
- Plaintext password storage
- Weak password reset logic

It is built for educational and demonstration purposes **only**.

## 📁 Structure

- `app.py` – Main application file
- `models.py` – Database models
- `templates/` – HTML templates
- `.env` – Environment variables (e.g., Mailtrap)
- `mail_utils.py` – Helper for sending emails via Mailtrap

## ⚠️ Vulnerabilities Included

- **SQL Injection** in login and registration
- **XSS** on dashboard page via unescaped client input
- **Passwords** are stored in plaintext (no hashing)
- **Password reset** uses predictable codes

## 🛠 Setup

1. Create virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows


## Install dependencies:

pip install -r requirements.txt

# Set up .env file with your Mailtrap credentials:

MAILTRAP_USER=your_mailtrap_user\
MAILTRAP_PASS=your_mailtrap_pass

