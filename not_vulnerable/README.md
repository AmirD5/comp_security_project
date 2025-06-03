# Secure Web Application – Comunication_LTD

This is a **secure version** of the Comunication_LTD Flask web app. It includes essential security practices for user management and data handling.

## 🔐 Security Features

- ✅ SQL Injection protection via SQLAlchemy ORM
- ✅ Passwords stored securely using HMAC with SHA256 and salt
- ✅ Password reuse prevention with history tracking
- ✅ Expiring password reset codes
- ✅ Input validation and safe email handling

## 📁 Project Structure

not_vulnerable/
│
├── app.py # Main application logic\
├── models.py # Database models (User, Client, PasswordHistory)\
├── utils.py # Password validation and SHA-1 generator\
├── mail_utils.py # Email sending helper\
├── templates/ # Jinja2 HTML templates\
├── .env # Mailtrap credentials\
└── requirements.txt # Project dependencies


## ⚙️ Setup Instructions

1. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies:
pip install -r requirements.txt

# Configure Mailtrap credentials in .env:
MAILTRAP_USER=your_mailtrap_username\
MAILTRAP_PASS=your_mailtrap_password