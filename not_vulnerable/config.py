import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)



class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URI",
        f"sqlite:///{BASE_DIR / 'communication_ltd.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    PASS_MIN_LENGTH = int(os.getenv("PASS_MIN_LENGTH", 10))
    PASS_REQUIRE_UPPER = bool(int(os.getenv("PASS_REQUIRE_UPPER", 1)))
    PASS_REQUIRE_LOWER = bool(int(os.getenv("PASS_REQUIRE_LOWER", 1)))
    PASS_REQUIRE_DIGIT = bool(int(os.getenv("PASS_REQUIRE_DIGIT", 1)))
    PASS_REQUIRE_SPECIAL = bool(int(os.getenv("PASS_REQUIRE_SPECIAL", 1)))
    PASS_HISTORY_COUNT = int(os.getenv("PASS_HISTORY_COUNT", 3))
    PASS_DICTIONARY_PATH = os.getenv("PASS_DICTIONARY_PATH", "")
    LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", 3))
    RESET_TOKEN_TTL_MIN = int(os.getenv("RESET_TOKEN_TTL_MIN", 15))

    # ── Mail settings ─────────────────────────
    MAIL_FROM = os.getenv(
        "MAIL_FROM",
        "Comunication_LTD <no-reply@communication-ltd.local>"
    )

    # optional SendGrid – leave blank on professor’s PC
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

    # Mailtrap credentials (used by mail_utils.py)
    MAILTRAP_USER = os.getenv("MAILTRAP_USER")
    MAILTRAP_PASS = os.getenv("MAILTRAP_PASS")

    # Flask-Mail fallback
    MAIL_DEFAULT_SENDER = MAIL_FROM
    RESET_TOKEN_MAX_AGE = 3600  # seconds