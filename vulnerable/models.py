import hashlib
import hmac
import os
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy

from config import Config

db = SQLAlchemy()


def _hash_password(password: str, salt: bytes | str | None = None):
    if salt is None:                       # fresh password
        salt = os.urandom(16)
    elif isinstance(salt, str):            # coming back from DB as hex-str
        salt = bytes.fromhex(salt)         # ← convert to bytes
    digest = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()
    return salt.hex(), digest              # still store hex-str


class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    login_attempts = db.Column(db.Integer, default=0)

    reset_code = db.Column(db.String(40))
    reset_sent_at = db.Column(db.DateTime)

    passwords = db.relationship("PasswordHistory", backref="user",
                                order_by=PasswordHistory.created.desc())

    def _password_digest(self, raw_password: str, salt: bytes | None = None):
        if salt is None:
            salt = self.salt
        _, digest = _hash_password(raw_password, salt)
        return digest

    def password_reused(self, raw_password: str) -> bool:
        # compare plain text against history + current
        history = [p.hash for p in self.passwords[:Config.PASS_HISTORY_COUNT]]
        history.append(self.hash)
        return raw_password in history

    def set_password(self, raw_password: str):
        # save previous password in history (optional for demo)
        if getattr(self, "hash", None):
            hist = PasswordHistory(salt="00", hash=self.hash)
            hist.user = self
            db.session.add(hist)

        self.salt = "00"          # always the same fake salt
        self.hash = raw_password  # store plain text

    def check_password(self, raw_password: str) -> bool:
        # simple string compare – no hashing
        return raw_password == self.hash

    def set_reset_code(self, code_sha1: str):
        self.reset_code = code_sha1
        self.reset_sent_at = datetime.utcnow()

    def clear_reset_code(self):
        self.reset_code = None
        self.reset_sent_at = None

    def reset_code_valid(self, code: str) -> bool:
        if not self.reset_code or not self.reset_sent_at:
            return False
        if datetime.utcnow() - self.reset_sent_at > timedelta(minutes=Config.RESET_TOKEN_TTL_MIN):
            return False
        return hmac.compare_digest(self.reset_code, code)


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    sector = db.Column(db.String(120))
    plan = db.Column(db.String(120))
    created = db.Column(db.DateTime, default=datetime.utcnow)
