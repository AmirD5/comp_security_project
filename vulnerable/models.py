import hashlib
import hmac
import os
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy

from config import Config

db = SQLAlchemy()


def _hash_password(password: str, salt: bytes | None = None):
    if salt is None:
        salt = os.urandom(16)
    digest = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()
    return salt, digest


class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)
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
        digest_now = self._password_digest(raw_password)
        history_digests = [p.hash for p in self.passwords[:Config.PASS_HISTORY_COUNT]]
        history_digests.append(self.hash)
        return digest_now in history_digests

    def set_password(self, raw_password: str):
        salt, digest = _hash_password(raw_password)
        if getattr(self, "hash", None):
            self.passwords.insert(0, PasswordHistory(salt=self.salt, hash=self.hash))
            while len(self.passwords) > Config.PASS_HISTORY_COUNT:
                self.passwords.pop()
        self.salt, self.hash = salt, digest

    def check_password(self, raw_password: str) -> bool:
        _, digest = _hash_password(raw_password, self.salt)
        return hmac.compare_digest(digest, self.hash)

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
