import hashlib
import os
import re
from config import Config


def validate_password(password: str) -> tuple[bool, str]:
    """Return (is_valid, human_readable_reason)."""
    problems: list[str] = []

    if len(password) < Config.PASS_MIN_LENGTH:
        problems.append(f"at least {Config.PASS_MIN_LENGTH} characters")

    checks = [
        (Config.PASS_REQUIRE_UPPER, r"[A-Z]", "one uppercase letter"),
        (Config.PASS_REQUIRE_LOWER, r"[a-z]", "one lowercase letter"),
        (Config.PASS_REQUIRE_DIGIT, r"\d", "one digit"),
        (Config.PASS_REQUIRE_SPECIAL, r"[^A-Za-z0-9]", "one special character"),
    ]
    for required, pattern, human in checks:
        if required and not re.search(pattern, password):
            problems.append(human)

    if Config.PASS_DICTIONARY_PATH:
        with open(Config.PASS_DICTIONARY_PATH) as words:
            if password.lower() in (w.strip().lower() for w in words):
                problems.append("not be a dictionary word")

    if problems:
        msg = "Password must contain " + ", ".join(problems[:-1])
        if len(problems) > 1:
            msg += " and " + problems[-1]
        return False, msg

    return True, ""


def generate_sha1_code() -> str:
    return hashlib.sha1(os.urandom(32)).hexdigest()
