from flask import Flask, render_template, redirect, url_for, flash, request, session
from mail_utils import send_email
import hmac, hashlib, os
from config import Config
from models import db, User, Client
from utils import validate_password, generate_sha1_code
from sqlalchemy import text

app = Flask(__name__)
app.config.from_object(Config)
print("[VULN] MAILTRAP_USER in app.config =", app.config.get("MAILTRAP_USER"))
db.init_app(app)

with app.app_context():
    db.create_all()

# --------------------------------------------------------------------- helpers
def _current_user():
    uid = session.get("uid")
    return db.get_or_404(User, uid) if uid else None


def _send_email(to_address: str, subject: str, body: str):
    print(f"=== Email to {to_address} ===\nSubject: {subject}\n{body}\n==============")

# ---------- mini password-hash helper ----------
def _hash_password(raw_password: str, salt: bytes | None = None):
    if salt is None:
        salt = os.urandom(16)
    digest = hmac.new(salt, raw_password.encode(), hashlib.sha256).hexdigest()
    return salt.hex(), digest


# --------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if _current_user() else "login"))


# ------------------------------- VULNERABLE register  (Section 1)
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Classic SQL-i: raw INSERT built by string concatenation.
    Duplicate e-mails are checked manually; all other validation removed.
    """
    if request.method == "POST":
        username = request.form["username"]
        email    = request.form["email"]
        password = request.form["password"]
        confirm  = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords don’t match.", "danger")
            return redirect(url_for("register"))

        # 🔐 Manual duplicate email check
        existing = db.session.scalar(db.select(User).where(User.email == email))
        if existing:
            flash("E-mail already registered.", "danger")
            return redirect(url_for("register"))

        # 💥 Vulnerable raw SQL insert (for SQL-i demo)
        raw_sql = (
            "INSERT INTO user (username, email, salt, hash, created, login_attempts) "
            f"VALUES ('{username}', '{email}', '00', '{password}', datetime('now'), 0)"
        )

        try:
            raw_conn = db.session.connection().connection
            raw_conn.executescript(raw_sql)
            db.session.commit()
            flash("Registration successful! You can now log in.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Register failed: {e}", "danger")

        return redirect(url_for("login"))

    return render_template('register.html')


# ------------------------------- VULNERABLE login  (Section 3)
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Still vulnerable to SQL-i, now with clearer flash messages.
    """
    username_input = ""  # keeps field sticky

    if request.method == "POST":
        username_input = request.form["username"].strip()
        password       = request.form["password"]

        # 1️⃣ check if the user exists (still raw SQL)
        exists_q = f"SELECT hash FROM user WHERE username = '{username_input}'"
        row = db.session.execute(text(exists_q)).fetchone()

        if not row:
            flash("User not found.", "warning")
            return render_template("login.html", username_input=username_input)

        # 2️⃣ user exists → check password (still vulnerable)
        q = f"SELECT id FROM user WHERE username = '{username_input}' AND hash = '{password}'"
        row = db.session.execute(text(q)).fetchone()

        if row:
            session["uid"] = row[0]
            flash("Logged-in", "warning")
            return redirect(url_for("dashboard"))

        flash("Wrong password.", "warning")
        return render_template("login.html", username_input=username_input)

    # GET
    return render_template("login.html", username_input=username_input)


# ------------------------------- delete client
@app.route("/delete_client/<int:cid>", methods=["POST"])
def delete_client(cid):
    """
    Remove a client row by its primary-key ID.
    Only logged-in users may call this.
    """
    if not _current_user():
        return redirect(url_for("login"))

    client = db.get_or_404(Client, cid)
    db.session.delete(client)
    db.session.commit()
    flash(f"Client '{client.name}' deleted.", "info")
    return redirect(url_for("dashboard"))


# ------------------------------- dashboard / add client
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    user = _current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        name   = request.form["name"]
        sector = request.form["sector"]
        plan   = request.form["plan"]

        # completely raw INSERT --> Stored-XSS + SQL-i
        sql = (
            "INSERT INTO client (name, sector, plan, created) "
            f"VALUES ('{name}', '{sector}', '{plan}', datetime('now'))"
        )
        try:
            raw_conn = db.session.connection().connection  # grab the sqlite3.Connection
            raw_conn.executescript(sql)  # accepts multiple statements
            db.session.commit()  # flush ORM bookkeeping
            flash("VULN client inserted (XSS / SQL-i possible).", "warning")
        except Exception as e:
            db.session.rollback()
            flash(f"Insert failed: {e}", "danger")

    clients = db.session.scalars(db.select(Client)).all()
    return render_template("dashboard.html", clients=clients)


# ------------------------------- change password
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    user = _current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        current = request.form["current"]
        new_pw = request.form["new"]

        if not user.check_password(current):
            flash("Current password incorrect.", "danger")
        else:
            valid, reason = validate_password(new_pw)
            if not valid:
                flash(reason, "danger")
            elif user.password_reused(new_pw):
                flash("Cannot reuse your last passwords.", "danger")
            else:
                user.set_password(new_pw)
                db.session.commit()
                flash("Password updated.", "success")
                return redirect(url_for("dashboard"))

    return render_template("change_password.html")


# ------------------------------- forgot password (send code)
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip()
        print("[DEBUG] form submitted with", email)

        user = db.session.scalar(db.select(User).where(User.email == email))
        print("[DEBUG] user lookup:", "FOUND" if user else "NONE")

        if user:
            code = generate_sha1_code()
            user.set_reset_code(code)
            db.session.commit()
            print("[DEBUG] code saved to DB:", code)

            send_email(
                to=email,
                subject="Password reset key",
                text=f"Your password-reset code is:\n{code}",
                html=f"<p>Your password-reset code is: <b>{code}</b></p>",
            )
            print("[DEBUG] send_email() called")

        flash("If the email exists, a reset link was sent.", "info")
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


# ------------------------------- reset password (use code)
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        code = request.form["code"].strip()
        new_pw = request.form["new"].strip()
        confirm_pw = request.form["confirm"].strip()  # ← NEW

        user = db.session.scalar(db.select(User).where(User.username == username))
        if not user or not user.reset_code_valid(code):
            flash("Invalid username or code (or expired).", "danger")
        elif new_pw != confirm_pw:  # ← NEW
            flash("Passwords don’t match.", "danger")
        else:
            valid, reason = validate_password(new_pw)
            if not valid:
                flash(reason, "danger")
            elif user.password_reused(new_pw):
                flash("Cannot reuse your last passwords.", "danger")
            else:
                user.set_password(new_pw)
                user.clear_reset_code()
                db.session.commit()
                flash("Password reset successful. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("reset_password.html")


# ------------------------------- logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------- run
if __name__ == "__main__":
    app.run(debug=True)
