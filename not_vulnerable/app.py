from flask import Flask, render_template, redirect, url_for, flash, request, session
from email_validator import validate_email, EmailNotValidError
from itsdangerous import URLSafeTimedSerializer
from mail_utils import send_email

from config import Config
from models import db, User, Client
from utils import validate_password, generate_sha1_code

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

with app.app_context():
    db.create_all()

# --------------------------------------------------------------------- helpers
def _current_user():
    uid = session.get("uid")
    return db.get_or_404(User, uid) if uid else None


# --------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if _current_user() else "login"))


# ------------------------------- register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm  = request.form["confirm_password"]

        error = None

        # ── validation ────────────────────────────────────────────────
        if db.session.scalar(db.select(User).where(User.username == username)):
            error = "Username already taken."
        elif db.session.scalar(db.select(User).where(User.email == email)):
            error = "E-mail already registered."
        elif password != confirm:
            error = "Passwords don’t match."
        else:
            ok, reason = validate_password(password)
            if not ok:
                error = reason

        # ── outcome ───────────────────────────────────────────────────
        if error:
            flash(error, "danger")
            return render_template(
                "register.html",
                username_input=username,
                email_input=email,
            )

        # success → create the user
        u = User(username=username, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Registered successfully. Please log in.", "success")
        return redirect(url_for("login"))

    # GET request
    return render_template("register.html", username_input="", email_input="")


# ---------------- login ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    username_input = ""

    if request.method == "POST":
        username_input = request.form["username"].strip()
        password       = request.form["password"]

        user = db.session.scalar(db.select(User).where(User.username == username_input))

        if user and user.check_password(password):
            # ── success → redirect ─────────────────────────
            session["uid"] = user.id
            user.login_attempts = 0
            db.session.commit()
            return redirect(url_for("dashboard"))

        # ── failure → flash + re-render in same request ──
        flash("Wrong password." if user else "User not found.", "danger")
        if user:
            user.login_attempts += 1
            db.session.commit()
        return render_template("login.html", username_input=username_input)

    # GET  → blank or sticky (e.g. after lockout message above)
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
        name = request.form["name"]
        sector = request.form["sector"]
        plan = request.form["plan"]
        if name:
            client = Client(name=name, sector=sector or None, plan=plan or None)
            db.session.add(client)
            db.session.commit()
            flash(f"Client '{name}' added.", "success")

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


# ---------- request reset ----------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        token = ts.dumps(email, salt="pwd-reset")
        link  = url_for("reset_password", token=token, _external=True)
        code = generate_sha1_code()
        session["PW_RESET_EMAIL"] = email
        session["PW_RESET_CODE"] = code

        send_email(
            to=email,
            subject="Password reset key",
            text=f"Your reset key is: {code}\n{link}",
            html=f"<p>Your reset key is: <b>{code}</b></p><p><a href='{link}'>Reset here</a></p>",
        )

        flash("If the address is in our system, a reset link was sent.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

# ---------- reset form ----------
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Must reach this page via the e-mail link,
    # so the session still contains email & code
    if "PW_RESET_EMAIL" not in session:
        return redirect(url_for("forgot_password"))

    email       = session["PW_RESET_EMAIL"]
    stored_code = session["PW_RESET_CODE"]

    # ------------------------------------------------------------------
    if request.method == "POST":
        user_code = request.form["code"].strip()
        pw1       = request.form["password"]
        pw2       = request.form["confirm_password"]

        # ---- 1. code must match ----
        if user_code != stored_code:
            flash("Wrong reset key.", "danger")
            return redirect(request.url)

        # ---- 2. passwords must match & meet policy ----
        if pw1 != pw2:
            flash("Passwords don’t match.", "danger")
            return redirect(request.url)

        ok, msg = validate_password(pw1)
        if not ok:
            flash(msg, "danger")
            return redirect(request.url)

        # ---- 3. update DB ----
        user = db.session.scalar(db.select(User).where(User.email == email))
        user.set_password(pw1)
        db.session.commit()

        # ---- 4. clean up session ----
        session.pop("PW_RESET_CODE",   None)
        session.pop("PW_RESET_EMAIL",  None)
        session.pop("PW_RESET_VERIFIED", None)  # if you kept this flag

        flash("Password updated. Please log in.", "success")
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
