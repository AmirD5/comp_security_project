from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from email_validator import validate_email, EmailNotValidError

from config import Config
from models import db, User, Client
from utils import validate_password, generate_sha1_code

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()


# --------------------------------------------------------------------- helpers
def _current_user():
    uid = session.get("uid")
    return db.get_or_404(User, uid) if uid else None


def _send_email(to_address: str, subject: str, body: str):
    print(f"=== Email to {to_address} ===\nSubject: {subject}\n{body}\n==============")


# --------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if _current_user() else "login"))


# ------------------------------- register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        # -------- validation --------
        error = None

        # username unique?
        if db.session.scalar(db.select(User).where(User.username == username)):
            error = "Username already taken."

        # e-mail unique?
        if db.session.scalar(db.select(User).where(User.email == email)):
            error = "E-mail already registered."

        # email syntax OK?
        if not error:  # avoid overwriting earlier error
            try:
                validate_email(email)
            except EmailNotValidError:
                error = "Invalid email address."

        # password meets policy?
        valid, reason = validate_password(password)
        if not valid:
            error = reason

        # -------- result --------
        if error:
            flash(error, "danger")
        else:
            u = User(username=username, email=email)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Registered successfully. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


# ------------------------------- login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = db.session.scalar(db.select(User).where(User.username == username))
        if user and user.check_password(password):
            if user.login_attempts >= Config.LOGIN_MAX_ATTEMPTS:
                flash("Account locked. Reset your password or contact admin.", "danger")
                return redirect(url_for("login"))
            user.login_attempts = 0
            session["uid"] = user.id
            db.session.commit()
            return redirect(url_for("dashboard"))

        # wrong credentials path
        if user:
            user.login_attempts += 1
            db.session.commit()
        flash("Wrong credentials.", "warning")

    return render_template("login.html")


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


# ------------------------------- forgot password (send code)
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = db.session.scalar(db.select(User).where(User.email == email))
        if user:
            code = generate_sha1_code()
            user.set_reset_code(code)
            db.session.commit()
            _send_email(user.email, "Password reset code", f"Your reset code: {code}")
        flash("If the email exists, a reset code has been sent.", "info")
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


# ------------------------------- reset password (use code)
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        code = request.form["code"].strip()
        new_pw = request.form["new"].strip()

        user = db.session.scalar(db.select(User).where(User.username == username))
        if not user or not user.reset_code_valid(code):
            flash("Invalid username or code (or expired).", "danger")
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
