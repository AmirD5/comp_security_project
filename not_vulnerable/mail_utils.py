# mail_utils.py
import logging
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app as app

def send_email(to: str, subject: str, text: str, html: str | None = None):
    """Send via Mailtrap; if creds missing, just print to console."""
    host = app.config.get("MAILTRAP_HOST", "sandbox.smtp.mailtrap.io")
    port = int(app.config.get("MAILTRAP_PORT", 2525))
    user = app.config.get("MAILTRAP_USER")
    pwd  = app.config.get("MAILTRAP_PASS")

    if not user or not pwd:
        logging.warning("MAILTRAP creds missing – printing e-mail instead:\n"
                        "TO: %s\nSUBJECT: %s\nBODY:\n%s", to, subject, text)
        return

    # build message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = app.config.get("MAIL_FROM", "demo@example.com")
    msg["To"]      = to
    msg.attach(MIMEText(text, "plain"))
    if html:
        msg.attach(MIMEText(html, "html"))

    # send
    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port) as srv:
        srv.starttls(context=ctx)
        srv.login(user, pwd)
        srv.sendmail(msg["From"], [to], msg.as_string())

    logging.info("Mailtrap message delivered to inbox for %s", to)
