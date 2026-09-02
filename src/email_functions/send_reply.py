import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value

def _send_reply(
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        recipient: str,
        original_subject: str,
        reply_text: str,
) -> None:
    reply_subject = original_subject
    if not reply_subject.lower().startswith("re:"):
        reply_subject = f"Re: {reply_subject or '(без темы)'}"

    message = EmailMessage()
    message["From"] = formataddr(("Helpdesk", smtp_user))
    message["To"] = recipient
    message["Subject"] = reply_subject
    message.set_content(reply_text)

    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as smtp:
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)

def handle(event, context):
    smtp_host = os.getenv("SMTP_HOST", "smtp.yandex.ru")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = _required_env("SMTP_USER")
    smtp_password = _required_env("SMTP_PASSWORD")

    recipient = event["to"]
    subject = event.get("subject", "")
    reply_text = event["text"]

    _send_reply(smtp_host, smtp_port, smtp_user, smtp_password,
                recipient, subject, reply_text)

    return {"ok": True}