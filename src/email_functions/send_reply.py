import base64
import json
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value


def _extract_payload(event):
    """
    Функция вызывается двумя разными путями:
    - напрямую (yc serverless function invoke -d '{...}') — event уже
      является распарсенным телом запроса;
    - через HTTP (httpCall из Workflows, functions.yandexcloud.net/...) —
      event это стандартный HTTP-конверт Cloud Functions, и настоящий
      payload лежит строкой в event["body"].
    """
    if isinstance(event, dict) and "httpMethod" in event and "body" in event:
        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        if isinstance(raw_body, str):
            return json.loads(raw_body)
        return raw_body
    return event


def _send_email(
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        recipient: str,
        subject: str,
        text: str,
        is_reply: bool,
) -> None:
    final_subject = subject
    if is_reply and not final_subject.lower().startswith("re:"):
        final_subject = f"Re: {final_subject or '(без темы)'}"
    elif not is_reply and not final_subject:
        final_subject = "Дайджест по тикетам"

    message = EmailMessage()
    message["From"] = formataddr(("Helpdesk", smtp_user))
    message["To"] = recipient
    message["Subject"] = final_subject
    message.set_content(text)

    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as smtp:
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)


def handle(event, context):
    smtp_host = os.getenv("SMTP_HOST", "smtp.yandex.ru")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = _required_env("SMTP_USER")
    smtp_password = _required_env("SMTP_PASSWORD")

    payload = _extract_payload(event)

    if "to" in payload:
        # Ответ пользователю на его обращение.
        recipient = payload["to"]
        subject = payload.get("subject", "")
        text = payload["text"]
        is_reply = True
    else:
        # Дайджест по просроченным тикетам для оператора.
        # Адрес НЕ из payload — жёстко из окружения.
        recipient = _required_env("OPERATOR_EMAIL")
        subject = payload.get("subject", "")
        text = payload.get("body", "")
        is_reply = False

    _send_email(smtp_host, smtp_port, smtp_user, smtp_password,
                recipient, subject, text, is_reply=is_reply)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"ok": True}),
    }