import imaplib
import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr, parseaddr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

METADATA_IAM_TOKEN_URL = (
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
)
RESPONSES_API_URL = "https://rest-assistant.api.cloud.yandex.net/v1/responses"


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def _get_iam_token() -> str:
    request = urllib.request.Request(
        METADATA_IAM_TOKEN_URL,
        headers={"Metadata-Flavor": "Google"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)
    return payload["access_token"]


def _get_text_body(message) -> str:
    part = message.get_body(preferencelist=("plain",))
    if part is not None:
        return part.get_content().strip()

    # Fallback for a non-multipart text/plain email.
    if message.get_content_type() == "text/plain":
        return message.get_content().strip()

    return ""


def _ask_agent(sender: str, subject: str, body: str) -> str:
    folder_id = _required_env("YC_FOLDER_ID")
    model = os.getenv("YC_MODEL", f"gpt://{folder_id}/yandexgpt/latest")
    iam_token = _get_iam_token()

    payload = {
        "model": model,
        "instructions": (
            "Ты ассистент службы поддержки. Отвечай по-русски, вежливо, "
            "кратко и по существу."
        ),
        "input": (
            f"Письмо в поддержку.\n"
            f"Отправитель: {sender}\n"
            f"Тема: {subject or '(без темы)'}\n"
            f"Текст:\n{body or '(пустое письмо)'}"
        ),
        "text": {"format": {"type": "text"}},
    }

    request = urllib.request.Request(
        RESPONSES_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {iam_token}",
            "Content-Type": "application/json",
            "x-folder-id": folder_id,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Responses API HTTP {error.code}: {details}") from error

    texts = []

    for output_item in result.get("output", []):
        if output_item.get("type") != "message":
            continue

        for content_item in output_item.get("content", []):
            if content_item.get("type") == "output_text":
                text = (content_item.get("text") or "").strip()
                if text:
                    texts.append(text)

    answer = "\n".join(texts).strip()

    if not answer:
        raise RuntimeError(
            f"Responses API returned no textual output: {result}"
        )

    return answer


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


def _mark_seen(imap: imaplib.IMAP4_SSL, num: bytes) -> None:
    status, _ = imap.store(num, "+FLAGS", "\\Seen")
    if status != "OK":
        raise RuntimeError(f"Cannot mark message {num!r} as Seen: {status}")


def handle(event, context):
    imap_host = os.getenv("IMAP_HOST", "imap.yandex.ru")
    imap_user = _required_env("IMAP_USER")
    imap_password = _required_env("IMAP_PASSWORD")
    smtp_host = os.getenv("SMTP_HOST", "smtp.yandex.ru")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = _required_env("SMTP_USER")
    smtp_password = _required_env("SMTP_PASSWORD")
    helpdesk_mailbox = _required_env("HELPDESK_MAILBOX").lower()

    processed = 0
    failed = 0

    with imaplib.IMAP4_SSL(imap_host, 993, timeout=30) as imap:
        imap.login(imap_user, imap_password)
        status, _ = imap.select("INBOX")
        if status != "OK":
            raise RuntimeError("Cannot select INBOX")

        status, data = imap.search(None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Cannot search unread messages")

        message_numbers = data[0].split()
        logger.info("GOT_UNSEEN=%d", len(message_numbers))

        for num in message_numbers:
            try:
                status, raw_data = imap.fetch(num, "(RFC822)")
                if status != "OK" or not raw_data or raw_data[0] is None:
                    raise RuntimeError(f"Cannot fetch message {num!r}")

                message = BytesParser(policy=policy.default).parsebytes(raw_data[0][1])
                sender_name, sender_email = parseaddr(message.get("From", ""))
                sender_email = sender_email.strip()
                subject = _decode_header(message.get("Subject"))
                body = _get_text_body(message)

                logger.info(
                    "MSG num=%s from=%s subject=%s",
                    num.decode(), sender_email, subject,
                )

                if not sender_email:
                    raise RuntimeError("Message has no valid From address")
                if sender_email.lower() == helpdesk_mailbox:
                    logger.info("SKIP_SELF num=%s", num.decode())
                    _mark_seen(imap, num)
                    processed += 1
                    continue

                answer = _ask_agent(sender_email, subject, body)
                logger.info("AGENT_OK len=%d", len(answer))

                _send_reply(
                    smtp_host=smtp_host,
                    smtp_port=smtp_port,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    recipient=sender_email,
                    original_subject=subject,
                    reply_text=answer,
                )
                logger.info("SEND_OK to=%s", sender_email)
                processed += 1

            except Exception:
                failed += 1
                logger.exception("MSG_ERROR num=%s", num.decode())
            finally:
                # Mark every attempted message as read, including failed ones,
                # so one bad message cannot block subsequent polling runs.
                _mark_seen(imap, num)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"processed": processed, "failed": failed},
            ensure_ascii=False,
        ),
    }
