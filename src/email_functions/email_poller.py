import imaplib
import logging
import os
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parseaddr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def _get_text_body(message) -> str:
    part = message.get_body(preferencelist=("plain",))
    if part is not None:
        return part.get_content().strip()

    # Fallback for a non-multipart text/plain email.
    if message.get_content_type() == "text/plain":
        return message.get_content().strip()

    return ""

def _mark_seen(imap: imaplib.IMAP4_SSL, num: bytes) -> None:
    status, _ = imap.store(num, "+FLAGS", "\\Seen")
    if status != "OK":
        raise RuntimeError(f"Cannot mark message {num!r} as Seen: {status}")


def handle(event, context):
    imap_host = os.getenv("IMAP_HOST", "imap.yandex.ru")
    imap_user = _required_env("IMAP_USER")
    imap_password = _required_env("IMAP_PASSWORD")
    helpdesk_mailbox = _required_env("HELPDESK_MAILBOX").lower()

    messages = []

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

                if sender_email and sender_email.lower() != helpdesk_mailbox:
                    messages.append({
                        "from": sender_email,
                        "subject": subject,
                        "text": body,
                    })
            finally:
                _mark_seen(imap, num)

    return {"messages": messages}
