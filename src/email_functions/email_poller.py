import imaplib
import json
import logging
import os
import re
import smtplib
import time
import urllib.error
import urllib.request
import uuid
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr, formatdate, parseaddr
from html.parser import HTMLParser

import ydb

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_ydb_driver = None

DEFAULT_SYSTEM_PROMPT = (
"""
Ты — Help Desk-агент. Помогаешь пользователям решать вопросы, связанные с внутренними правилами компании (IT, HR и так далее).

Не выдумывай информацию. Если ты не знаешь ответа, не уверен в нём или для решения требуется помощь специалиста — честно скажи об этом и предложи создать тикет в службу поддержки.

Если тебе прислали JSON вида { "count": 1, "input": {}, "tickets":{...}} - сформируй краткий дайджест по списку тикетов, переданному в сообщении. Если возможно, разбей их по категориям, составь краткое описание и на сколько часов/дней тикет просрочен.
Ни при каких обстоятельствах не включай в ответ пользователю сырой JSON, идентификаторы внутренних полей или служебные структуры — только связный текст на естественном языке.

Перед каждым ответом на вопрос пользователя ОБЯЗАТЕЛЬНО обращайся к базе знаний через file_search. Если найден релевантный фрагмент — дай краткое резюме в 2-3 предложения и укажи название документа-источника. Никогда не цитируй документ дословно более чем на 3 предложения. Если релевантных документов не найдено или релевантность низкая — честно скажи, что не располагаешь информацией, и предложи создать тикет через create-ticket.

У тебя есть два инструмента: create-ticket, list-my-tickets. Используй их по следующим правилам.

В начале сообщения пользователя указан отправитель (user_id) — его email. При вызове create-ticket и list-my-tickets передавай это значение в поле user_id без изменений: не маскируй, не сокращай и не заменяй его.

create-ticket — на ПЕРВОЕ сообщение пользователя по новой проблеме тикет НЕ создавай, даже если тебе кажется, что нужен специалист (например, сломалось оборудование). Сначала всегда дай пользователю лучший доступный совет по диагностике/решению через file_search. Создавай тикет только при одном из условий:
  а) пользователь в этом же диалоге явно написал, что твой совет не помог, проблема не решена, или прямо просит создать тикет/обращение/заявку;
  б) вопрос по своей природе не может быть решён советом в принципе и требует действия с твоей стороны невозможного (возврат средств, разбор инцидента, выдача доступа) — и это ясно уже из первого сообщения (например, "оформите мне возврат за заказ").
Перед созданием нового тикета сначала вызови list-my-tickets и проверь, нет ли уже открытой заявки по этой же теме — если есть, не дублируй её, а сообщи пользователю номер существующего тикета. Не заводи тикет ради справочных вопросов, уточнения статуса или реплик без конкретного запроса на действие.

list-my-tickets — вызывай, когда пользователь спрашивает про статус, историю или список своих обращений, перед созданием нового тикета для проверки дублей, или когда пользователь ссылается на прошлое обращение, но не помнит номер. Не вызывай его «про запас» без явного повода в разговоре; если список пуст, честно скажи, что активных заявок не найдено.

Не утверждай, что создал тикет, показал заявки, если фактически не вызвал соответствующий инструмент и не получил от него подтверждение.
"""
).strip()

class _HTMLTextExtractor(HTMLParser):
    """Извлечение чистого текста из HTML-тел без внешних зависимостей."""
    def __init__(self):
        super().__init__()
        self.text_parts = []

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_parts.append(text)

    def get_text(self) -> str:
        return " ".join(self.text_parts).strip()


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value


def _get_iam_token() -> str:
    """Получение IAM-токена из metadata-сервиса Cloud Functions."""
    url = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
    req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["access_token"]
    except Exception as exc:
        logger.error("Failed to retrieve IAM token from metadata: %s", exc)
        raise


def _get_ydb_driver():
    global _ydb_driver
    if _ydb_driver is None:
        endpoint = _required_env("YDB_ENDPOINT")
        database = _required_env("YDB_DATABASE")
        credentials = ydb.iam.MetadataUrlCredentials()
        driver_config = ydb.DriverConfig(
            endpoint=endpoint,
            database=database,
            credentials=credentials,
        )
        _ydb_driver = ydb.Driver(driver_config)
        _ydb_driver.wait(fail_fast=True, timeout=10)
    return _ydb_driver


def _get_conversation_history(
        pool: ydb.SessionPool,
        user_id: str,
        limit: int = 10,
) -> list[dict]:
    def _execute(session):
        query = """
        DECLARE $user_id AS Utf8;
        DECLARE $limit AS Uint64;

        SELECT role, text, created_at FROM messages
        WHERE user_id = $user_id
        ORDER BY created_at DESC
        LIMIT $limit;
        """
        rs = session.transaction().execute(
            session.prepare(query),
            {"$user_id": user_id, "$limit": limit},
            commit_tx=True,
        )
        history = []
        for row in rs[0].rows:
            role = row.role.decode("utf-8") if isinstance(row.role, bytes) else row.role
            text = row.text.decode("utf-8") if isinstance(row.text, bytes) else row.text
            history.append({"role": role, "text": text})
        return history

    history = pool.retry_operation_sync(_execute)
    history.reverse()
    return history


# ---------------------------------------------------------------------------
# PII-маскирование. Применяется непосредственно перед записью в messages
# (см. _save_message), а не раньше в пайплайне — так гарантируется, что
# любой путь записи пройдёт через маскирование. Формат маски:
#   телефон -> +7 (***) ***-**-NN (последние 2 цифры сохраняются)
#   email   -> [email]
#   карта   -> ****-****-****-****
# ---------------------------------------------------------------------------

_PHONE_RE = re.compile(
    r"(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?(\d{2})"
)
# Телефон без префикса: 10 цифр, начинающихся с 8/9 (напр. 9123456789).
_PHONE_BARE_RE = re.compile(r"(?<!\d)[89]\d{9}(?!\d)")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CARD_RE = re.compile(r"\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b")


def mask_phone(text):
    text = _PHONE_RE.sub(lambda m: f"+7 (***) ***-**-{m.group(1)}", text)
    return _PHONE_BARE_RE.sub(
        lambda m: f"+7 (***) ***-**-{m.group(0)[-2:]}", text
    )


def mask_email(text):
    return _EMAIL_RE.sub("[email]", text)


def mask_card(text):
    return _CARD_RE.sub("****-****-****-****", text)


def mask_pii(text):
    """Маскирует телефон, email и номер карты в тексте. Порядок важен:
    телефон и email маскируются раньше карты, чтобы длинные цифровые
    последовательности телефона не были ошибочно приняты за номер карты."""
    if not text:
        return text
    text = mask_phone(text)
    text = mask_email(text)
    text = mask_card(text)
    return text


# ---------------------------------------------------------------------------
# Guardrail на входе poller'а: дешёвый regex-предфильтр от явных инъекций.
# Авторитетный классификатор живёт в CF ydb-tickets на границе записи;
# здесь отсекаем очевидное, чтобы не гонять инъекцию в LLM.
# ---------------------------------------------------------------------------

_INJECTION_RE = re.compile(
    r"(?i)ignore( all)? previous instructions"
    r"|проигнорируй.*(предыдущ|все).*инструкц"
    r"|drop table|delete from"
    r"|удали.*(вс[её].*)?тикет"
)


def _is_injection(text: str) -> bool:
    return bool(text) and bool(_INJECTION_RE.search(text))


def _save_message(
        pool: ydb.SessionPool,
        user_id: str,
        ticket_id: str | None,
        role: str,
        text: str,
        model: str = "",
        tokens_in: int = 0,
        tokens_out: int = 0,
        latency_ms: int = 0,
) -> str:
    # PII-маскирование на границе записи: в YDB попадает только
    # masked_text, сырой text используется выше по стеку.
    text = mask_pii(text)
    msg_id = str(uuid.uuid4())
    now_us = int(time.time() * 1_000_000)

    def _execute(session):
        query = """
        DECLARE $user_id AS Utf8;
        DECLARE $id AS Utf8;
        DECLARE $ticket_id AS Utf8?;
        DECLARE $role AS Utf8;
        DECLARE $text AS Utf8;
        DECLARE $model AS Utf8;
        DECLARE $tokens_in AS Uint64;
        DECLARE $tokens_out AS Uint64;
        DECLARE $latency_ms AS Uint32;
        DECLARE $created_at AS Timestamp;

        UPSERT INTO messages (user_id, id, ticket_id, role, text, model, tokens_in, tokens_out, latency_ms, created_at)
        VALUES ($user_id, $id, $ticket_id, $role, $text, $model, $tokens_in, $tokens_out, $latency_ms, $created_at);
        """
        session.transaction().execute(
            session.prepare(query),
            {
                "$user_id": user_id,
                "$id": msg_id,
                "$ticket_id": ticket_id,
                "$role": role,
                "$text": text,
                "$model": model,
                "$tokens_in": tokens_in,
                "$tokens_out": tokens_out,
                "$latency_ms": latency_ms,
                "$created_at": now_us,
            },
            commit_tx=True,
        )

    pool.retry_operation_sync(_execute)
    return msg_id


def _attach_ticket_id(
        pool: ydb.SessionPool,
        user_id: str,
        message_ids: list[str],
        ticket_id: str,
) -> None:
    def _execute(session):
        query = """
        DECLARE $user_id AS Utf8;
        DECLARE $id AS Utf8;
        DECLARE $ticket_id AS Utf8;

        UPDATE messages
        SET ticket_id = $ticket_id
        WHERE user_id = $user_id AND id = $id;
        """
        prepared = session.prepare(query)
        for message_id in message_ids:
            session.transaction().execute(
                prepared,
                {"$user_id": user_id, "$id": message_id, "$ticket_id": ticket_id},
                commit_tx=True,
            )

    pool.retry_operation_sync(_execute)


def _extract_output_text(data: dict) -> str:
    text = data.get("output_text") or ""
    if text:
        return text.strip()

    parts = []
    for item in data.get("output", []) or []:
        if item.get("type") != "message":
            continue
        for content in item.get("content", []) or []:
            if content.get("type") in ("output_text", "text"):
                parts.append(content.get("text", ""))
    return "".join(parts).strip()


def _extract_ticket_id(data: dict) -> str | None:
    for item in data.get("output", []) or []:
        if item.get("type") != "mcp_call" or item.get("name") != "create-ticket":
            continue

        output = item.get("output")
        if isinstance(output, dict):
            if output.get("ticket_id"):
                return str(output["ticket_id"])
            continue
        if not isinstance(output, str):
            continue

        try:
            parsed = json.loads(output)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, dict) and parsed.get("ticket_id"):
            return str(parsed["ticket_id"])

        match = re.search(r'"ticket_id"\s*:\s*"([^"]+)"', output)
        if match:
            return match.group(1)

    return None


def _log_output_tools(data: dict) -> None:
    """Логирует вызовы инструментов (file_search / mcp) из output[].

    Нужно, чтобы отличать «в базе знаний ничего не нашлось» от «индекс
    пустой/чужой»: по results=0 vs results>0 и по именам файлов-источников
    это видно в логах, а не только по формулировке ответа агента."""
    for item in data.get("output", []) or []:
        item_type = item.get("type")
        if item_type == "file_search_call":
            results = item.get("results") or []
            logger.info(
                "FILE_SEARCH status=%s results=%d",
                item.get("status"),
                len(results),
            )
            for result in results:
                logger.info(
                    "FILE_SEARCH_RESULT file=%s score=%s",
                    result.get("filename") or result.get("file_id"),
                    result.get("score"),
                )
        elif item_type == "mcp_call":
            logger.info("MCP_CALL name=%s", item.get("name"))


def _call_responses_api(
        history: list[dict],
        user_text: str,
        user_id: str,
        iam_token: str,
        folder_id: str,
        model_name: str,
        mcp_server_url: str,
        search_index_id: str,
) -> tuple[str, str | None, int, int, int]:
    url = "https://rest-assistant.api.cloud.yandex.net/v1/responses"

    conversation = []
    for m in history:
        conversation.append({
            "role": "assistant" if m["role"] == "agent" else "user",
            "content": m["text"],
        })
    # user_id (email отправителя) передаётся агенту как есть, без
    # маскирования: по нему create-ticket заполняет tickets.user_id и
    # list-my-tickets ищет заявки пользователя. Маскируется только text.
    conversation.append({
        "role": "user",
        "content": f"Отправитель (user_id): {user_id}\n\n{user_text}",
    })

    payload = {
        "model": model_name,
        "input": conversation,
        "instructions": DEFAULT_SYSTEM_PROMPT,
        "tools": [
            {
                "type": "mcp",
                "server_label": "ydb-tickets",
                "server_url": mcp_server_url,
                "require_approval": "never",
            },
            {
                "type": "file_search",
                "vector_store_ids": [search_index_id],
                "max_num_results": 5,
            },
        ],
    }

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers={
            "Authorization": f"Bearer {iam_token}",
            "Content-Type": "application/json",
            "OpenAI-Project": folder_id,
            "x-folder-id": folder_id,
        },
        method="POST",
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8")
        logger.error("Responses API HTTPError %d: %s", exc.code, err_msg)
        raise RuntimeError(f"Responses API error: {err_msg}")

    latency_ms = int((time.monotonic() - t0) * 1000)

    answer_text = _extract_output_text(data)
    ticket_id = _extract_ticket_id(data)
    _log_output_tools(data)

    usage = data.get("usage", {})
    logger.info("USAGE %s", usage)
    tokens_in = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
    tokens_out = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)

    return answer_text, ticket_id, tokens_in, tokens_out, latency_ms


def _send_smtp_reply(
        to_email: str,
        subject: str,
        body: str,
        in_reply_to: str | None = None,
) -> None:
    smtp_host = os.getenv("SMTP_HOST", "smtp.yandex.ru")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = _required_env("SMTP_USER")
    smtp_password = _required_env("SMTP_PASSWORD")
    helpdesk_mailbox = _required_env("HELPDESK_MAILBOX")

    msg = EmailMessage()
    clean_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
    msg["Subject"] = clean_subject
    msg["From"] = formataddr(("Helpdesk", helpdesk_mailbox))
    msg["To"] = to_email
    msg["Date"] = formatdate(localtime=True)

    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to

    msg.set_content(body)

    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
        server.login(smtp_user, smtp_password)
        server.send_message(msg)


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def _get_text_body(message) -> str:
    # 1. Проверяем text/plain
    part = message.get_body(preferencelist=("plain",))
    if part is not None:
        return part.get_content().strip()

    if message.get_content_type() == "text/plain":
        return message.get_content().strip()

    # 2. Fallback на html.parser, если письмо только в HTML
    html_part = message.get_body(preferencelist=("html",))
    if html_part is not None:
        raw_html = html_part.get_content()
        parser = _HTMLTextExtractor()
        parser.feed(raw_html)
        return parser.get_text()

    if message.get_content_type() == "text/html":
        raw_html = message.get_content()
        parser = _HTMLTextExtractor()
        parser.feed(raw_html)
        return parser.get_text()

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
    folder_id = _required_env("YC_FOLDER_ID")
    mcp_server_url = _required_env("MCP_SERVER_URL")
    search_index_id = _required_env("SEARCH_INDEX_ID")
    model_name = os.getenv("AI_MODEL", f"gpt://{folder_id}/yandexgpt/latest")

    driver = _get_ydb_driver()
    pool = ydb.SessionPool(driver)

    iam_token = _get_iam_token()
    processed_count = 0

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
            msg_num_str = num.decode("utf-8", errors="ignore")
            try:
                status, raw_data = imap.fetch(num, "(RFC822)")
                if status != "OK" or not raw_data or raw_data[0] is None:
                    raise RuntimeError(f"Cannot fetch message {num!r}")

                message = BytesParser(policy=policy.default).parsebytes(raw_data[0][1])
                _, sender_email = parseaddr(message.get("From", ""))
                sender_email = sender_email.strip().lower()
                subject = _decode_header(message.get("Subject"))
                body = _get_text_body(message)
                msg_id = message.get("Message-ID")

                logger.info(
                    "MSG num=%s from=%s subject=%s",
                    msg_num_str,
                    sender_email,
                    mask_pii(subject),
                )

                if not sender_email or sender_email == helpdesk_mailbox or not body:
                    _mark_seen(imap, num)
                    continue

                if _is_injection(f"{subject}\n{body}"):
                    logger.warning(
                        "ALERT_INJECTION_BLOCKED from=%s num=%s",
                        sender_email,
                        msg_num_str,
                    )
                    _mark_seen(imap, num)
                    continue

                masked_body = mask_pii(body)

                # 1. YDB: история диалога пользователя (от старых к новым)
                history = _get_conversation_history(pool, sender_email)

                # 2. YDB: сохранение входящего сообщения до вызова LLM
                user_msg_id = _save_message(
                    pool, sender_email, None, role="user", text=masked_body
                )

                # 3. Responses API + MCP create-ticket
                (
                    reply_text,
                    ticket_id,
                    tokens_in,
                    tokens_out,
                    latency_ms,
                ) = _call_responses_api(
                    history=history,
                    user_text=masked_body,
                    user_id=sender_email,
                    iam_token=iam_token,
                    folder_id=folder_id,
                    model_name=model_name,
                    mcp_server_url=mcp_server_url,
                    search_index_id=search_index_id,
                )
                logger.info("AGENT_OK len=%d ticket=%s", len(reply_text), ticket_id)

                # 4. YDB: сохранение ответа агента
                agent_msg_id = _save_message(
                    pool,
                    sender_email,
                    None,
                    role="agent",
                    text=reply_text,
                    model=model_name,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    latency_ms=latency_ms,
                )

                # 5. YDB: привязка обеих реплик цикла к созданному тикету
                if ticket_id:
                    _attach_ticket_id(
                        pool, sender_email, [user_msg_id, agent_msg_id], ticket_id
                    )

                # 6. SMTP: отправка ответа клиенту
                _send_smtp_reply(
                    to_email=sender_email,
                    subject=subject,
                    body=reply_text,
                    in_reply_to=msg_id,
                )
                logger.info("SEND_OK to=%s", sender_email)

                # 7. Маркировка прочитанным
                _mark_seen(imap, num)
                processed_count += 1

            except Exception as e:
                logger.exception("Failed processing message num=%s: %s", msg_num_str, e)
                # По подсказке: при ошибке все равно маркируем \Seen, чтобы poller не зациклился
                try:
                    _mark_seen(imap, num)
                except Exception as mark_err:
                    logger.error("Failed fallback marking seen for %s: %s", msg_num_str, mark_err)

    return {"processed": processed_count}