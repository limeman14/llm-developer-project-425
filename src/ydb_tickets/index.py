"""
Yandex Cloud Function: ydb-tickets
Путь в репозитории: src/ydb_tickets/index.py
Точка входа (entrypoint) в настройках CF: index.handle

Зависимости (requirements.txt рядом с этим файлом):
    ydb>=3.0.0

Переменные окружения / секреты функции:
    YDB_ENDPOINT   - например grpcs://ydb.serverless.yandexcloud.net:2135
    YDB_DATABASE   - например /ru-central1/xxxx/yyyy

Сервисному аккаунту функции нужна роль ydb.editor (или выше) на базе данных,
аутентификация внутри CF идёт через MetadataUrlCredentials (метаданные СА,
привязанного к функции) — отдельный IAM-токен передавать не нужно.

DDL таблиц (создать заранее, например через YDB CLI/консоль):

CREATE TABLE tickets (
    id Utf8,
    user_id Utf8,
    category Utf8,
    text Utf8,
    status Utf8,
    created_at Utf8,
    PRIMARY KEY (id)
);

CREATE TABLE messages (
    id Utf8,
    ticket_id Utf8,
    author Utf8,
    text Utf8,
    tokens Int64,
    created_at Utf8,
    PRIMARY KEY (id)
);

Контракт функции — три источника события:
  1) Прямой invoke (yc serverless function invoke):
     event = {"action": "create-ticket", "user_id": "...", ...}
  2) API Gateway (x-yc-apigateway-integration: cloud_functions):
     event = {"httpMethod": "POST", "body": "<JSON-строка>", ...}
     Тело нужно json.loads(), action лежит внутри body.
  3) MCP Hub:
     аргументы инструмента приходят НАПРЯМУЮ как event, без обёртки
     {"tool": ...} и без ключа "action". Действие определяется по
     набору присутствующих ключей:
       - ticket_id + text                    -> append-message
       - user_id + category + text           -> create-ticket
       - только user_id (без category/text/ticket_id) -> list-my-tickets
"""

import base64
import datetime
import json
import logging
import os
import uuid

import ydb
import ydb.iam

logger = logging.getLogger("ydb-tickets")
logger.setLevel(logging.INFO)

YDB_ENDPOINT = os.environ.get("YDB_ENDPOINT", "")
YDB_DATABASE = os.environ.get("YDB_DATABASE", "")

_driver = None
_pool = None


def _get_pool():
    """Ленивая инициализация драйвера/пула — переиспользуется между
    "тёплыми" вызовами одного инстанса функции."""
    global _driver, _pool
    if _pool is not None:
        return _pool

    if not YDB_ENDPOINT or not YDB_DATABASE:
        # Частая причина "тикет не создаётся" — секреты не подцепились
        raise RuntimeError(
            "YDB_ENDPOINT/YDB_DATABASE пусты. Проверьте, что переменные "
            "окружения/секреты функции сохранены и версия функции "
            "пересоздана после их добавления."
        )

    credentials = ydb.iam.MetadataUrlCredentials()
    driver_config = ydb.DriverConfig(
        endpoint=YDB_ENDPOINT,
        database=YDB_DATABASE,
        credentials=credentials,
    )
    driver = ydb.Driver(driver_config)
    driver.wait(timeout=5, fail_fast=True)
    pool = ydb.SessionPool(driver, size=5)

    _driver = driver
    _pool = pool
    return _pool


def _now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# ---------------------------------------------------------------------------
# Операции с YDB. Параметры передаются только через prepared statements:
# session.prepare(yql) -> transaction().execute(prepared, {"$name": value}).
# ---------------------------------------------------------------------------

def _create_ticket(pool, user_id, category, text):
    ticket_id = str(uuid.uuid4())
    created_dt = datetime.datetime.utcnow()
    created_at_iso = created_dt.isoformat() + "Z"

    def callee(session):
        prepared = session.prepare(
            """
            DECLARE $ticket_id AS Utf8;
            DECLARE $user_id AS Utf8;
            DECLARE $category AS Utf8;
            DECLARE $text AS Utf8;
            DECLARE $status AS Utf8;
            DECLARE $created_at AS Timestamp;

            UPSERT INTO tickets (id, user_id, category, text, status, created_at)
            VALUES ($ticket_id, $user_id, $category, $text, $status, $created_at);
            """
        )
        session.transaction(ydb.SerializableReadWrite()).execute(
            prepared,
            {
                "$ticket_id": ticket_id,
                "$user_id": user_id,
                "$category": category,
                "$text": text,
                "$status": "new",
                "$created_at": created_dt,
            },
            commit_tx=True,
        )

    pool.retry_operation_sync(callee)
    return {"ticket_id": ticket_id, "created_at": created_at_iso}


def _list_my_tickets(pool, user_id):
    holder = {"rows": []}

    def callee(session):
        prepared = session.prepare(
            """
            DECLARE $user_id AS Utf8;

            SELECT id, status, category, text, created_at
            FROM tickets
            WHERE user_id = $user_id
            ORDER BY created_at DESC;
            """
        )
        result_sets = session.transaction(ydb.OnlineReadOnly()).execute(
            prepared,
            {"$user_id": user_id},
            commit_tx=True,
        )
        holder["rows"] = result_sets[0].rows

    pool.retry_operation_sync(callee)

    tickets = []
    for row in holder["rows"]:
        created_at = row["created_at"]

        # YDB может вернуть Timestamp как datetime.datetime, а может — как
        # int (микросекунды с эпохи), в зависимости от версии/настроек SDK.
        if isinstance(created_at, (int, float)):
            created_at = datetime.datetime.utcfromtimestamp(created_at / 1_000_000)

        if hasattr(created_at, "isoformat"):
            created_at_str = created_at.isoformat() + "Z"
        else:
            created_at_str = str(created_at)

        tickets.append(
            {
                "id": row["id"],
                "status": row["status"],
                "category": row["category"],
                "text": row["text"],
                "created_at": created_at_str,
            }
        )

    return tickets


def _append_message(pool, ticket_id, author, text, tokens=None):
    # Таблица messages нужна только для разбора/учёта токенов —
    # читать её обратно для памяти агента не требуется.
    message_id = str(uuid.uuid4())
    created_dt = datetime.datetime.utcnow()

    def callee(session):
        prepared = session.prepare(
            """
            DECLARE $message_id AS Utf8;
            DECLARE $ticket_id AS Utf8;
            DECLARE $author AS Utf8;
            DECLARE $text AS Utf8;
            DECLARE $tokens AS Int64;
            DECLARE $created_at AS Timestamp;

            UPSERT INTO messages (id, ticket_id, author, text, tokens, created_at)
            VALUES ($message_id, $ticket_id, $author, $text, $tokens, $created_at);
            """
        )
        session.transaction(ydb.SerializableReadWrite()).execute(
            prepared,
            {
                "$message_id": message_id,
                "$ticket_id": ticket_id,
                "$author": author,
                "$text": text,
                "$tokens": int(tokens or 0),
                "$created_at": created_dt,
            },
            commit_tx=True,
        )

    pool.retry_operation_sync(callee)
    return {"message_id": message_id, "ok": True}


# ---------------------------------------------------------------------------
# Разбор входящего события: 3 разных формата на входе.
# ---------------------------------------------------------------------------

def _normalize_event(event):
    """Возвращает (action, payload, source)."""
    if not isinstance(event, dict):
        raise ValueError("event должен быть JSON-объектом")

    # 2) API Gateway: httpMethod + body (строка, возможно base64)
    if "httpMethod" in event:
        body_raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode("utf-8")
        try:
            payload = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
        except json.JSONDecodeError:
            raise ValueError("Тело запроса не является валидным JSON")
        if not isinstance(payload, dict):
            raise ValueError("Тело запроса должно быть JSON-объектом")
        return payload.get("action"), payload, "api-gateway"

    # 1) Прямой invoke: action указан явно
    if "action" in event:
        return event["action"], event, "direct-invoke"

    # 3) MCP Hub: аргументы инструмента приходят прямо как event,
    # без обёртки {"tool": ...} и без ключа action.
    # Диспетчеризация по набору присутствующих ключей.
    keys = set(event.keys())

    if {"ticket_id", "text"} <= keys:
        return "append-message", event, "mcp-hub"
    if {"user_id", "category", "text"} <= keys:
        return "create-ticket", event, "mcp-hub"
    if "user_id" in keys and not ({"category", "text", "ticket_id"} & keys):
        return "list-my-tickets", event, "mcp-hub"

    return None, event, "mcp-hub"


def _http_response(status_code, body_obj):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body_obj, ensure_ascii=False),
    }


def handle(event, context):
    try:
        action, payload, source = _normalize_event(event)
        logger.info("ydb-tickets: source=%s action=%s", source, action)

        pool = _get_pool()

        if action == "create-ticket":
            user_id = payload.get("user_id")
            category = payload.get("category") or "general"
            text = payload.get("text")
            if not user_id or not text:
                err = {"error": "user_id и text обязательны"}
                return _http_response(400, err) if source == "api-gateway" else err
            result = _create_ticket(pool, user_id, category, text)

        elif action == "list-my-tickets":
            user_id = payload.get("user_id")
            if not user_id:
                err = {"error": "user_id обязателен"}
                return _http_response(400, err) if source == "api-gateway" else err
            result = _list_my_tickets(pool, user_id)

        elif action == "append-message":
            ticket_id = payload.get("ticket_id")
            author = payload.get("author") or payload.get("role") or "agent"
            text = payload.get("text")
            tokens = payload.get("tokens")
            if not ticket_id or not text:
                err = {"error": "ticket_id и text обязательны"}
                return _http_response(400, err) if source == "api-gateway" else err
            result = _append_message(pool, ticket_id, author, text, tokens)

        else:
            logger.error(
                "unknown action: %s (source=%s, keys=%s)",
                action, source, list(payload.keys()),
            )
            err = {"error": f"unknown action: {action}"}
            return _http_response(400, err) if source == "api-gateway" else err

        # API Gateway ждёт HTTP-конверт statusCode/headers/body.
        # Прямой invoke и MCP Hub ждут "голый" JSON — так, как этот
        # результат и так является валидным JSON, оборачивать не нужно.
        if source == "api-gateway":
            return _http_response(200, result)
        return result

    except Exception as exc:  # noqa: BLE001
        logger.exception("ydb-tickets error: %s", exc)
        if isinstance(event, dict) and "httpMethod" in event:
            return _http_response(500, {"error": str(exc)})
        raise
