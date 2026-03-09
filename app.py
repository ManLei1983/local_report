import asyncio
import datetime as dt
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def env_csv(name: str) -> List[str]:
    value = os.getenv(name, "")
    if not value:
        return []

    items: List[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\r\n,]+", value):
        item = part.strip()
        if item and item not in seen:
            items.append(item)
            seen.add(item)
    return items


@dataclass
class Settings:
    app_name: str = os.getenv("APP_NAME", "Local Group Report")
    listen_host: str = os.getenv("LISTEN_HOST", "0.0.0.0")
    listen_port: int = env_int("LISTEN_PORT", 18080)
    ui_layout_mode: str = os.getenv("UI_LAYOUT_MODE", "grouped").strip().lower()
    ui_auto_refresh_seconds: int = env_int("UI_AUTO_REFRESH_SECONDS", 10)

    db_path: Path = BASE_DIR / os.getenv("DB_PATH", "local_report.db")
    persist_reports: bool = env_bool("PERSIST_REPORTS", False)
    delete_db_on_startup: bool = env_bool("DELETE_DB_ON_STARTUP", True)
    db_clean_interval_days: int = env_int("DB_CLEAN_INTERVAL_DAYS", 0)
    max_regions: int = env_int("MAX_REGIONS", 0)

    auth_token: str = os.getenv("AUTH_TOKEN", "").strip()

    alert_enabled: bool = env_bool("ALERT_ENABLED", True)
    alert_timeout_seconds: int = env_int("ALERT_TIMEOUT_SECONDS", 1200)
    alert_check_interval_seconds: int = env_int("ALERT_CHECK_INTERVAL_SECONDS", 10)
    alert_cooldown_seconds: int = env_int("ALERT_COOLDOWN_SECONDS", 360)
    alert_slow_mode_after_count: int = env_int("ALERT_SLOW_MODE_AFTER_COUNT", 10)
    alert_slow_mode_after_seconds: int = env_int(
        "ALERT_SLOW_MODE_AFTER_SECONDS", 3600
    )
    alert_slow_mode_cooldown_seconds: int = env_int(
        "ALERT_SLOW_MODE_COOLDOWN_SECONDS", 1800
    )
    alert_webhook_url: str = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    alert_webhook_urls: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.ui_layout_mode not in {"grouped", "table"}:
            self.ui_layout_mode = "grouped"
        self.ui_auto_refresh_seconds = max(1, self.ui_auto_refresh_seconds)
        self.alert_timeout_seconds = max(1, self.alert_timeout_seconds)
        self.alert_check_interval_seconds = max(1, self.alert_check_interval_seconds)
        self.alert_cooldown_seconds = max(1, self.alert_cooldown_seconds)
        self.alert_slow_mode_after_count = max(1, self.alert_slow_mode_after_count)
        self.alert_slow_mode_after_seconds = max(1, self.alert_slow_mode_after_seconds)
        self.alert_slow_mode_cooldown_seconds = max(
            self.alert_cooldown_seconds,
            self.alert_slow_mode_cooldown_seconds,
        )

        merged_urls: List[str] = []
        if self.alert_webhook_url:
            merged_urls.append(self.alert_webhook_url)
        for url in env_csv("ALERT_WEBHOOK_URLS"):
            if url not in merged_urls:
                merged_urls.append(url)
        self.alert_webhook_urls = merged_urls


settings = Settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("local_report")


class ReportPayload(BaseModel):
    event: str = Field(default="group_complete_ready_next")
    agent_id: str = Field(min_length=1, max_length=128)
    region: str = Field(default="")
    current_group: Optional[int] = None
    finished_group: int = 0
    next_group: int = 0
    role_index: int = 0
    ts: Optional[str] = None


class RemoveAgentPayload(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)


app = FastAPI(title=settings.app_name)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

state_lock = threading.Lock()
agent_states: Dict[str, Dict[str, Any]] = {}
history_cache: deque = deque(maxlen=2000)
stale_state: Dict[str, bool] = {}
last_alert_sent_at: Dict[str, float] = {}
alert_stale_started_at: Dict[str, float] = {}
alert_sent_count: Dict[str, int] = {}

db_lock = threading.Lock()
db_conn: Optional[sqlite3.Connection] = None
alert_task: Optional[asyncio.Task] = None


def now_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def extract_region_number(region_text: Any) -> Optional[int]:
    match = re.search(r"(\d+)", str(region_text))
    if not match:
        return None
    return int(match.group(1))


def ensure_auth(
    x_auth_token: Optional[str],
    query_auth_token: Optional[str] = None,
) -> None:
    if not settings.auth_token:
        return
    actual_token = x_auth_token or query_auth_token
    if not actual_token or actual_token != settings.auth_token:
        raise HTTPException(status_code=401, detail="invalid auth token")


def init_db() -> None:
    global db_conn
    if (
        (not settings.persist_reports)
        and settings.delete_db_on_startup
        and settings.db_path.exists()
    ):
        try:
            settings.db_path.unlink()
            logger.info("deleted old db on startup: %s", settings.db_path)
        except OSError as exc:
            logger.warning("delete db failed: %s", exc)

    db_conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    with db_conn:
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                region TEXT,
                current_group INTEGER,
                finished_group INTEGER,
                next_group INTEGER,
                role_index INTEGER,
                client_ts TEXT,
                server_time TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        # 兼容旧版本数据库：reports 表可能还没有 created_at 列
        cols = {
            row[1] for row in db_conn.execute("PRAGMA table_info(reports)").fetchall()
        }
        if "created_at" not in cols:
            db_conn.execute(
                "ALTER TABLE reports ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
            )
            db_conn.execute(
                "UPDATE reports SET created_at = CAST(strftime('%s','now') AS INTEGER) "
                "WHERE created_at = 0"
            )
            logger.warning("db schema upgraded: added reports.created_at")

        db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_agent ON reports(agent_id)"
        )
        db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)"
        )
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )
            """
        )


def maybe_cleanup_db() -> None:
    if not db_conn or settings.db_clean_interval_days <= 0:
        return

    today = dt.date.today()
    with db_lock:
        row = db_conn.execute("SELECT v FROM meta WHERE k='last_clean_date'").fetchone()
        last_date = None
        if row:
            try:
                last_date = dt.date.fromisoformat(row[0])
            except ValueError:
                last_date = None
        if last_date and (today - last_date).days < settings.db_clean_interval_days:
            return

        with db_conn:
            if not settings.persist_reports:
                db_conn.execute("DELETE FROM reports")
            db_conn.execute(
                "INSERT INTO meta(k, v) VALUES('last_clean_date', ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (today.isoformat(),),
            )

        if not settings.persist_reports:
            try:
                # 3.8新增：VACUUM 不能在事务内执行
                db_conn.execute("VACUUM")
            except sqlite3.OperationalError as exc:
                logger.warning("db vacuum skipped: %s", exc)

        logger.info("db cleanup executed, persist_reports=%s", settings.persist_reports)


def save_report_to_db(report: Dict[str, Any]) -> None:
    if not db_conn or not settings.persist_reports:
        return
    with db_lock:
        with db_conn:
            db_conn.execute(
                """
                INSERT INTO reports (
                    event, agent_id, region, current_group, finished_group,
                    next_group, role_index, client_ts, server_time, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["event"],
                    report["agent_id"],
                    report["region"],
                    report["current_group"],
                    report["finished_group"],
                    report["next_group"],
                    report["role_index"],
                    report["client_ts"],
                    report["server_time"],
                    int(report["server_epoch"]),
                ),
            )


def delete_agent_from_db(agent_id: str) -> int:
    if not db_conn:
        return 0
    with db_lock:
        with db_conn:
            cur = db_conn.execute("DELETE FROM reports WHERE agent_id=?", (agent_id,))
            return cur.rowcount


def clear_db_reports() -> int:
    if not db_conn:
        return 0
    with db_lock:
        with db_conn:
            cur = db_conn.execute("DELETE FROM reports")
            return cur.rowcount


def list_history(limit: int) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 2000))
    if db_conn and settings.persist_reports:
        with db_lock:
            rows = db_conn.execute(
                """
                SELECT event, agent_id, region, current_group, finished_group, next_group,
                       role_index, client_ts, server_time, created_at
                FROM reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "event": r[0],
                "agent_id": r[1],
                "region": r[2],
                "current_group": r[3],
                "finished_group": r[4],
                "next_group": r[5],
                "role_index": r[6],
                "client_ts": r[7],
                "server_time": r[8],
                "created_at": r[9],
            }
            for r in rows
        ]

    with state_lock:
        data = list(history_cache)[:limit]
    return data


def get_region_stats() -> Dict[str, Any]:
    if settings.max_regions <= 0:
        return {"enabled": False}

    done_regions: set[int] = set()
    with state_lock:
        for item in agent_states.values():
            region_number = extract_region_number(item.get("region", ""))
            if region_number is not None:
                done_regions.add(region_number)

    missing = [
        f"{idx}区"
        for idx in range(1, settings.max_regions + 1)
        if idx not in done_regions
    ]
    return {
        "enabled": True,
        "max_regions": settings.max_regions,
        "completed_count": len(done_regions),
        "missing_regions": missing,
    }


def build_rows() -> List[Dict[str, Any]]:
    now_ts = time.time()
    with state_lock:
        values = list(agent_states.values())

    rows: List[Dict[str, Any]] = []
    for item in values:
        elapsed = int(max(0, now_ts - item["server_epoch"]))
        stale = elapsed > settings.alert_timeout_seconds
        region = item["region"]
        region_number = extract_region_number(region)
        rows.append(
            {
                "event": item["event"],
                "agent_id": item["agent_id"],
                "region": region,
                "region_number": region_number,
                "current_group": item["current_group"],
                "finished_group": item["finished_group"],
                "next_group": item["next_group"],
                "role_index": item["role_index"],
                "client_ts": item["client_ts"],
                "server_time": item["server_time"],
                "elapsed": elapsed,
                "stale": stale,
            }
        )

    rows.sort(
        key=lambda x: (
            x["region_number"] is None,
            x["region_number"] if x["region_number"] is not None else float("inf"),
            str(x["region"]),
            str(x["agent_id"]),
        )
    )
    return rows


def build_region_groups(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []

    for row in rows:
        region_label = str(row["region"]).strip() or "未分区"
        if (
            groups
            and groups[-1]["region"] == region_label
            and groups[-1]["region_number"] == row["region_number"]
        ):
            group = groups[-1]
        else:
            group = {
                "region": region_label,
                "region_number": row["region_number"],
                "count": 0,
                "stale_count": 0,
                "rows": [],
            }
            groups.append(group)

        group["rows"].append(row)
        group["count"] += 1
        if row["stale"]:
            group["stale_count"] += 1

    return groups


def post_wecom_markdown_to_url(webhook_url: str, payload: Dict[str, Any]) -> bool:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", "ignore")
        result = json.loads(body) if body else {}
        if result.get("errcode") == 0:
            return True
        logger.warning("wecom webhook error response: %s", body)
        return False
    except Exception as exc:  # pragma: no cover
        logger.warning("wecom webhook request failed: %s", exc)
        return False


def post_wecom_markdown_sync(content: str) -> bool:
    if not settings.alert_webhook_urls:
        logger.warning(
            "skip wecom alert: ALERT_WEBHOOK_URL / ALERT_WEBHOOK_URLS is empty"
        )
        return False

    payload = {
        "msgtype": "markdown",
        "markdown": {"content": content},
    }
    success_count = 0
    total = len(settings.alert_webhook_urls)

    for webhook_url in settings.alert_webhook_urls:
        if post_wecom_markdown_to_url(webhook_url, payload):
            success_count += 1

    if success_count == 0:
        return False
    if success_count < total:
        logger.warning("wecom alert partial success: %s/%s", success_count, total)
    return True


async def post_wecom_markdown(content: str) -> bool:
    return await asyncio.to_thread(post_wecom_markdown_sync, content)


def build_timeout_markdown(item: Dict[str, Any], elapsed: int) -> str:
    return (
        f"[{item['agent_id']} 上报超时告警]\n"
        f"- 区服: `{item['region']}`\n"
        f"- 当前执行组: `{item['current_group']}`\n"
        f"- 当前角色: `{item['role_index']}`\n"
        f"- 最后上报时间: `{item['server_time']}`\n"
        f"- 距今秒数: `{elapsed}`\n"
    )


def build_recover_markdown(item: Dict[str, Any], elapsed: int) -> str:
    return (
        f"[{item['agent_id']} 上报恢复通知]\n"
        f"- 区服: `{item['region']}`\n"
        f"- 当前执行组: `{item['current_group']}`\n"
        f"- 当前角色: `{item['role_index']}`\n"
        f"- 最新上报时间: `{item['server_time']}`\n"
        f"- 当前距今秒数: `{elapsed}`\n"
    )


def get_alert_cooldown_seconds(agent_id: str, now_ts: float) -> int:
    stale_started_at = alert_stale_started_at.get(agent_id, now_ts)
    sent_count = alert_sent_count.get(agent_id, 0)
    stale_duration = now_ts - stale_started_at

    if (
        sent_count >= settings.alert_slow_mode_after_count
        and stale_duration >= settings.alert_slow_mode_after_seconds
    ):
        return settings.alert_slow_mode_cooldown_seconds

    return settings.alert_cooldown_seconds


async def check_alerts_once() -> None:
    if not settings.alert_enabled:
        return

    now_ts = time.time()
    rows = build_rows()
    stale_snapshot: Dict[str, bool] = {}

    for row in rows:
        agent_id = row["agent_id"]
        elapsed = row["elapsed"]
        is_stale = row["stale"]
        stale_snapshot[agent_id] = is_stale
        prev_stale = stale_state.get(agent_id, False)

        if is_stale:
            if not prev_stale:
                alert_stale_started_at[agent_id] = now_ts
                alert_sent_count[agent_id] = 0
                last_alert_sent_at.pop(agent_id, None)

            last_sent = last_alert_sent_at.get(agent_id, 0.0)
            cooldown_seconds = get_alert_cooldown_seconds(agent_id, now_ts)
            if (now_ts - last_sent) >= cooldown_seconds:
                ok = await post_wecom_markdown(build_timeout_markdown(row, elapsed))
                if ok:
                    last_alert_sent_at[agent_id] = now_ts
                    alert_sent_count[agent_id] = alert_sent_count.get(agent_id, 0) + 1
                    logger.warning(
                        "timeout alert sent: agent=%s elapsed=%s cooldown=%s count=%s",
                        agent_id,
                        elapsed,
                        cooldown_seconds,
                        alert_sent_count[agent_id],
                    )
            stale_state[agent_id] = True
        else:
            if prev_stale:
                ok = await post_wecom_markdown(build_recover_markdown(row, elapsed))
                if ok:
                    logger.info("recover alert sent: agent=%s", agent_id)
            stale_state[agent_id] = False
            alert_stale_started_at.pop(agent_id, None)
            alert_sent_count.pop(agent_id, None)
            last_alert_sent_at.pop(agent_id, None)

    with state_lock:
        active_ids = set(agent_states.keys())
    stale_keys = list(stale_state.keys())
    for key in stale_keys:
        if key not in active_ids:
            stale_state.pop(key, None)
            last_alert_sent_at.pop(key, None)
            alert_stale_started_at.pop(key, None)
            alert_sent_count.pop(key, None)


async def alert_loop() -> None:
    interval = max(1, settings.alert_check_interval_seconds)
    while True:
        try:
            await asyncio.sleep(interval)
            await check_alerts_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            logger.exception("alert loop error: %s", exc)


@app.on_event("startup")
async def on_startup() -> None:
    init_db()
    maybe_cleanup_db()
    logger.info(
        "startup complete, persist_reports=%s db=%s timeout=%ss alert_enabled=%s",
        settings.persist_reports,
        settings.db_path,
        settings.alert_timeout_seconds,
        settings.alert_enabled,
    )
    global alert_task
    alert_task = asyncio.create_task(alert_loop())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    global alert_task
    if alert_task:
        alert_task.cancel()
        try:
            await alert_task
        except asyncio.CancelledError:
            pass
        alert_task = None

    if db_conn:
        with db_lock:
            db_conn.close()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    rows = build_rows()
    region_groups = build_region_groups(rows)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "timeout": settings.alert_timeout_seconds,
            "ui_layout_mode": settings.ui_layout_mode,
            "ui_auto_refresh_seconds": settings.ui_auto_refresh_seconds,
            "rows": rows,
            "region_groups": region_groups,
            "region_stats": get_region_stats(),
        },
    )


@app.get("/api/status")
async def api_status() -> Dict[str, Any]:
    rows = build_rows()
    return {"ok": True, "server_time": now_str(), "count": len(rows), "rows": rows}


@app.get("/api/history")
async def api_history(limit: int = 100) -> Dict[str, Any]:
    data = list_history(limit)
    return {"ok": True, "count": len(data), "rows": data}


@app.get("/api/region_stats")
async def api_region_stats() -> Dict[str, Any]:
    return {"ok": True, **get_region_stats()}


@app.post("/api/report")
async def api_report(
    payload: ReportPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    server_time = now_str()
    server_epoch = time.time()
    current_group = (
        payload.current_group
        if payload.current_group is not None
        else payload.finished_group
    )

    report = {
        "event": payload.event,
        "agent_id": payload.agent_id,
        "region": payload.region,
        "current_group": current_group,
        "finished_group": payload.finished_group,
        "next_group": payload.next_group,
        "role_index": payload.role_index,
        "client_ts": payload.ts,
        "server_time": server_time,
        "server_epoch": server_epoch,
    }

    with state_lock:
        agent_states[payload.agent_id] = report
        history_cache.appendleft(
            {
                "event": payload.event,
                "agent_id": payload.agent_id,
                "region": payload.region,
                "current_group": current_group,
                "finished_group": payload.finished_group,
                "next_group": payload.next_group,
                "role_index": payload.role_index,
                "client_ts": payload.ts,
                "server_time": server_time,
                "created_at": int(server_epoch),
            }
        )

    save_report_to_db(report)
    logger.info(
        "report received: agent=%s region=%s group=%s role=%s",
        payload.agent_id,
        payload.region,
        current_group,
        payload.role_index,
    )
    return {"ok": True, "server_time": server_time}


@app.post("/api/agent/remove")
async def api_agent_remove(
    payload: RemoveAgentPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)

    removed = False
    with state_lock:
        if payload.agent_id in agent_states:
            agent_states.pop(payload.agent_id, None)
            removed = True
        stale_state.pop(payload.agent_id, None)
        last_alert_sent_at.pop(payload.agent_id, None)
        alert_stale_started_at.pop(payload.agent_id, None)
        alert_sent_count.pop(payload.agent_id, None)

    deleted_rows = (
        delete_agent_from_db(payload.agent_id) if settings.persist_reports else 0
    )
    return {"ok": True, "removed": removed, "deleted_history_rows": deleted_rows}


@app.post("/api/agents/clear")
async def api_agents_clear(
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)

    with state_lock:
        agent_count = len(agent_states)
        agent_states.clear()
        stale_state.clear()
        last_alert_sent_at.clear()
        alert_stale_started_at.clear()
        alert_sent_count.clear()

    deleted_rows = clear_db_reports() if settings.persist_reports else 0
    return {
        "ok": True,
        "cleared_agents": agent_count,
        "deleted_history_rows": deleted_rows,
    }


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {"ok": True, "time": now_str()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.listen_host,
        port=settings.listen_port,
        reload=False,
    )
