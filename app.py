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
from urllib.parse import parse_qs, urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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


def split_csv_text(value: str) -> List[str]:
    items: List[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\r\n,]+", value or ""):
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

VALID_DESIRED_RUN_STATES = {"run", "stop"}
VALID_DESIRED_ACTIONS = {"", "start_once", "restart_once", "sync_once", "stop_once"}

AGENT_PROFILE_SELECT_FIELDS = """
    agent_id, enabled, region, group_start, group_end, task_mode, priority,
    profile_version, config_version, config_payload, exe_version, exe_url,
    exe_sha256, startup_exe, startup_args, script_entry,
    resource_manifest_version, notes,
    desired_run_state, schedule_daily_start, auto_restart_on_stale,
    restart_cooldown_seconds, max_restart_per_day, startup_grace_seconds,
    desired_action, action_seq,
    updated_at, updated_epoch
"""


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
    db_conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    db_conn.row_factory = sqlite3.Row
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
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_profiles (
                agent_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                region TEXT DEFAULT '',
                group_start INTEGER NOT NULL DEFAULT 0,
                group_end INTEGER NOT NULL DEFAULT 0,
                task_mode TEXT NOT NULL DEFAULT 'normal',
                priority INTEGER NOT NULL DEFAULT 0,
                profile_version TEXT NOT NULL,
                config_version TEXT DEFAULT '',
                config_payload TEXT DEFAULT '',
                exe_version TEXT DEFAULT '',
                exe_url TEXT DEFAULT '',
                exe_sha256 TEXT DEFAULT '',
                startup_exe TEXT DEFAULT 'QianNian.exe',
                startup_args TEXT DEFAULT '',
                script_entry TEXT DEFAULT '',
                resource_manifest_version TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                updated_at TEXT NOT NULL,
                updated_epoch INTEGER NOT NULL
            )
            """
        )
        ensure_table_columns(
            "agent_profiles",
            {
                "desired_run_state": "TEXT NOT NULL DEFAULT 'run'",
                "schedule_daily_start": "TEXT DEFAULT ''",
                "auto_restart_on_stale": "INTEGER NOT NULL DEFAULT 1",
                "restart_cooldown_seconds": "INTEGER NOT NULL DEFAULT 600",
                "max_restart_per_day": "INTEGER NOT NULL DEFAULT 3",
                "startup_grace_seconds": "INTEGER NOT NULL DEFAULT 300",
                "desired_action": "TEXT DEFAULT ''",
                "action_seq": "INTEGER NOT NULL DEFAULT 0",
            },
        )
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resource_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                kind TEXT NOT NULL DEFAULT 'config',
                version TEXT NOT NULL,
                target_path TEXT DEFAULT '',
                url TEXT DEFAULT '',
                sha256 TEXT DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                target_agents TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                updated_at TEXT NOT NULL,
                updated_epoch INTEGER NOT NULL
            )
            """
        )
        db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_resource_items_enabled ON resource_items(enabled)"
        )
        db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_resource_items_kind ON resource_items(kind)"
        )

    if (not settings.persist_reports) and settings.delete_db_on_startup:
        with db_lock:
            with db_conn:
                db_conn.execute("DELETE FROM reports")
            try:
                db_conn.execute("VACUUM")
            except sqlite3.OperationalError as exc:
                logger.warning("db vacuum skipped on startup: %s", exc)
        logger.info("startup cleanup executed: reports cleared, config kept")


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


def now_epoch() -> int:
    return int(time.time())


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_json_payload(raw_text: str) -> Any:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return None
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return None


async def parse_request_form_data(request: Request) -> Dict[str, str]:
    body = await request.body()
    if not body:
        return {}

    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def append_query_params(path: str, **params: Any) -> str:
    filtered = {k: v for k, v in params.items() if v not in (None, "", [])}
    if not filtered:
        return path
    return f"{path}?{urlencode(filtered)}"


def resolve_download_url(request: Request, raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    if raw_url.startswith(("http://", "https://")):
        return raw_url
    return str(request.base_url).rstrip("/") + "/" + raw_url.lstrip("/")


def build_console_redirect_url(
    auth_token: Optional[str],
    message: Optional[str] = None,
    edit_agent: Optional[str] = None,
    edit_resource_id: Optional[int] = None,
) -> str:
    return append_query_params(
        "/console",
        auth_token=auth_token,
        message=message,
        edit_agent=edit_agent,
        edit_resource_id=edit_resource_id,
    )


def normalize_desired_run_state(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in VALID_DESIRED_RUN_STATES:
        return text
    return "run"


def normalize_desired_action(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in VALID_DESIRED_ACTIONS:
        return text
    return ""


def normalize_daily_start(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    match = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not match:
        return ""

    hour = int(match.group(1))
    minute = int(match.group(2))
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return ""
    return f"{hour:02d}:{minute:02d}"


def ensure_table_columns(table_name: str, column_defs: Dict[str, str]) -> None:
    if not db_conn:
        return

    existing_columns = {
        row[1] for row in db_conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    for column_name, definition in column_defs.items():
        if column_name in existing_columns:
            continue
        db_conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def build_agent_control(agent_profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "desired_run_state": normalize_desired_run_state(
            agent_profile.get("desired_run_state", "run")
        ),
        "schedule_daily_start": normalize_daily_start(
            agent_profile.get("schedule_daily_start", "")
        ),
        "auto_restart_on_stale": bool(
            agent_profile.get("auto_restart_on_stale", True)
        ),
        "restart_cooldown_seconds": max(
            0, parse_int(agent_profile.get("restart_cooldown_seconds"), 600)
        ),
        "max_restart_per_day": max(
            0, parse_int(agent_profile.get("max_restart_per_day"), 3)
        ),
        "startup_grace_seconds": max(
            0, parse_int(agent_profile.get("startup_grace_seconds"), 300)
        ),
        "desired_action": normalize_desired_action(
            agent_profile.get("desired_action", "")
        ),
        "action_seq": max(0, parse_int(agent_profile.get("action_seq"), 0)),
    }


def build_agent_runtime_snapshot(agent_id: str) -> Dict[str, Any]:
    now_ts = time.time()
    with state_lock:
        item = dict(agent_states.get(agent_id, {}))

    if not item:
        return {
            "has_report": False,
            "report_timeout_seconds": settings.alert_timeout_seconds,
            "stale": False,
            "elapsed": None,
            "server_time": "",
            "server_epoch": 0,
            "current_group": 0,
            "finished_group": 0,
            "next_group": 0,
            "role_index": 0,
            "event": "",
        }

    elapsed = int(max(0, now_ts - float(item.get("server_epoch", 0))))
    return {
        "has_report": True,
        "report_timeout_seconds": settings.alert_timeout_seconds,
        "stale": elapsed > settings.alert_timeout_seconds,
        "elapsed": elapsed,
        "server_time": item.get("server_time", ""),
        "server_epoch": item.get("server_epoch", 0),
        "current_group": item.get("current_group", 0),
        "finished_group": item.get("finished_group", 0),
        "next_group": item.get("next_group", 0),
        "role_index": item.get("role_index", 0),
        "event": item.get("event", ""),
    }


def blank_agent_profile() -> Dict[str, Any]:
    return {
        "agent_id": "",
        "enabled": True,
        "region": "",
        "group_start": 0,
        "group_end": 0,
        "task_mode": "normal",
        "priority": 0,
        "profile_version": "",
        "config_version": "",
        "config_payload": "",
        "exe_version": "",
        "exe_url": "",
        "exe_sha256": "",
        "startup_exe": "QianNian.exe",
        "startup_args": "",
        "script_entry": "",
        "resource_manifest_version": "",
        "notes": "",
        "desired_run_state": "run",
        "schedule_daily_start": "",
        "auto_restart_on_stale": True,
        "restart_cooldown_seconds": 600,
        "max_restart_per_day": 3,
        "startup_grace_seconds": 300,
        "desired_action": "",
        "action_seq": 0,
        "updated_at": "",
        "updated_epoch": 0,
    }


def blank_resource_item() -> Dict[str, Any]:
    return {
        "id": 0,
        "name": "",
        "enabled": True,
        "kind": "config",
        "version": "",
        "target_path": "",
        "url": "",
        "sha256": "",
        "size_bytes": 0,
        "target_agents": "",
        "notes": "",
        "updated_at": "",
        "updated_epoch": 0,
    }


def row_to_agent_profile(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "agent_id": row["agent_id"],
        "enabled": bool(row["enabled"]),
        "region": row["region"] or "",
        "group_start": row["group_start"],
        "group_end": row["group_end"],
        "task_mode": row["task_mode"] or "normal",
        "priority": row["priority"],
        "profile_version": row["profile_version"] or "",
        "config_version": row["config_version"] or "",
        "config_payload": row["config_payload"] or "",
        "exe_version": row["exe_version"] or "",
        "exe_url": row["exe_url"] or "",
        "exe_sha256": row["exe_sha256"] or "",
        "startup_exe": row["startup_exe"] or "QianNian.exe",
        "startup_args": row["startup_args"] or "",
        "script_entry": row["script_entry"] or "",
        "resource_manifest_version": row["resource_manifest_version"] or "",
        "notes": row["notes"] or "",
        "desired_run_state": normalize_desired_run_state(
            row["desired_run_state"] if "desired_run_state" in row.keys() else "run"
        ),
        "schedule_daily_start": normalize_daily_start(
            row["schedule_daily_start"] if "schedule_daily_start" in row.keys() else ""
        ),
        "auto_restart_on_stale": bool(
            row["auto_restart_on_stale"]
            if "auto_restart_on_stale" in row.keys()
            else True
        ),
        "restart_cooldown_seconds": parse_int(
            row["restart_cooldown_seconds"]
            if "restart_cooldown_seconds" in row.keys()
            else 600,
            600,
        ),
        "max_restart_per_day": parse_int(
            row["max_restart_per_day"] if "max_restart_per_day" in row.keys() else 3,
            3,
        ),
        "startup_grace_seconds": parse_int(
            row["startup_grace_seconds"]
            if "startup_grace_seconds" in row.keys()
            else 300,
            300,
        ),
        "desired_action": normalize_desired_action(
            row["desired_action"] if "desired_action" in row.keys() else ""
        ),
        "action_seq": parse_int(
            row["action_seq"] if "action_seq" in row.keys() else 0,
            0,
        ),
        "updated_at": row["updated_at"],
        "updated_epoch": row["updated_epoch"],
    }


def row_to_resource_item(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "kind": row["kind"] or "config",
        "version": row["version"] or "",
        "target_path": row["target_path"] or "",
        "url": row["url"] or "",
        "sha256": row["sha256"] or "",
        "size_bytes": row["size_bytes"],
        "target_agents": row["target_agents"] or "",
        "notes": row["notes"] or "",
        "updated_at": row["updated_at"],
        "updated_epoch": row["updated_epoch"],
    }


def list_agent_profiles() -> List[Dict[str, Any]]:
    if not db_conn:
        return []
    with db_lock:
        rows = db_conn.execute(
            """
            SELECT
            """
            + AGENT_PROFILE_SELECT_FIELDS
            +
            """
            FROM agent_profiles
            ORDER BY enabled DESC, agent_id ASC
            """
        ).fetchall()
    return [row_to_agent_profile(row) for row in rows]


def get_agent_profile(agent_id: str) -> Optional[Dict[str, Any]]:
    if not db_conn or not agent_id:
        return None
    with db_lock:
        row = db_conn.execute(
            """
            SELECT
            """
            + AGENT_PROFILE_SELECT_FIELDS
            +
            """
            FROM agent_profiles
            WHERE agent_id = ?
            """,
            (agent_id,),
        ).fetchone()
    return row_to_agent_profile(row) if row else None


def upsert_agent_profile(profile: Dict[str, Any], original_agent_id: Optional[str]) -> None:
    if not db_conn:
        return
    current_time = now_str()
    current_epoch = now_epoch()
    agent_id = profile["agent_id"]
    profile_version = profile["profile_version"] or current_time

    with db_lock:
        with db_conn:
            if original_agent_id and original_agent_id != agent_id:
                db_conn.execute(
                    "DELETE FROM agent_profiles WHERE agent_id = ?",
                    (original_agent_id,),
                )
            db_conn.execute(
                """
                INSERT INTO agent_profiles (
                    agent_id, enabled, region, group_start, group_end, task_mode, priority,
                    profile_version, config_version, config_payload, exe_version, exe_url,
                    exe_sha256, startup_exe, startup_args, script_entry,
                    resource_manifest_version, notes,
                    desired_run_state, schedule_daily_start, auto_restart_on_stale,
                    restart_cooldown_seconds, max_restart_per_day, startup_grace_seconds,
                    desired_action, action_seq,
                    updated_at, updated_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    enabled=excluded.enabled,
                    region=excluded.region,
                    group_start=excluded.group_start,
                    group_end=excluded.group_end,
                    task_mode=excluded.task_mode,
                    priority=excluded.priority,
                    profile_version=excluded.profile_version,
                    config_version=excluded.config_version,
                    config_payload=excluded.config_payload,
                    exe_version=excluded.exe_version,
                    exe_url=excluded.exe_url,
                    exe_sha256=excluded.exe_sha256,
                    startup_exe=excluded.startup_exe,
                    startup_args=excluded.startup_args,
                    script_entry=excluded.script_entry,
                    resource_manifest_version=excluded.resource_manifest_version,
                    notes=excluded.notes,
                    desired_run_state=excluded.desired_run_state,
                    schedule_daily_start=excluded.schedule_daily_start,
                    auto_restart_on_stale=excluded.auto_restart_on_stale,
                    restart_cooldown_seconds=excluded.restart_cooldown_seconds,
                    max_restart_per_day=excluded.max_restart_per_day,
                    startup_grace_seconds=excluded.startup_grace_seconds,
                    desired_action=excluded.desired_action,
                    action_seq=excluded.action_seq,
                    updated_at=excluded.updated_at,
                    updated_epoch=excluded.updated_epoch
                """,
                (
                    agent_id,
                    1 if profile["enabled"] else 0,
                    profile["region"],
                    profile["group_start"],
                    profile["group_end"],
                    profile["task_mode"],
                    profile["priority"],
                    profile_version,
                    profile["config_version"],
                    profile["config_payload"],
                    profile["exe_version"],
                    profile["exe_url"],
                    profile["exe_sha256"],
                    profile["startup_exe"],
                    profile["startup_args"],
                    profile["script_entry"],
                    profile["resource_manifest_version"],
                    profile["notes"],
                    normalize_desired_run_state(profile.get("desired_run_state", "run")),
                    normalize_daily_start(profile.get("schedule_daily_start", "")),
                    1 if profile.get("auto_restart_on_stale", True) else 0,
                    max(0, parse_int(profile.get("restart_cooldown_seconds"), 600)),
                    max(0, parse_int(profile.get("max_restart_per_day"), 3)),
                    max(0, parse_int(profile.get("startup_grace_seconds"), 300)),
                    normalize_desired_action(profile.get("desired_action", "")),
                    max(0, parse_int(profile.get("action_seq"), 0)),
                    current_time,
                    current_epoch,
                ),
            )


def bump_agent_action(agent_id: str, action: str) -> int:
    if not db_conn or not agent_id:
        return 0

    normalized_action = normalize_desired_action(action)
    if not normalized_action:
        return 0

    current_time = now_str()
    current_epoch = now_epoch()

    with db_lock:
        with db_conn:
            row = db_conn.execute(
                "SELECT action_seq FROM agent_profiles WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if not row:
                return 0

            next_seq = parse_int(row["action_seq"], 0) + 1
            db_conn.execute(
                """
                UPDATE agent_profiles
                SET desired_action = ?,
                    action_seq = ?,
                    updated_at = ?,
                    updated_epoch = ?
                WHERE agent_id = ?
                """,
                (normalized_action, next_seq, current_time, current_epoch, agent_id),
            )
            return next_seq


def delete_agent_profile(agent_id: str) -> int:
    if not db_conn or not agent_id:
        return 0
    with db_lock:
        with db_conn:
            cur = db_conn.execute(
                "DELETE FROM agent_profiles WHERE agent_id = ?",
                (agent_id,),
            )
            return cur.rowcount


def resource_applies_to_agent(resource: Dict[str, Any], agent_id: Optional[str]) -> bool:
    targets = split_csv_text(resource.get("target_agents", ""))
    if not targets:
        return True
    if not agent_id:
        return False
    return agent_id in targets


def list_resource_items(
    agent_id: Optional[str] = None,
    enabled_only: bool = False,
) -> List[Dict[str, Any]]:
    if not db_conn:
        return []
    query = """
        SELECT id, name, enabled, kind, version, target_path, url, sha256,
               size_bytes, target_agents, notes, updated_at, updated_epoch
        FROM resource_items
    """
    params: List[Any] = []
    if enabled_only:
        query += " WHERE enabled = ?"
        params.append(1)
    query += " ORDER BY enabled DESC, kind ASC, name ASC"

    with db_lock:
        rows = db_conn.execute(query, params).fetchall()
    items = [row_to_resource_item(row) for row in rows]
    if agent_id is None:
        return items
    return [item for item in items if resource_applies_to_agent(item, agent_id)]


def get_resource_item(resource_id: int) -> Optional[Dict[str, Any]]:
    if not db_conn or resource_id <= 0:
        return None
    with db_lock:
        row = db_conn.execute(
            """
            SELECT id, name, enabled, kind, version, target_path, url, sha256,
                   size_bytes, target_agents, notes, updated_at, updated_epoch
            FROM resource_items
            WHERE id = ?
            """,
            (resource_id,),
        ).fetchone()
    return row_to_resource_item(row) if row else None


def upsert_resource_item(item: Dict[str, Any]) -> int:
    if not db_conn:
        return 0
    current_time = now_str()
    current_epoch = now_epoch()
    version = item["version"] or current_time

    with db_lock:
        with db_conn:
            db_conn.execute(
                """
                INSERT INTO resource_items (
                    id, name, enabled, kind, version, target_path, url, sha256,
                    size_bytes, target_agents, notes, updated_at, updated_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    enabled=excluded.enabled,
                    kind=excluded.kind,
                    version=excluded.version,
                    target_path=excluded.target_path,
                    url=excluded.url,
                    sha256=excluded.sha256,
                    size_bytes=excluded.size_bytes,
                    target_agents=excluded.target_agents,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at,
                    updated_epoch=excluded.updated_epoch
                """,
                (
                    item["id"] if item["id"] > 0 else None,
                    item["name"],
                    1 if item["enabled"] else 0,
                    item["kind"],
                    version,
                    item["target_path"],
                    item["url"],
                    item["sha256"],
                    item["size_bytes"],
                    item["target_agents"],
                    item["notes"],
                    current_time,
                    current_epoch,
                ),
            )
            row = db_conn.execute(
                "SELECT id FROM resource_items WHERE name = ?",
                (item["name"],),
            ).fetchone()
            return int(row[0]) if row else 0


def delete_resource_item(resource_id: int) -> int:
    if not db_conn or resource_id <= 0:
        return 0
    with db_lock:
        with db_conn:
            cur = db_conn.execute(
                "DELETE FROM resource_items WHERE id = ?",
                (resource_id,),
            )
            return cur.rowcount


def build_manifest_items(request: Request, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    manifest_items: List[Dict[str, Any]] = []
    for item in items:
        manifest_items.append(
            {
                "name": item["name"],
                "enabled": item["enabled"],
                "kind": item["kind"],
                "version": item["version"],
                "target_path": item["target_path"],
                "url": resolve_download_url(request, item["url"]),
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "target_agents": split_csv_text(item["target_agents"]),
                "notes": item["notes"],
                "updated_at": item["updated_at"],
            }
        )
    return manifest_items


def build_bootstrap_payload(
    request: Request,
    agent_profile: Dict[str, Any],
    auth_token: Optional[str],
) -> Dict[str, Any]:
    manifest_url = append_query_params(
        str(request.url_for("api_resources_manifest")),
        agent_id=agent_profile["agent_id"],
        auth_token=auth_token,
    )
    resources = list_resource_items(
        agent_id=agent_profile["agent_id"],
        enabled_only=True,
    )
    config_payload = parse_json_payload(agent_profile["config_payload"])
    manifest_items = build_manifest_items(request, resources)

    return {
        "ok": True,
        "server_time": now_str(),
        "agent_id": agent_profile["agent_id"],
        "profile_version": agent_profile["profile_version"],
        "task": {
            "enabled": agent_profile["enabled"],
            "region": agent_profile["region"],
            "group_start": agent_profile["group_start"],
            "group_end": agent_profile["group_end"],
            "task_mode": agent_profile["task_mode"],
            "priority": agent_profile["priority"],
            "notes": agent_profile["notes"],
        },
        "control": build_agent_control(agent_profile),
        "config": {
            "version": agent_profile["config_version"],
            "payload_text": agent_profile["config_payload"],
            "payload_json": config_payload,
        },
        "launch": {
            "startup_exe": agent_profile["startup_exe"],
            "startup_args": agent_profile["startup_args"],
            "script_entry": agent_profile["script_entry"],
        },
        "downloads": {
            "exe": {
                "version": agent_profile["exe_version"],
                "url": resolve_download_url(request, agent_profile["exe_url"]),
                "sha256": agent_profile["exe_sha256"],
            },
            "resources_manifest": {
                "version": agent_profile["resource_manifest_version"],
                "url": manifest_url,
                "count": len(manifest_items),
            },
        },
        "resources": manifest_items,
        "updated_at": agent_profile["updated_at"],
    }


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
async def index(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> HTMLResponse:
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
            "auth_token": auth_token or "",
            "console_url": append_query_params("/console", auth_token=auth_token),
            "agent_profile_count": len(list_agent_profiles()),
            "resource_item_count": len(list_resource_items()),
        },
    )


@app.get("/console", response_class=HTMLResponse)
async def config_console(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
    edit_agent: Optional[str] = Query(default=None),
    edit_resource_id: int = Query(default=0),
    message: str = Query(default=""),
) -> HTMLResponse:
    ensure_auth(None, auth_token)

    agent_profiles = list_agent_profiles()
    resource_items = list_resource_items()
    selected_agent = get_agent_profile(edit_agent or "") or blank_agent_profile()
    selected_resource = get_resource_item(edit_resource_id) or blank_resource_item()

    return templates.TemplateResponse(
        "config_console.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "auth_token": auth_token or "",
            "auth_query_suffix": append_query_params("", auth_token=auth_token),
            "message": message,
            "agent_profiles": agent_profiles,
            "resource_items": resource_items,
            "selected_agent": selected_agent,
            "selected_resource": selected_resource,
            "dashboard_url": append_query_params("/", auth_token=auth_token),
            "agent_profile_count": len(agent_profiles),
            "resource_item_count": len(resource_items),
        },
    )


@app.post("/console/agents/save")
async def console_agent_save(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> RedirectResponse:
    ensure_auth(None, auth_token)
    form = await parse_request_form_data(request)

    agent_id = str(form.get("agent_id", "")).strip()
    if not agent_id:
        return RedirectResponse(
            build_console_redirect_url(auth_token, "Agent ID 不能为空"),
            status_code=303,
        )

    profile = {
        "agent_id": agent_id,
        "enabled": form.get("enabled") == "on",
        "region": str(form.get("region", "")).strip(),
        "group_start": parse_int(form.get("group_start"), 0),
        "group_end": parse_int(form.get("group_end"), 0),
        "task_mode": str(form.get("task_mode", "normal")).strip() or "normal",
        "priority": parse_int(form.get("priority"), 0),
        "profile_version": str(form.get("profile_version", "")).strip(),
        "config_version": str(form.get("config_version", "")).strip(),
        "config_payload": str(form.get("config_payload", "")),
        "exe_version": str(form.get("exe_version", "")).strip(),
        "exe_url": str(form.get("exe_url", "")).strip(),
        "exe_sha256": str(form.get("exe_sha256", "")).strip(),
        "startup_exe": str(form.get("startup_exe", "QianNian.exe")).strip()
        or "QianNian.exe",
        "startup_args": str(form.get("startup_args", "")).strip(),
        "script_entry": str(form.get("script_entry", "")).strip(),
        "resource_manifest_version": str(
            form.get("resource_manifest_version", "")
        ).strip(),
        "notes": str(form.get("notes", "")).strip(),
        "desired_run_state": normalize_desired_run_state(
            form.get("desired_run_state", "run")
        ),
        "schedule_daily_start": normalize_daily_start(
            form.get("schedule_daily_start", "")
        ),
        "auto_restart_on_stale": form.get("auto_restart_on_stale") == "on",
        "restart_cooldown_seconds": max(
            0, parse_int(form.get("restart_cooldown_seconds"), 600)
        ),
        "max_restart_per_day": max(0, parse_int(form.get("max_restart_per_day"), 3)),
        "startup_grace_seconds": max(
            0, parse_int(form.get("startup_grace_seconds"), 300)
        ),
        "desired_action": normalize_desired_action(form.get("desired_action", "")),
        "action_seq": max(0, parse_int(form.get("action_seq"), 0)),
    }

    original_agent_id = str(form.get("original_agent_id", "")).strip() or None
    upsert_agent_profile(profile, original_agent_id)
    return RedirectResponse(
        build_console_redirect_url(
            auth_token,
            f"{agent_id} 配置已保存",
            edit_agent=agent_id,
        ),
        status_code=303,
    )


@app.post("/console/agents/action")
async def console_agent_action(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> RedirectResponse:
    ensure_auth(None, auth_token)
    form = await parse_request_form_data(request)

    agent_id = str(form.get("agent_id", "")).strip()
    action = normalize_desired_action(form.get("action", ""))
    if not agent_id or not action:
        return RedirectResponse(
            build_console_redirect_url(auth_token, "未指定有效动作或 Agent"),
            status_code=303,
        )

    action_seq = bump_agent_action(agent_id, action)
    if action_seq <= 0:
        return RedirectResponse(
            build_console_redirect_url(
                auth_token,
                f"{agent_id} 动作下发失败",
                edit_agent=agent_id,
            ),
            status_code=303,
        )

    return RedirectResponse(
        build_console_redirect_url(
            auth_token,
            f"{agent_id} 已下发动作 {action} (seq={action_seq})",
            edit_agent=agent_id,
        ),
        status_code=303,
    )


@app.post("/console/agents/delete")
async def console_agent_delete(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> RedirectResponse:
    ensure_auth(None, auth_token)
    form = await parse_request_form_data(request)
    agent_id = str(form.get("agent_id", "")).strip()
    if agent_id:
        delete_agent_profile(agent_id)
    return RedirectResponse(
        build_console_redirect_url(auth_token, f"{agent_id or 'Agent'} 配置已删除"),
        status_code=303,
    )


@app.post("/console/resources/save")
async def console_resource_save(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> RedirectResponse:
    ensure_auth(None, auth_token)
    form = await parse_request_form_data(request)

    name = str(form.get("name", "")).strip()
    if not name:
        return RedirectResponse(
            build_console_redirect_url(auth_token, "资源名称不能为空"),
            status_code=303,
        )

    item = {
        "id": parse_int(form.get("resource_id"), 0),
        "name": name,
        "enabled": form.get("enabled") == "on",
        "kind": str(form.get("kind", "config")).strip() or "config",
        "version": str(form.get("version", "")).strip(),
        "target_path": str(form.get("target_path", "")).strip(),
        "url": str(form.get("url", "")).strip(),
        "sha256": str(form.get("sha256", "")).strip(),
        "size_bytes": parse_int(form.get("size_bytes"), 0),
        "target_agents": str(form.get("target_agents", "")).strip(),
        "notes": str(form.get("notes", "")).strip(),
    }
    resource_id = upsert_resource_item(item)
    return RedirectResponse(
        build_console_redirect_url(
            auth_token,
            f"{name} 资源已保存",
            edit_resource_id=resource_id,
        ),
        status_code=303,
    )


@app.post("/console/resources/delete")
async def console_resource_delete(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
) -> RedirectResponse:
    ensure_auth(None, auth_token)
    form = await parse_request_form_data(request)
    resource_id = parse_int(form.get("resource_id"), 0)
    resource = get_resource_item(resource_id)
    if resource_id > 0:
        delete_resource_item(resource_id)
    resource_name = resource["name"] if resource else "资源"
    return RedirectResponse(
        build_console_redirect_url(auth_token, f"{resource_name} 已删除"),
        status_code=303,
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


@app.get("/api/bootstrap")
async def api_bootstrap(
    request: Request,
    agent_id: str = Query(min_length=1),
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    agent_profile = get_agent_profile(agent_id)
    if not agent_profile:
        raise HTTPException(status_code=404, detail="agent profile not found")
    return build_bootstrap_payload(request, agent_profile, auth_token)


@app.get("/api/agent/control")
async def api_agent_control(
    agent_id: str = Query(min_length=1),
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    agent_profile = get_agent_profile(agent_id)
    if not agent_profile:
        raise HTTPException(status_code=404, detail="agent profile not found")

    return {
        "ok": True,
        "server_time": now_str(),
        "agent_id": agent_profile["agent_id"],
        "profile_version": agent_profile["profile_version"],
        "task": {
            "enabled": agent_profile["enabled"],
            "region": agent_profile["region"],
            "group_start": agent_profile["group_start"],
            "group_end": agent_profile["group_end"],
            "task_mode": agent_profile["task_mode"],
            "priority": agent_profile["priority"],
        },
        "control": build_agent_control(agent_profile),
        "runtime": build_agent_runtime_snapshot(agent_profile["agent_id"]),
        "updated_at": agent_profile["updated_at"],
    }


@app.get("/api/resources/manifest", name="api_resources_manifest")
async def api_resources_manifest(
    request: Request,
    agent_id: Optional[str] = Query(default=None),
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    resources = list_resource_items(agent_id=agent_id, enabled_only=True)
    return {
        "ok": True,
        "server_time": now_str(),
        "agent_id": agent_id,
        "count": len(resources),
        "items": build_manifest_items(request, resources),
    }


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
