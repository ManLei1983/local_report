import asyncio
import datetime as dt
import json
import logging
import os
import re
import sys
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


if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
    RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = Path(__file__).resolve().parent
    RESOURCE_DIR = APP_DIR

load_dotenv(APP_DIR / ".env")


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

    db_path: Path = APP_DIR / os.getenv("DB_PATH", "local_report.db")
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
    alert_slow_mode_after_seconds: int = env_int("ALERT_SLOW_MODE_AFTER_SECONDS", 3600)
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


class RecoveryPayload(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="restart")
    region: str = Field(default="")
    current_group: int = 0
    finished_group: int = 0
    next_group: int = 0
    role_index: int = 0
    hold_seconds: int = 0
    ts: Optional[str] = None


class RemoveAgentPayload(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)


class AgentHeartbeatPayload(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    heartbeat_at: Optional[str] = None
    intent: str = Field(default="none")
    intent_reason: str = Field(default="")
    intent_at: Optional[str] = None
    process_exists: bool = False
    process_pid: int = 0
    status_exists: bool = False
    status_group: int = 0
    status_role_index: int = 0
    status_date: str = Field(default="")
    status_mtime_epoch: float = 0
    last_progress_change_at: Optional[str] = None
    last_restart_at: Optional[str] = None
    restart_count_today: int = 0


class AssistAssignPayload(BaseModel):
    target_agent_id: str = Field(min_length=1, max_length=128)
    helper_agent_id: str = Field(min_length=1, max_length=128)
    region: str = Field(default="")
    delegate_start: int = 0
    delegate_end: int = 0


class AssistClearPayload(BaseModel):
    target_agent_id: str = Field(default="")
    helper_agent_id: str = Field(default="")


app = FastAPI(title=settings.app_name)
templates = Jinja2Templates(directory=str(RESOURCE_DIR / "templates"))


@app.middleware("http")
async def ensure_utf8_charset(request: Request, call_next):
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("application/json") and "charset=" not in content_type.lower():
        response.headers["content-type"] = "application/json; charset=utf-8"
    return response

state_lock = threading.Lock()
agent_states: Dict[str, Dict[str, Any]] = {}
heartbeat_states: Dict[str, Dict[str, Any]] = {}
history_cache: deque = deque(maxlen=2000)
stale_state: Dict[str, bool] = {}
completed_state: Dict[str, bool] = {}
completed_notice_sent: Dict[str, bool] = {}
last_alert_sent_at: Dict[str, float] = {}
alert_stale_started_at: Dict[str, float] = {}
alert_sent_count: Dict[str, int] = {}

db_lock = threading.Lock()
db_conn: Optional[sqlite3.Connection] = None
alert_task: Optional[asyncio.Task] = None


def now_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d")


current_runtime_day = today_str()


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
        # Backfill created_at for older reports tables.
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
            CREATE TABLE IF NOT EXISTS agent_assist_overrides (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                work_date TEXT NOT NULL,
                target_agent_id TEXT NOT NULL,
                helper_agent_id TEXT NOT NULL,
                region TEXT DEFAULT '',
                delegate_start INTEGER NOT NULL DEFAULT 0,
                delegate_end INTEGER NOT NULL DEFAULT 0,
                original_target_group_end INTEGER NOT NULL DEFAULT 0,
                effective_target_group_end INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db_conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_assist_target_date ON agent_assist_overrides(work_date, target_agent_id)"
        )
        db_conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_assist_helper_date ON agent_assist_overrides(work_date, helper_agent_id)"
        )
        db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assist_work_date ON agent_assist_overrides(work_date)"
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
            cutoff_date = (today - dt.timedelta(days=max(settings.db_clean_interval_days, 1))).isoformat()
            db_conn.execute(
                "DELETE FROM agent_assist_overrides WHERE work_date < ?",
                (cutoff_date,),
            )
            db_conn.execute(
                "INSERT INTO meta(k, v) VALUES('last_clean_date', ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (today.isoformat(),),
            )

        if not settings.persist_reports:
            try:
                # 3.8閺傛澘顤冮敍姝廇CUUM 娑撳秷鍏橀崷銊ょ皑閸斺€冲敶閹笛嗩攽
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


QIANNIAN_UI_LAUNCH_BUTTONS = {"", "gongzi", "runtask", "start", "none"}
DEFAULT_COMPLETE_ROLE_INDEX = 5
QIANNIAN_UI_CHECKBOX_KEYS = (
    "trade_setting",
    "gumu_exit",
    "log_file",
    "log_detail",
)
QIANNIAN_UI_LEGACY_TOP_LEVEL_KEYS = {
    "region",
    "group_start",
    "group_end",
    "start_group",
    "current_group",
    "group_id",
    "max_group",
    "max_group_id",
    "selorder",
    "role_index",
    "start_role_index",
    "launch_button",
    "checkboxes",
}


def normalize_launch_button(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in QIANNIAN_UI_LAUNCH_BUTTONS:
        return text
    return ""


def extract_qiannian_ui_settings(raw_text: str) -> Dict[str, Any]:
    defaults = {
        "ui_launch_button": "",
        "ui_role_index": 0,
        "ui_checkbox_trade_setting": False,
        "ui_checkbox_gumu_exit": False,
        "ui_checkbox_log_file": False,
        "ui_checkbox_log_detail": False,
        "config_payload_extra": "",
    }
    payload = parse_json_payload(raw_text)
    if not isinstance(payload, dict):
        return defaults

    payload_copy = dict(payload)
    nested = payload_copy.pop("qiannian_ui", None)
    ui_payload = dict(nested) if isinstance(nested, dict) else {}

    if "launch_button" not in ui_payload and "launch_button" in payload_copy:
        ui_payload["launch_button"] = payload_copy.pop("launch_button")

    if "checkboxes" not in ui_payload and isinstance(
        payload_copy.get("checkboxes"), dict
    ):
        ui_payload["checkboxes"] = payload_copy.pop("checkboxes")

    role_index_value = 0
    for key in ("role_index", "selorder", "start_role_index"):
        if key in ui_payload:
            role_index_value = parse_int(ui_payload.get(key), 0)
            break
        if key in payload_copy:
            role_index_value = parse_int(payload_copy.pop(key), 0)
            break

    for legacy_key in QIANNIAN_UI_LEGACY_TOP_LEVEL_KEYS:
        payload_copy.pop(legacy_key, None)

    checkbox_values = ui_payload.get("checkboxes", {})
    if not isinstance(checkbox_values, dict):
        checkbox_values = {}

    defaults["ui_launch_button"] = normalize_launch_button(
        ui_payload.get("launch_button", "")
    )
    defaults["ui_role_index"] = role_index_value
    for key in QIANNIAN_UI_CHECKBOX_KEYS:
        defaults[f"ui_checkbox_{key}"] = bool(checkbox_values.get(key, False))

    if payload_copy:
        defaults["config_payload_extra"] = json.dumps(
            payload_copy, ensure_ascii=False, indent=2
        )
    return defaults


def attach_qiannian_ui_settings(profile: Dict[str, Any]) -> Dict[str, Any]:
    profile.update(extract_qiannian_ui_settings(str(profile.get("config_payload", ""))))
    profile["config_payload_original"] = str(profile.get("config_payload", ""))
    return profile


def build_config_payload_text(form: Dict[str, str], original_raw: str) -> str:
    original_payload = parse_json_payload(original_raw)
    if not isinstance(original_payload, dict):
        original_payload = {}

    existing_ui_payload = original_payload.get("qiannian_ui")
    if not isinstance(existing_ui_payload, dict):
        existing_ui_payload = {}

    extra_raw = str(form.get("config_payload_extra", "")).strip()
    if extra_raw:
        extra_payload = parse_json_payload(extra_raw)
        if not isinstance(extra_payload, dict):
            raise ValueError("高级 JSON 扩展必须是合法 JSON 对象")
    else:
        extra_payload = {}

    ui_payload = {
        key: value
        for key, value in existing_ui_payload.items()
        if key
        not in {
            "launch_button",
            "role_index",
            "selorder",
            "start_role_index",
            "checkboxes",
        }
    }

    launch_button = normalize_launch_button(form.get("ui_launch_button", ""))
    if launch_button:
        ui_payload["launch_button"] = launch_button

    role_index_text = str(form.get("ui_role_index", "")).strip()
    if role_index_text:
        ui_payload["selorder"] = max(0, parse_int(role_index_text, 0))

    checkbox_values = {
        key: form.get(f"ui_checkbox_{key}") == "on" for key in QIANNIAN_UI_CHECKBOX_KEYS
    }
    ui_payload["checkboxes"] = checkbox_values

    payload: Dict[str, Any] = dict(extra_payload)
    if ui_payload:
        payload["qiannian_ui"] = ui_payload

    return json.dumps(payload, ensure_ascii=False, indent=2) if payload else ""


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
    console_path: str = "/console",
) -> str:
    return append_query_params(
        console_path,
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
        db_conn.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )


def get_agent_complete_role_index(agent_profile: Optional[Dict[str, Any]]) -> int:
    if not agent_profile:
        return DEFAULT_COMPLETE_ROLE_INDEX

    payload = parse_json_payload(str(agent_profile.get("config_payload", "")))
    if isinstance(payload, dict):
        for key in ("complete_role_index", "completed_role_index", "max_role_index"):
            if key in payload:
                return max(0, parse_int(payload.get(key), DEFAULT_COMPLETE_ROLE_INDEX))
    return DEFAULT_COMPLETE_ROLE_INDEX


def get_completion_state(
    agent_profile: Optional[Dict[str, Any]],
    report_item: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    task_context = build_agent_task_context(agent_profile)
    group_end = max(0, parse_int(task_context.get("group_end"), 0))
    complete_role_index = get_agent_complete_role_index(agent_profile)
    if not report_item:
        return {
            "completed": False,
            "target_group_end": group_end,
            "complete_role_index": complete_role_index,
            "completion_basis": "no_report",
        }

    current_group = max(
        parse_int(report_item.get("current_group"), 0),
        parse_int(report_item.get("finished_group"), 0),
    )
    role_index = max(0, parse_int(report_item.get("role_index"), 0))
    event = str(report_item.get("event", "") or "")
    completed = (
        group_end > 0
        and current_group >= group_end
        and role_index >= complete_role_index
        and not event.startswith("recovering:")
    )
    return {
        "completed": completed,
        "target_group_end": group_end,
        "complete_role_index": complete_role_index,
        "completion_basis": f"group>={group_end},role_index>={complete_role_index}",
    }


def build_agent_control(agent_profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "desired_run_state": normalize_desired_run_state(
            agent_profile.get("desired_run_state", "run")
        ),
        "schedule_daily_start": normalize_daily_start(
            agent_profile.get("schedule_daily_start", "")
        ),
        "auto_restart_on_stale": bool(agent_profile.get("auto_restart_on_stale", True)),
        "restart_cooldown_seconds": max(
            0, parse_int(agent_profile.get("restart_cooldown_seconds"), 600)
        ),
        "max_restart_per_day": max(
            0, parse_int(agent_profile.get("max_restart_per_day"), 3)
        ),
        "startup_grace_seconds": max(
            0, parse_int(agent_profile.get("startup_grace_seconds"), 300)
        ),
        "complete_role_index": get_agent_complete_role_index(agent_profile),
        "desired_action": normalize_desired_action(
            agent_profile.get("desired_action", "")
        ),
        "action_seq": max(0, parse_int(agent_profile.get("action_seq"), 0)),
    }

def ensure_runtime_state_for_today() -> None:
    global current_runtime_day
    today = today_str()
    if current_runtime_day == today:
        return

    with state_lock:
        if current_runtime_day == today:
            return
        agent_count = len(agent_states)
        history_count = len(history_cache)
        agent_states.clear()
        heartbeat_states.clear()
        history_cache.clear()
        stale_state.clear()
        completed_state.clear()
        completed_notice_sent.clear()
        last_alert_sent_at.clear()
        alert_stale_started_at.clear()
        alert_sent_count.clear()
        logger.info(
            "runtime state rolled to new day: %s -> %s, cleared agents=%s history=%s",
            current_runtime_day,
            today,
            agent_count,
            history_count,
        )
        current_runtime_day = today


def build_agent_runtime_snapshot(agent_id: str) -> Dict[str, Any]:
    ensure_runtime_state_for_today()
    now_ts = time.time()
    with state_lock:
        item = dict(agent_states.get(agent_id, {}))
        heartbeat_item = dict(heartbeat_states.get(agent_id, {}))

    agent_profile = get_agent_profile(agent_id)
    task_context = build_agent_task_context(agent_profile)
    if not item:
        return {
            "has_report": False,
            "report_timeout_seconds": settings.alert_timeout_seconds,
            "stale": False,
            "result_stale": False,
            "stale_suppressed": False,
            "elapsed": None,
            "server_time": "",
            "server_epoch": 0,
            "current_group": 0,
            "finished_group": 0,
            "next_group": 0,
            "role_index": 0,
            "event": "",
            "completed": False,
            "target_group_end": max(0, parse_int(task_context.get("group_end"), 0)),
            "complete_role_index": get_agent_complete_role_index(agent_profile),
            "completion_basis": "no_report",
            "assist": task_context.get("assist", build_assist_view(None)),
        }

    completion_state = get_completion_state(agent_profile, item)
    elapsed = int(max(0, now_ts - float(item.get("server_epoch", 0))))
    result_stale = False if completion_state["completed"] else elapsed > settings.alert_timeout_seconds
    supervision_snapshot = build_supervision_snapshot(
        agent_profile,
        heartbeat_item or None,
        now_ts=now_ts,
    )
    actionable_stale = should_alert_for_result_stale(
        result_stale,
        supervision_snapshot.get("state_code", ""),
    )
    return {
        "has_report": True,
        "report_timeout_seconds": settings.alert_timeout_seconds,
        "stale": actionable_stale,
        "result_stale": result_stale,
        "stale_suppressed": bool(result_stale and not actionable_stale),
        "elapsed": elapsed,
        "server_time": item.get("server_time", ""),
        "server_epoch": item.get("server_epoch", 0),
        "current_group": item.get("current_group", 0),
        "finished_group": item.get("finished_group", 0),
        "next_group": item.get("next_group", 0),
        "role_index": item.get("role_index", 0),
        "event": item.get("event", ""),
        "completed": completion_state["completed"],
        "target_group_end": completion_state["target_group_end"],
        "complete_role_index": completion_state["complete_role_index"],
        "completion_basis": completion_state["completion_basis"],
        "assist": task_context.get("assist", build_assist_view(None)),
    }


SUPERVISION_ISSUE_CODES = {"suspected_stuck", "startup_failed"}
SUPERVISION_STALE_SUPPRESS_CODES = {"running", "starting", "waiting_schedule"}
RESULT_ACTIVE_CODES = {"fresh", "stale", "completed"}
DEFAULT_HEARTBEAT_MISSING_SECONDS = 90
DEFAULT_PROGRESS_STALL_SECONDS = 900
DEFAULT_GONGZI_PROGRESS_STALL_SECONDS = 1800
INTENT_REASON_LABELS = {
    "": "-",
    "schedule": "定时启动",
    "daily_schedule": "定时启动",
    "daily_rollover": "跨天重启",
    "manual_run": "手动启动",
    "manual_restart": "手动重启",
    "restart_once": "手动重启",
    "start_once": "手动启动",
    "report_stale": "结果超时后重启",
    "startup_no_report": "启动后久未出结果",
    "resume_pending_session": "按今日进度续跑",
    "manual_stop": "手动停止",
    "stop_once": "手动停止",
    "manual_skip_today": "跳过今天",
    "skip_today": "跳过今天",
}


def parse_datetime_text(value: Any) -> Optional[dt.datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("T", " ")
    if len(normalized) >= 19:
        normalized = normalized[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return dt.datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    return None


def parse_hhmm_text(value: Any) -> Optional[tuple[int, int]]:
    text = str(value or "").strip()
    if not text:
        return None
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not match:
        return None
    hour = int(match.group(1))
    minute = int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return hour, minute


def get_supervision_overrides(agent_profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not agent_profile:
        return {}
    payload = parse_json_payload(str(agent_profile.get("config_payload", "")))
    if not isinstance(payload, dict):
        return {}
    supervision = payload.get("supervision")
    if isinstance(supervision, dict):
        return supervision
    return {}


def get_supervision_thresholds(agent_profile: Optional[Dict[str, Any]]) -> Dict[str, int]:
    profile = agent_profile or {}
    control = build_agent_control(profile) if profile else {"startup_grace_seconds": 300}
    overrides = get_supervision_overrides(agent_profile)
    launch_button = str(profile.get("ui_launch_button", "")).strip().lower()
    task_mode = str(profile.get("task_mode", "normal")).strip().lower()
    default_progress_stall = (
        DEFAULT_GONGZI_PROGRESS_STALL_SECONDS
        if launch_button == "gongzi" or task_mode == "gongzi"
        else DEFAULT_PROGRESS_STALL_SECONDS
    )
    progress_stall_seconds = max(
        60,
        parse_int(overrides.get("progress_stall_seconds"), default_progress_stall),
    )
    heartbeat_missing_seconds = max(
        30,
        parse_int(
            overrides.get("heartbeat_missing_seconds"),
            DEFAULT_HEARTBEAT_MISSING_SECONDS,
        ),
    )
    return {
        "startup_grace_seconds": max(
            30,
            parse_int(control.get("startup_grace_seconds"), 300),
        ),
        "progress_stall_seconds": progress_stall_seconds,
        "heartbeat_missing_seconds": heartbeat_missing_seconds,
        "report_timeout_seconds": max(1, settings.alert_timeout_seconds),
    }

def build_result_snapshot(
    agent_profile: Optional[Dict[str, Any]],
    report_item: Optional[Dict[str, Any]],
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    current_ts = time.time() if now_ts is None else now_ts
    completion_state = get_completion_state(agent_profile, report_item)
    report_timeout_seconds = max(1, settings.alert_timeout_seconds)
    if not report_item:
        return {
            "has_report": False,
            "state_code": "not_reported",
            "state_label": "未上报",
            "detail": "今天还没有收到组完成结果上报",
            "elapsed": None,
            "stale": False,
            "completed": False,
            "server_time": "",
            "event": "",
            "target_group_end": completion_state["target_group_end"],
            "complete_role_index": completion_state["complete_role_index"],
            "completion_basis": completion_state["completion_basis"],
            "report_timeout_seconds": report_timeout_seconds,
            "current_group": 0,
            "finished_group": 0,
            "next_group": 0,
            "role_index": 0,
        }

    event = str(report_item.get("event", "") or "")
    if event.startswith("recovering:"):
        return {
            "has_report": False,
            "state_code": "not_reported",
            "state_label": "未上报",
            "detail": "当前处于恢复保护期，等待新的组完成结果",
            "elapsed": None,
            "stale": False,
            "completed": False,
            "server_time": report_item.get("server_time", ""),
            "event": event,
            "target_group_end": completion_state["target_group_end"],
            "complete_role_index": completion_state["complete_role_index"],
            "completion_basis": completion_state["completion_basis"],
            "report_timeout_seconds": report_timeout_seconds,
            "current_group": parse_int(report_item.get("current_group"), 0),
            "finished_group": parse_int(report_item.get("finished_group"), 0),
            "next_group": parse_int(report_item.get("next_group"), 0),
            "role_index": parse_int(report_item.get("role_index"), 0),
        }

    elapsed = int(max(0, current_ts - float(report_item.get("server_epoch", 0))))
    stale = False if completion_state["completed"] else elapsed > report_timeout_seconds
    if completion_state["completed"]:
        state_code = "completed"
        state_label = "已完成"
        detail = (
            f"已达到结束组 {completion_state['target_group_end']}，角色阈值 {completion_state['complete_role_index']}"
        )
    elif stale:
        state_code = "stale"
        state_label = "结果超时"
        detail = f"已超过 {report_timeout_seconds} 秒未收到新的组完成结果"
    else:
        state_code = "fresh"
        state_label = "结果新鲜"
        detail = f"最近 {elapsed} 秒内收到过有效结果"

    return {
        "has_report": True,
        "state_code": state_code,
        "state_label": state_label,
        "detail": detail,
        "elapsed": elapsed,
        "stale": stale,
        "completed": completion_state["completed"],
        "server_time": report_item.get("server_time", ""),
        "event": event,
        "target_group_end": completion_state["target_group_end"],
        "complete_role_index": completion_state["complete_role_index"],
        "completion_basis": completion_state["completion_basis"],
        "report_timeout_seconds": report_timeout_seconds,
        "current_group": parse_int(report_item.get("current_group"), 0),
        "finished_group": parse_int(report_item.get("finished_group"), 0),
        "next_group": parse_int(report_item.get("next_group"), 0),
        "role_index": parse_int(report_item.get("role_index"), 0),
    }

def build_heartbeat_snapshot(
    heartbeat_item: Optional[Dict[str, Any]],
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    current_ts = time.time() if now_ts is None else now_ts
    if not heartbeat_item:
        return {
            "has_heartbeat": False,
            "server_time": "",
            "server_epoch": 0,
            "heartbeat_elapsed": None,
            "intent": "none",
            "intent_reason": "",
            "intent_at": "",
            "process_exists": False,
            "process_pid": 0,
            "status_exists": False,
            "status_group": 0,
            "status_role_index": 0,
            "status_date": "",
            "status_mtime_epoch": 0,
            "last_progress_change_at": "",
            "last_restart_at": "",
            "restart_count_today": 0,
        }

    return {
        "has_heartbeat": True,
        "server_time": heartbeat_item.get("server_time", ""),
        "server_epoch": float(heartbeat_item.get("server_epoch", 0) or 0),
        "heartbeat_elapsed": int(
            max(0, current_ts - float(heartbeat_item.get("server_epoch", 0) or 0))
        ),
        "intent": str(heartbeat_item.get("intent", "none") or "none"),
        "intent_reason": str(heartbeat_item.get("intent_reason", "") or ""),
        "intent_at": str(heartbeat_item.get("intent_at", "") or ""),
        "process_exists": bool(heartbeat_item.get("process_exists", False)),
        "process_pid": parse_int(heartbeat_item.get("process_pid"), 0),
        "status_exists": bool(heartbeat_item.get("status_exists", False)),
        "status_group": parse_int(heartbeat_item.get("status_group"), 0),
        "status_role_index": parse_int(heartbeat_item.get("status_role_index"), 0),
        "status_date": str(heartbeat_item.get("status_date", "") or ""),
        "status_mtime_epoch": float(heartbeat_item.get("status_mtime_epoch", 0) or 0),
        "last_progress_change_at": str(
            heartbeat_item.get("last_progress_change_at", "") or ""
        ),
        "last_restart_at": str(heartbeat_item.get("last_restart_at", "") or ""),
        "restart_count_today": max(
            0,
            parse_int(heartbeat_item.get("restart_count_today"), 0),
        ),
    }


def describe_action_text(intent: str, reason: str) -> str:
    reason_key = str(reason or "").strip()
    reason_label = INTENT_REASON_LABELS.get(reason_key, reason_key or "-")
    mapping = {
        "start_requested": "启动请求",
        "restart_requested": "重启请求",
        "stop_requested": "停止请求",
        "skip_today": "跳过今天",
    }
    prefix = mapping.get(str(intent or "").strip(), "")
    if prefix and reason_label and reason_label != "-":
        return f"{prefix} / {reason_label}"
    if prefix:
        return prefix
    return reason_label if reason_label != "-" else "-"

def build_supervision_snapshot(
    agent_profile: Optional[Dict[str, Any]],
    heartbeat_item: Optional[Dict[str, Any]],
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    current_ts = time.time() if now_ts is None else now_ts
    now_dt = dt.datetime.fromtimestamp(current_ts)
    profile = agent_profile or {}
    thresholds = get_supervision_thresholds(agent_profile)
    schedule_text = normalize_daily_start(profile.get("schedule_daily_start", ""))
    schedule_hhmm = parse_hhmm_text(schedule_text)
    schedule_due_today = False
    if schedule_hhmm is not None:
        due_dt = now_dt.replace(
            hour=schedule_hhmm[0], minute=schedule_hhmm[1], second=0, microsecond=0
        )
        schedule_due_today = now_dt < due_dt

    heartbeat = build_heartbeat_snapshot(heartbeat_item, now_ts=current_ts)
    if not heartbeat["has_heartbeat"]:
        if schedule_due_today:
            return {
                "state_code": "waiting_schedule",
                "state_label": "等待定时",
                "detail": f"今天计划在 {schedule_text} 启动，当前仍在等待",
                "heartbeat_elapsed": None,
                "action_text": "-",
                "last_progress_change_at": "",
            }
        return {
            "state_code": "stopped",
            "state_label": "已停止",
            "detail": "尚未收到 game_tool 的证据心跳",
            "heartbeat_elapsed": None,
            "action_text": "-",
            "last_progress_change_at": "",
        }

    heartbeat_elapsed = heartbeat["heartbeat_elapsed"]
    intent = heartbeat["intent"]
    intent_reason = heartbeat["intent_reason"]
    intent_dt = parse_datetime_text(heartbeat["intent_at"])
    last_progress_dt = parse_datetime_text(heartbeat["last_progress_change_at"])
    action_text = describe_action_text(intent, intent_reason)

    if (
        heartbeat_elapsed is not None
        and heartbeat_elapsed > thresholds["heartbeat_missing_seconds"]
    ):
        if heartbeat["process_exists"]:
            return {
                "state_code": "suspected_stuck",
                "state_label": "疑似卡住",
                "detail": f"已超过 {thresholds['heartbeat_missing_seconds']} 秒未收到 heartbeat，最后一次显示进程仍存在",
                "heartbeat_elapsed": heartbeat_elapsed,
                "action_text": action_text,
                "last_progress_change_at": heartbeat["last_progress_change_at"],
            }
        return {
            "state_code": "stopped",
            "state_label": "已停止",
            "detail": f"已超过 {thresholds['heartbeat_missing_seconds']} 秒未收到 heartbeat，最后一次显示无进程",
            "heartbeat_elapsed": heartbeat_elapsed,
            "action_text": action_text,
            "last_progress_change_at": heartbeat["last_progress_change_at"],
        }

    if intent == "skip_today":
        return {
            "state_code": "waiting_schedule",
            "state_label": "等待定时",
            "detail": "今天已被标记为跳过，等待下一次计划启动",
            "heartbeat_elapsed": heartbeat_elapsed,
            "action_text": action_text,
            "last_progress_change_at": heartbeat["last_progress_change_at"],
        }

    intent_elapsed: Optional[int] = None
    if intent_dt is not None:
        intent_elapsed = int(max(0, (now_dt - intent_dt).total_seconds()))

    if intent in {"start_requested", "restart_requested"}:
        if intent_elapsed is not None and intent_elapsed <= thresholds["startup_grace_seconds"]:
            return {
                "state_code": "starting",
                "state_label": "启动中",
                "detail": f"处于 {thresholds['startup_grace_seconds']} 秒启动保护期内",
                "heartbeat_elapsed": heartbeat_elapsed,
                "action_text": action_text,
                "last_progress_change_at": heartbeat["last_progress_change_at"],
            }
        if not heartbeat["process_exists"]:
            return {
                "state_code": "startup_failed",
                "state_label": "启动失败",
                "detail": f"超过 {thresholds['startup_grace_seconds']} 秒仍未检测到 qiannian 进程",
                "heartbeat_elapsed": heartbeat_elapsed,
                "action_text": action_text,
                "last_progress_change_at": heartbeat["last_progress_change_at"],
            }

    if not heartbeat["process_exists"]:
        if schedule_due_today and intent != "stop_requested":
            return {
                "state_code": "waiting_schedule",
                "state_label": "等待定时",
                "detail": f"今天计划在 {schedule_text} 启动，当前仍在等待",
                "heartbeat_elapsed": heartbeat_elapsed,
                "action_text": action_text,
                "last_progress_change_at": heartbeat["last_progress_change_at"],
            }
        return {
            "state_code": "stopped",
            "state_label": "已停止",
            "detail": "当前未检测到 qiannian 进程",
            "heartbeat_elapsed": heartbeat_elapsed,
            "action_text": action_text,
            "last_progress_change_at": heartbeat["last_progress_change_at"],
        }

    if last_progress_dt is None:
        if intent in {"start_requested", "restart_requested"} and intent_elapsed is not None:
            remaining = max(0, thresholds["startup_grace_seconds"] - intent_elapsed)
            return {
                "state_code": "starting",
                "state_label": "启动中",
                "detail": f"进程已存在，但还没看到 status.ini 推进证据，剩余保护期约 {remaining} 秒",
                "heartbeat_elapsed": heartbeat_elapsed,
                "action_text": action_text,
                "last_progress_change_at": heartbeat["last_progress_change_at"],
            }
        return {
            "state_code": "suspected_stuck",
            "state_label": "疑似卡住",
            "detail": "进程存在，但还没有看到任何 status.ini 推进证据",
            "heartbeat_elapsed": heartbeat_elapsed,
            "action_text": action_text,
            "last_progress_change_at": heartbeat["last_progress_change_at"],
        }

    progress_elapsed = int(max(0, (now_dt - last_progress_dt).total_seconds()))
    if progress_elapsed <= thresholds["progress_stall_seconds"]:
        return {
            "state_code": "running",
            "state_label": "运行中",
            "detail": f"最近 {progress_elapsed} 秒内看到过 status.ini 推进",
            "heartbeat_elapsed": heartbeat_elapsed,
            "action_text": action_text,
            "last_progress_change_at": heartbeat["last_progress_change_at"],
        }
    return {
        "state_code": "suspected_stuck",
        "state_label": "疑似卡住",
        "detail": f"进程存在，但已超过 {thresholds['progress_stall_seconds']} 秒未看到 status.ini 推进",
        "heartbeat_elapsed": heartbeat_elapsed,
        "action_text": action_text,
        "last_progress_change_at": heartbeat["last_progress_change_at"],
    }


def build_dashboard_summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "agent_count": len(rows),
        "supervision_issue_count": sum(
            1 for row in rows if row.get("supervision_code") in SUPERVISION_ISSUE_CODES
        ),
        "waiting_count": sum(
            1 for row in rows if row.get("supervision_code") == "waiting_schedule"
        ),
        "running_count": sum(
            1 for row in rows if row.get("supervision_code") == "running"
        ),
        "result_stale_count": sum(
            1 for row in rows if row.get("result_code") == "stale"
        ),
        "completed_count": sum(
            1 for row in rows if row.get("result_code") == "completed"
        ),
    }



def blank_agent_profile() -> Dict[str, Any]:
    return attach_qiannian_ui_settings(
        {
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
    )


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
    return attach_qiannian_ui_settings(
        {
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
                row["schedule_daily_start"]
                if "schedule_daily_start" in row.keys()
                else ""
            ),
            "auto_restart_on_stale": bool(
                row["auto_restart_on_stale"]
                if "auto_restart_on_stale" in row.keys()
                else True
            ),
            "restart_cooldown_seconds": parse_int(
                (
                    row["restart_cooldown_seconds"]
                    if "restart_cooldown_seconds" in row.keys()
                    else 600
                ),
                600,
            ),
            "max_restart_per_day": parse_int(
                (
                    row["max_restart_per_day"]
                    if "max_restart_per_day" in row.keys()
                    else 3
                ),
                3,
            ),
            "startup_grace_seconds": parse_int(
                (
                    row["startup_grace_seconds"]
                    if "startup_grace_seconds" in row.keys()
                    else 300
                ),
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
    )


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
            + """
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
            + """
            FROM agent_profiles
            WHERE agent_id = ?
            """,
            (agent_id,),
        ).fetchone()
    return row_to_agent_profile(row) if row else None


def upsert_agent_profile(
    profile: Dict[str, Any], original_agent_id: Optional[str]
) -> None:
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
                    normalize_desired_run_state(
                        profile.get("desired_run_state", "run")
                    ),
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


def row_to_assist_override(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "work_date": row["work_date"],
        "target_agent_id": row["target_agent_id"],
        "helper_agent_id": row["helper_agent_id"],
        "region": row["region"] or "",
        "delegate_start": parse_int(row["delegate_start"], 0),
        "delegate_end": parse_int(row["delegate_end"], 0),
        "original_target_group_end": parse_int(
            row["original_target_group_end"], 0
        ),
        "effective_target_group_end": parse_int(
            row["effective_target_group_end"], 0
        ),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_active_assist_for_target(
    agent_id: str,
    work_date: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not db_conn or not agent_id:
        return None
    effective_date = str(work_date or today_str())
    with db_lock:
        row = db_conn.execute(
            """
            SELECT id, work_date, target_agent_id, helper_agent_id, region,
                   delegate_start, delegate_end,
                   original_target_group_end, effective_target_group_end,
                   created_at, updated_at
            FROM agent_assist_overrides
            WHERE work_date = ? AND target_agent_id = ?
            """,
            (effective_date, agent_id),
        ).fetchone()
    return row_to_assist_override(row) if row else None


def get_active_assist_for_helper(
    agent_id: str,
    work_date: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not db_conn or not agent_id:
        return None
    effective_date = str(work_date or today_str())
    with db_lock:
        row = db_conn.execute(
            """
            SELECT id, work_date, target_agent_id, helper_agent_id, region,
                   delegate_start, delegate_end,
                   original_target_group_end, effective_target_group_end,
                   created_at, updated_at
            FROM agent_assist_overrides
            WHERE work_date = ? AND helper_agent_id = ?
            """,
            (effective_date, agent_id),
        ).fetchone()
    return row_to_assist_override(row) if row else None


def build_assist_view(
    assist_row: Optional[Dict[str, Any]],
    role: str = "",
) -> Dict[str, Any]:
    if not assist_row:
        return {
            "active": False,
            "role": "",
            "summary": "",
        }
    helper_agent_id = str(assist_row.get("helper_agent_id", "") or "")
    target_agent_id = str(assist_row.get("target_agent_id", "") or "")
    delegate_start = parse_int(assist_row.get("delegate_start"), 0)
    delegate_end = parse_int(assist_row.get("delegate_end"), 0)
    effective_group_end = parse_int(
        assist_row.get("effective_target_group_end"), 0
    )
    region = str(assist_row.get("region", "") or "")
    if role == "helper":
        summary = (
            f"\u534f\u52a9 {target_agent_id} \u5c3e\u6bb5 {delegate_start}->{delegate_end}"
            + (f" / \u533a\u670d {region}" if region else "")
        )
    elif role == "target":
        summary = (
            f"\u7531 {helper_agent_id} \u63a5\u624b {delegate_start}->{delegate_end}"
            f"\uff0c\u4eca\u65e5\u6709\u6548\u7ed3\u675f\u7ec4 {effective_group_end}"
        )
    else:
        summary = (
            f"{helper_agent_id} -> {target_agent_id}"
            f" {delegate_start}->{delegate_end}"
        )
    return {
        **assist_row,
        "active": True,
        "role": role,
        "summary": summary,
    }


def get_latest_agent_progress(agent_id: str) -> Dict[str, Any]:
    progress_group = 0
    role_index = 0
    source = "none"
    server_time = ""
    with state_lock:
        report_item = dict(agent_states.get(agent_id, {}))
        heartbeat_item = dict(heartbeat_states.get(agent_id, {}))
    if report_item:
        progress_group = max(
            progress_group,
            parse_int(report_item.get("current_group"), 0),
            parse_int(report_item.get("finished_group"), 0),
        )
        role_index = max(role_index, parse_int(report_item.get("role_index"), 0))
        server_time = str(report_item.get("server_time", "") or server_time)
        source = "memory_report"
    if heartbeat_item:
        heartbeat_group = parse_int(heartbeat_item.get("status_group"), 0)
        heartbeat_role = parse_int(heartbeat_item.get("status_role_index"), 0)
        if heartbeat_group > progress_group or (
            heartbeat_group == progress_group and heartbeat_role > role_index
        ):
            progress_group = heartbeat_group
            role_index = heartbeat_role
            server_time = str(heartbeat_item.get("server_time", "") or server_time)
            source = "heartbeat"
    if progress_group > 0 or not db_conn or not settings.persist_reports:
        return {
            "group": progress_group,
            "role_index": role_index,
            "server_time": server_time,
            "source": source,
        }
    with db_lock:
        row = db_conn.execute(
            """
            SELECT current_group, finished_group, role_index, server_time
            FROM reports
            WHERE agent_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (agent_id,),
        ).fetchone()
    if not row:
        return {
            "group": progress_group,
            "role_index": role_index,
            "server_time": server_time,
            "source": source,
        }
    progress_group = max(
        progress_group,
        parse_int(row["current_group"], 0),
        parse_int(row["finished_group"], 0),
    )
    role_index = max(role_index, parse_int(row["role_index"], 0))
    server_time = str(row["server_time"] or server_time)
    source = "db_report"
    return {
        "group": progress_group,
        "role_index": role_index,
        "server_time": server_time,
        "source": source,
    }


def validate_assist_region(target_region: str, requested_region: str) -> str:
    target_text = str(target_region or "").strip()
    requested_text = str(requested_region or "").strip()
    if not requested_text:
        return target_text
    if not target_text:
        return requested_text
    target_number = extract_region_number(target_text)
    requested_number = extract_region_number(requested_text)
    if target_number is not None and requested_number is not None:
        if target_number != requested_number:
            raise ValueError(
                f"\u533a\u670d {requested_text} \u4e0e\u76ee\u6807 Agent \u7684\u533a\u670d {target_text} \u4e0d\u4e00\u81f4"
            )
        return requested_text
    if target_text != requested_text:
        raise ValueError(
            f"\u533a\u670d {requested_text} \u4e0e\u76ee\u6807 Agent \u7684\u533a\u670d {target_text} \u4e0d\u4e00\u81f4"
        )
    return requested_text


def upsert_assist_override(payload: AssistAssignPayload) -> Dict[str, Any]:
    if not db_conn:
        raise ValueError("\u6570\u636e\u5e93\u672a\u521d\u59cb\u5316")
    target_agent_id = str(payload.target_agent_id or "").strip()
    helper_agent_id = str(payload.helper_agent_id or "").strip()
    if not target_agent_id or not helper_agent_id:
        raise ValueError("helper_agent_id \u548c target_agent_id \u90fd\u4e0d\u80fd\u4e3a\u7a7a")
    if target_agent_id == helper_agent_id:
        raise ValueError("helper_agent_id \u4e0d\u80fd\u4e0e target_agent_id \u76f8\u540c")

    target_profile = get_agent_profile(target_agent_id)
    helper_profile = get_agent_profile(helper_agent_id)
    if not target_profile:
        raise ValueError(f"\u76ee\u6807 Agent \u4e0d\u5b58\u5728: {target_agent_id}")
    if not helper_profile:
        raise ValueError(f"\u534f\u52a9 Agent \u4e0d\u5b58\u5728: {helper_agent_id}")

    delegate_start = max(0, parse_int(payload.delegate_start, 0))
    delegate_end = max(0, parse_int(payload.delegate_end, 0))
    target_group_start = max(0, parse_int(target_profile.get("group_start"), 0))
    target_group_end = max(0, parse_int(target_profile.get("group_end"), 0))
    if delegate_start <= 0 or delegate_end <= 0:
        raise ValueError("delegate_start \u548c delegate_end \u90fd\u5fc5\u987b\u5927\u4e8e 0")
    if delegate_end < delegate_start:
        raise ValueError("delegate_end \u4e0d\u80fd\u5c0f\u4e8e delegate_start")
    if target_group_end <= 0:
        raise ValueError("\u76ee\u6807 Agent \u672a\u914d\u7f6e\u6709\u6548\u7684\u7ed3\u675f\u7ec4")
    if delegate_end != target_group_end:
        raise ValueError(
            f"\u7b2c\u4e00\u7248\u53ea\u652f\u6301\u5c3e\u6bb5\u63a5\u624b\uff0cdelegate_end \u5fc5\u987b\u7b49\u4e8e\u76ee\u6807\u7ed3\u675f\u7ec4 {target_group_end}"
        )
    if delegate_start <= target_group_start:
        raise ValueError(
            f"delegate_start \u5fc5\u987b\u5927\u4e8e\u76ee\u6807\u8d77\u59cb\u7ec4 {target_group_start}"
        )

    helper_active = get_active_assist_for_helper(helper_agent_id)
    if helper_active and helper_active.get("target_agent_id") != target_agent_id:
        raise ValueError(
            f"\u534f\u52a9 Agent {helper_agent_id} \u4eca\u5929\u5df2\u7ecf\u5728\u534f\u52a9 {helper_active.get('target_agent_id')}"
        )
    target_active = get_active_assist_for_target(target_agent_id)
    if target_active and target_active.get("helper_agent_id") != helper_agent_id:
        raise ValueError(
            f"\u76ee\u6807 Agent {target_agent_id} \u4eca\u5929\u5df2\u7ecf\u88ab {target_active.get('helper_agent_id')} \u63a5\u624b"
        )

    latest_progress = get_latest_agent_progress(target_agent_id)
    if parse_int(latest_progress.get("group"), 0) >= delegate_start:
        raise ValueError(
            f"\u76ee\u6807 Agent {target_agent_id} \u5f53\u524d\u8fdb\u5ea6\u5df2\u5230 {latest_progress.get('group', 0)}\uff0c\u4e0d\u80fd\u518d\u5206\u914d {delegate_start}->{delegate_end}"
        )

    effective_group_end = delegate_start - 1
    region = validate_assist_region(
        str(target_profile.get("region", "") or ""),
        str(payload.region or ""),
    )
    current_time = now_str()
    work_date = today_str()

    with db_lock:
        with db_conn:
            db_conn.execute(
                "DELETE FROM agent_assist_overrides WHERE work_date = ? AND (target_agent_id = ? OR helper_agent_id = ?)",
                (work_date, target_agent_id, helper_agent_id),
            )
            db_conn.execute(
                """
                INSERT INTO agent_assist_overrides (
                    work_date, target_agent_id, helper_agent_id, region,
                    delegate_start, delegate_end,
                    original_target_group_end, effective_target_group_end,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    work_date,
                    target_agent_id,
                    helper_agent_id,
                    region,
                    delegate_start,
                    delegate_end,
                    target_group_end,
                    effective_group_end,
                    current_time,
                    current_time,
                ),
            )
            row = db_conn.execute(
                """
                SELECT id, work_date, target_agent_id, helper_agent_id, region,
                       delegate_start, delegate_end,
                       original_target_group_end, effective_target_group_end,
                       created_at, updated_at
                FROM agent_assist_overrides
                WHERE work_date = ? AND target_agent_id = ?
                """,
                (work_date, target_agent_id),
            ).fetchone()
    return row_to_assist_override(row)


def clear_assist_override(
    helper_agent_id: str = "",
    target_agent_id: str = "",
    work_date: Optional[str] = None,
) -> int:
    if not db_conn:
        return 0
    helper_agent_id = str(helper_agent_id or "").strip()
    target_agent_id = str(target_agent_id or "").strip()
    if not helper_agent_id and not target_agent_id:
        return 0
    effective_date = str(work_date or today_str())
    clauses: List[str] = ["work_date = ?"]
    params: List[Any] = [effective_date]
    if helper_agent_id:
        clauses.append("helper_agent_id = ?")
        params.append(helper_agent_id)
    if target_agent_id:
        clauses.append("target_agent_id = ?")
        params.append(target_agent_id)
    sql = "DELETE FROM agent_assist_overrides WHERE " + " AND ".join(clauses)
    with db_lock:
        with db_conn:
            cur = db_conn.execute(sql, tuple(params))
            return cur.rowcount


def build_agent_task_context(
    agent_profile: Optional[Dict[str, Any]],
    work_date: Optional[str] = None,
) -> Dict[str, Any]:
    profile = agent_profile or {}
    profile_region = str(profile.get("region", "") or "")
    profile_group_start = max(0, parse_int(profile.get("group_start"), 0))
    profile_group_end = max(0, parse_int(profile.get("group_end"), 0))
    context = {
        "enabled": bool(profile.get("enabled", True)),
        "region": profile_region,
        "group_start": profile_group_start,
        "group_end": profile_group_end,
        "profile_group_start": profile_group_start,
        "profile_group_end": profile_group_end,
        "task_mode": str(profile.get("task_mode", "normal") or "normal"),
        "priority": max(0, parse_int(profile.get("priority"), 0)),
        "notes": str(profile.get("notes", "") or ""),
        "assist": build_assist_view(None),
    }
    agent_id = str(profile.get("agent_id", "") or "")
    if not agent_id:
        return context
    helper_assist = get_active_assist_for_helper(agent_id, work_date=work_date)
    if helper_assist:
        context["region"] = str(helper_assist.get("region", "") or context["region"])
        context["group_start"] = max(
            0, parse_int(helper_assist.get("delegate_start"), context["group_start"])
        )
        context["group_end"] = max(
            0, parse_int(helper_assist.get("delegate_end"), context["group_end"])
        )
        context["assist"] = build_assist_view(helper_assist, role="helper")
        return context
    target_assist = get_active_assist_for_target(agent_id, work_date=work_date)
    if target_assist:
        if target_assist.get("region") and not context["region"]:
            context["region"] = str(target_assist.get("region", "") or "")
        context["group_end"] = max(
            0,
            parse_int(
                target_assist.get("effective_target_group_end"),
                context["group_end"],
            ),
        )
        context["assist"] = build_assist_view(target_assist, role="target")
    return context


def resource_applies_to_agent(
    resource: Dict[str, Any], agent_id: Optional[str]
) -> bool:
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


def build_manifest_items(
    request: Request, items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
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
    task_context = build_agent_task_context(agent_profile)
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
            "enabled": task_context["enabled"],
            "region": task_context["region"],
            "group_start": task_context["group_start"],
            "group_end": task_context["group_end"],
            "profile_group_start": task_context["profile_group_start"],
            "profile_group_end": task_context["profile_group_end"],
            "task_mode": task_context["task_mode"],
            "priority": task_context["priority"],
            "notes": task_context["notes"],
            "assist": task_context["assist"],
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
        "assist": task_context["assist"],
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
    ensure_runtime_state_for_today()
    now_ts = time.time()
    with state_lock:
        report_values = {key: dict(value) for key, value in agent_states.items()}
        heartbeat_values = {key: dict(value) for key, value in heartbeat_states.items()}
    profiles = {profile["agent_id"]: profile for profile in list_agent_profiles()}

    rows: List[Dict[str, Any]] = []
    active_agent_ids = set(report_values.keys()) | set(heartbeat_values.keys())
    for agent_id in active_agent_ids:
        report_item = report_values.get(agent_id)
        heartbeat_item = heartbeat_values.get(agent_id)
        agent_profile = profiles.get(str(agent_id), {})
        task_context = build_agent_task_context(agent_profile)

        alert_snapshot = build_agent_runtime_snapshot(agent_id)
        result_snapshot = build_result_snapshot(agent_profile, report_item, now_ts=now_ts)
        supervision_snapshot = build_supervision_snapshot(
            agent_profile,
            heartbeat_item,
            now_ts=now_ts,
        )
        heartbeat_snapshot = build_heartbeat_snapshot(heartbeat_item, now_ts=now_ts)

        region = str(
            (report_item or {}).get("region")
            or task_context.get("region")
            or agent_profile.get("region")
            or ""
        ).strip()
        region_number = extract_region_number(region)
        progress_group = heartbeat_snapshot["status_group"] or result_snapshot["current_group"]
        progress_role_index = (
            heartbeat_snapshot["status_role_index"] or result_snapshot["role_index"]
        )
        rows.append(
            {
                "event": str((report_item or {}).get("event", "") or "-"),
                "agent_id": agent_id,
                "region": region,
                "region_number": region_number,
                "current_group": result_snapshot["current_group"],
                "finished_group": result_snapshot["finished_group"],
                "next_group": result_snapshot["next_group"],
                "role_index": result_snapshot["role_index"],
                "client_ts": (report_item or {}).get("client_ts", ""),
                "server_time": (report_item or {}).get("server_time", ""),
                "elapsed": alert_snapshot["elapsed"],
                "stale": alert_snapshot["stale"],
                "completed": alert_snapshot["completed"],
                "target_group_end": alert_snapshot["target_group_end"],
                "complete_role_index": alert_snapshot["complete_role_index"],
                "completion_basis": alert_snapshot["completion_basis"],
                "supervision_state": supervision_snapshot["state_label"],
                "supervision_code": supervision_snapshot["state_code"],
                "supervision_detail": supervision_snapshot["detail"],
                "supervision_heartbeat_elapsed": supervision_snapshot["heartbeat_elapsed"],
                "action_text": supervision_snapshot["action_text"],
                "result_state": result_snapshot["state_label"],
                "result_code": result_snapshot["state_code"],
                "result_detail": result_snapshot["detail"],
                "result_elapsed": result_snapshot["elapsed"],
                "result_server_time": result_snapshot["server_time"],
                "progress_group": progress_group,
                "progress_role_index": progress_role_index,
                "status_date": heartbeat_snapshot["status_date"],
                "status_exists": heartbeat_snapshot["status_exists"],
                "process_exists": heartbeat_snapshot["process_exists"],
                "process_pid": heartbeat_snapshot["process_pid"],
                "heartbeat_at": heartbeat_snapshot["server_time"],
                "heartbeat_elapsed": heartbeat_snapshot["heartbeat_elapsed"],
                "last_progress_change_at": heartbeat_snapshot["last_progress_change_at"],
                "last_restart_at": heartbeat_snapshot["last_restart_at"],
                "restart_count_today": heartbeat_snapshot["restart_count_today"],
                "assist_active": bool(task_context.get("assist", {}).get("active", False)),
                "assist_role": str(task_context.get("assist", {}).get("role", "") or ""),
                "assist_summary": str(task_context.get("assist", {}).get("summary", "") or ""),
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
                "supervision_issue_count": 0,
                "running_count": 0,
                "waiting_count": 0,
                "result_stale_count": 0,
                "completed_count": 0,
                "rows": [],
            }
            groups.append(group)

        group["rows"].append(row)
        group["count"] += 1
        if row.get("supervision_code") in SUPERVISION_ISSUE_CODES:
            group["supervision_issue_count"] += 1
        if row.get("supervision_code") == "running":
            group["running_count"] += 1
        if row.get("supervision_code") == "waiting_schedule":
            group["waiting_count"] += 1
        if row.get("result_code") == "stale":
            group["result_stale_count"] += 1
        if row.get("result_code") == "completed":
            group["completed_count"] += 1

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
        f"[{item['agent_id']} \u4e0a\u62a5\u8d85\u65f6\u544a\u8b66]\n"
        f"- \u533a\u670d: `{item['region']}`\n"
        f"- \u5f53\u524d\u6267\u884c\u7ec4: `{item['current_group']}`\n"
        f"- \u5f53\u524d\u89d2\u8272\u7d22\u5f15: `{item['role_index']}`\n"
        f"- \u6700\u540e\u4e0a\u62a5\u65f6\u95f4: `{item['server_time']}`\n"
        f"- \u8ddd\u4eca\u79d2\u6570: `{elapsed}`\n"
    )

def build_recover_markdown(item: Dict[str, Any], elapsed: int) -> str:
    return (
        f"[{item['agent_id']} \u5df2\u6062\u590d\u4e0a\u62a5]\n"
        f"- \u533a\u670d: `{item['region']}`\n"
        f"- \u5f53\u524d\u6267\u884c\u7ec4: `{item['current_group']}`\n"
        f"- \u5f53\u524d\u89d2\u8272\u7d22\u5f15: `{item['role_index']}`\n"
        f"- \u6700\u65b0\u4e0a\u62a5\u65f6\u95f4: `{item['server_time']}`\n"
        f"- \u4e0a\u6b21\u8d85\u65f6\u79d2\u6570: `{elapsed}`\n"
    )

def build_completed_markdown(item: Dict[str, Any]) -> str:
    return (
        f"[{item['agent_id']} \u5df2\u5b8c\u6210\u9884\u5b9a\u4efb\u52a1]\n"
        f"- \u533a\u670d: `{item['region']}`\n"
        f"- \u5f53\u524d\u6267\u884c\u7ec4: `{item['current_group']}` / \u76ee\u6807\u7ed3\u675f\u7ec4: `{item['target_group_end']}`\n"
        f"- \u5f53\u524d\u89d2\u8272\u7d22\u5f15: `{item['role_index']}` / \u5b8c\u6210\u9608\u503c: `{item['complete_role_index']}`\n"
        f"- \u6700\u65b0\u4e0a\u62a5\u65f6\u95f4: `{item['server_time']}`\n"
    )

async def maybe_send_completed_notice(agent_id: str, report: Dict[str, Any]) -> None:
    agent_profile = get_agent_profile(agent_id)
    row = {
        **report,
        "elapsed": 0,
        "region_number": extract_region_number(report.get("region", "")),
    }
    completion_state = get_completion_state(agent_profile, report)
    row.update(
        {
            "stale": False,
            "completed": completion_state["completed"],
            "target_group_end": completion_state["target_group_end"],
            "complete_role_index": completion_state["complete_role_index"],
            "completion_basis": completion_state["completion_basis"],
        }
    )

    if not row["completed"]:
        return

    if not completed_notice_sent.get(agent_id, False):
        ok = await post_wecom_markdown(build_completed_markdown(row))
        if ok:
            completed_notice_sent[agent_id] = True
            logger.info("completed alert sent immediately: agent=%s", agent_id)

    completed_state[agent_id] = True
    stale_state[agent_id] = False
    alert_stale_started_at.pop(agent_id, None)
    alert_sent_count.pop(agent_id, None)
    last_alert_sent_at.pop(agent_id, None)


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


def should_alert_for_result_stale(
    result_stale: bool,
    supervision_code: str,
) -> bool:
    if not result_stale:
        return False
    return str(supervision_code or "") not in SUPERVISION_STALE_SUPPRESS_CODES


async def check_alerts_once() -> None:
    ensure_runtime_state_for_today()
    if not settings.alert_enabled:
        return

    now_ts = time.time()
    rows = build_rows()
    for row in rows:
        agent_id = row["agent_id"]
        elapsed = row["elapsed"]
        result_stale = bool(row.get("result_code") == "stale")
        alert_stale = bool(row.get("stale", False))
        is_completed = bool(row.get("completed", False))
        prev_stale = stale_state.get(agent_id, False)
        prev_completed = completed_state.get(agent_id, False)

        if is_completed:
            if not completed_notice_sent.get(agent_id, False):
                ok = await post_wecom_markdown(build_completed_markdown(row))
                if ok:
                    completed_notice_sent[agent_id] = True
                    logger.info("completed alert sent: agent=%s", agent_id)
            completed_state[agent_id] = True
            stale_state[agent_id] = False
            alert_stale_started_at.pop(agent_id, None)
            alert_sent_count.pop(agent_id, None)
            last_alert_sent_at.pop(agent_id, None)
            continue

        if prev_completed:
            completed_state[agent_id] = False

        if alert_stale:
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
            continue

        if result_stale:
            continue

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
            completed_state.pop(key, None)
            completed_notice_sent.pop(key, None)
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
    summary = build_dashboard_summary(rows)
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
            "summary": summary,
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
            "resources_console_url": append_query_params(
                "/console/resources", auth_token=auth_token
            ),
            "agent_profile_count": len(agent_profiles),
            "resource_item_count": len(resource_items),
        },
    )


@app.get("/console/resources")
async def console_resources(
    request: Request,
    auth_token: Optional[str] = Query(default=None),
    edit_resource_id: int = Query(default=0),
    message: str = Query(default=""),
) -> HTMLResponse:
    ensure_auth(None, auth_token)
    resource_items = list_resource_items()
    selected_resource = get_resource_item(edit_resource_id) or blank_resource_item()
    return templates.TemplateResponse(
        "resources_console.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "auth_token": auth_token or "",
            "auth_query_suffix": append_query_params("", auth_token=auth_token),
            "message": message,
            "resource_items": resource_items,
            "selected_resource": selected_resource,
            "dashboard_url": append_query_params("/", auth_token=auth_token),
            "main_console_url": append_query_params("/console", auth_token=auth_token),
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

    original_agent_id = str(form.get("original_agent_id", "")).strip() or None
    existing_agent = (
        get_agent_profile(original_agent_id or agent_id) or blank_agent_profile()
    )

    try:
        config_payload_text = build_config_payload_text(
            form,
            str(
                form.get(
                    "config_payload_original",
                    existing_agent.get(
                        "config_payload_original",
                        existing_agent.get("config_payload", ""),
                    ),
                )
            ),
        )
    except ValueError as exc:
        return RedirectResponse(
            build_console_redirect_url(
                auth_token,
                str(exc),
                edit_agent=original_agent_id or agent_id,
            ),
            status_code=303,
        )

    profile = {
        "agent_id": agent_id,
        "enabled": form.get("enabled") == "on",
        "region": str(form.get("region", existing_agent.get("region", ""))).strip(),
        "group_start": parse_int(
            form.get("group_start", existing_agent.get("group_start", 0)), 0
        ),
        "group_end": parse_int(
            form.get("group_end", existing_agent.get("group_end", 0)), 0
        ),
        "task_mode": str(
            form.get("task_mode", existing_agent.get("task_mode", "normal"))
        ).strip()
        or "normal",
        "priority": parse_int(
            form.get("priority", existing_agent.get("priority", 0)), 0
        ),
        "profile_version": str(
            form.get("profile_version", existing_agent.get("profile_version", ""))
        ).strip(),
        "config_version": str(
            form.get("config_version", existing_agent.get("config_version", ""))
        ).strip(),
        "config_payload": config_payload_text,
        "exe_version": str(
            form.get("exe_version", existing_agent.get("exe_version", ""))
        ).strip(),
        "exe_url": str(form.get("exe_url", existing_agent.get("exe_url", ""))).strip(),
        "exe_sha256": str(
            form.get("exe_sha256", existing_agent.get("exe_sha256", ""))
        ).strip(),
        "startup_exe": str(
            form.get("startup_exe", existing_agent.get("startup_exe", "QianNian.exe"))
        ).strip()
        or "QianNian.exe",
        "startup_args": str(
            form.get("startup_args", existing_agent.get("startup_args", ""))
        ).strip(),
        "script_entry": str(
            form.get("script_entry", existing_agent.get("script_entry", ""))
        ).strip(),
        "resource_manifest_version": str(
            form.get(
                "resource_manifest_version",
                existing_agent.get("resource_manifest_version", ""),
            )
        ).strip(),
        "notes": str(form.get("notes", existing_agent.get("notes", ""))).strip(),
        "desired_run_state": normalize_desired_run_state(
            form.get(
                "desired_run_state", existing_agent.get("desired_run_state", "run")
            )
        ),
        "schedule_daily_start": normalize_daily_start(
            form.get(
                "schedule_daily_start", existing_agent.get("schedule_daily_start", "")
            )
        ),
        "auto_restart_on_stale": form.get("auto_restart_on_stale") == "on",
        "restart_cooldown_seconds": max(
            0,
            parse_int(
                form.get(
                    "restart_cooldown_seconds",
                    existing_agent.get("restart_cooldown_seconds", 600),
                ),
                600,
            ),
        ),
        "max_restart_per_day": max(
            0,
            parse_int(
                form.get(
                    "max_restart_per_day",
                    existing_agent.get("max_restart_per_day", 3),
                ),
                3,
            ),
        ),
        "startup_grace_seconds": max(
            0,
            parse_int(
                form.get(
                    "startup_grace_seconds",
                    existing_agent.get("startup_grace_seconds", 300),
                ),
                300,
            ),
        ),
        "desired_action": normalize_desired_action(
            form.get("desired_action", existing_agent.get("desired_action", ""))
        ),
        "action_seq": max(
            0,
            parse_int(form.get("action_seq", existing_agent.get("action_seq", 0)), 0),
        ),
    }

    upsert_agent_profile(profile, original_agent_id)
    return RedirectResponse(
        build_console_redirect_url(
            auth_token,
            f"{agent_id} 已保存配置",
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
            build_console_redirect_url(auth_token, "请选择有效的 Agent 和动作"),
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
            f"{agent_id} 动作已下发: {action} (seq={action_seq})",
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
        build_console_redirect_url(auth_token, f"{agent_id or 'Agent'} 已删除"),
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
            build_console_redirect_url(
                auth_token,
                "资源名称不能为空",
                console_path="/console/resources",
            ),
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
            f"{name} 已保存",
            edit_resource_id=resource_id,
            console_path="/console/resources",
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
        build_console_redirect_url(
            auth_token,
            f"{resource_name} 已删除",
            console_path="/console/resources",
        ),
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

    task_context = build_agent_task_context(agent_profile)
    with state_lock:
        heartbeat_item = dict(heartbeat_states.get(agent_profile["agent_id"], {}))
        report_item = dict(agent_states.get(agent_profile["agent_id"], {}))

    return {
        "ok": True,
        "server_time": now_str(),
        "agent_id": agent_profile["agent_id"],
        "profile_version": agent_profile["profile_version"],
        "task": {
            "enabled": task_context["enabled"],
            "region": task_context["region"],
            "group_start": task_context["group_start"],
            "group_end": task_context["group_end"],
            "profile_group_start": task_context["profile_group_start"],
            "profile_group_end": task_context["profile_group_end"],
            "task_mode": task_context["task_mode"],
            "priority": task_context["priority"],
            "notes": task_context["notes"],
            "assist": task_context["assist"],
        },
        "assist": task_context["assist"],
        "control": build_agent_control(agent_profile),
        "runtime": build_agent_runtime_snapshot(agent_profile["agent_id"]),
        "heartbeat": build_heartbeat_snapshot(heartbeat_item),
        "supervision": build_supervision_snapshot(agent_profile, heartbeat_item),
        "result": build_result_snapshot(agent_profile, report_item),
        "updated_at": agent_profile["updated_at"],
    }


@app.post("/api/agent/assist/assign")
async def api_agent_assist_assign(
    payload: AssistAssignPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    try:
        assist_row = upsert_assist_override(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target_profile = get_agent_profile(str(assist_row.get("target_agent_id", "") or ""))
    helper_profile = get_agent_profile(str(assist_row.get("helper_agent_id", "") or ""))
    target_task = build_agent_task_context(target_profile)
    helper_task = build_agent_task_context(helper_profile)
    assist_view = build_assist_view(assist_row)
    return {
        "ok": True,
        "server_time": now_str(),
        "assist": assist_view,
        "target_effective_group_end": max(
            0, parse_int(target_task.get("group_end"), 0)
        ),
        "target_task": target_task,
        "helper_task": helper_task,
    }


@app.post("/api/agent/assist/clear")
async def api_agent_assist_clear(
    payload: AssistClearPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    removed = clear_assist_override(
        helper_agent_id=payload.helper_agent_id,
        target_agent_id=payload.target_agent_id,
    )
    return {
        "ok": True,
        "server_time": now_str(),
        "removed": removed,
        "target_agent_id": str(payload.target_agent_id or "").strip(),
        "helper_agent_id": str(payload.helper_agent_id or "").strip(),
    }


@app.post("/api/agent/heartbeat")
async def api_agent_heartbeat(
    payload: AgentHeartbeatPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    ensure_runtime_state_for_today()
    server_time = now_str()
    server_epoch = time.time()
    heartbeat = {
        "agent_id": payload.agent_id,
        "heartbeat_at": payload.heartbeat_at,
        "intent": str(payload.intent or "none").strip() or "none",
        "intent_reason": str(payload.intent_reason or "").strip(),
        "intent_at": payload.intent_at,
        "process_exists": bool(payload.process_exists),
        "process_pid": max(0, parse_int(payload.process_pid, 0)),
        "status_exists": bool(payload.status_exists),
        "status_group": max(0, parse_int(payload.status_group, 0)),
        "status_role_index": max(0, parse_int(payload.status_role_index, 0)),
        "status_date": str(payload.status_date or "").strip(),
        "status_mtime_epoch": float(payload.status_mtime_epoch or 0),
        "last_progress_change_at": str(payload.last_progress_change_at or "").strip(),
        "last_restart_at": str(payload.last_restart_at or "").strip(),
        "restart_count_today": max(0, parse_int(payload.restart_count_today, 0)),
        "server_time": server_time,
        "server_epoch": server_epoch,
    }
    with state_lock:
        heartbeat_states[payload.agent_id] = heartbeat
        report_item = dict(agent_states.get(payload.agent_id, {}))
    agent_profile = get_agent_profile(payload.agent_id)
    return {
        "ok": True,
        "server_time": server_time,
        "heartbeat": build_heartbeat_snapshot(heartbeat, now_ts=server_epoch),
        "supervision": build_supervision_snapshot(
            agent_profile,
            heartbeat,
            now_ts=server_epoch,
        ),
        "result": build_result_snapshot(agent_profile, report_item, now_ts=server_epoch),
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
    ensure_runtime_state_for_today()
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
    await maybe_send_completed_notice(payload.agent_id, report)
    logger.info(
        "report received: agent=%s region=%s group=%s role=%s",
        payload.agent_id,
        payload.region,
        current_group,
        payload.role_index,
    )
    return {"ok": True, "server_time": server_time}


@app.post("/api/agent/recovering")
async def api_agent_recovering(
    payload: RecoveryPayload,
    x_auth_token: Optional[str] = Header(default=None),
    auth_token: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    ensure_auth(x_auth_token, auth_token)
    ensure_runtime_state_for_today()
    server_time = now_str()
    now_ts = time.time()
    hold_seconds = max(
        settings.alert_timeout_seconds * 2,
        max(30, parse_int(payload.hold_seconds, 0)),
    )
    synthetic_epoch = now_ts + hold_seconds

    with state_lock:
        existing = dict(agent_states.get(payload.agent_id, {}))
        region = payload.region or str(existing.get("region", ""))
        current_group = payload.current_group or parse_int(
            existing.get("current_group"), 0
        )
        finished_group = payload.finished_group or parse_int(
            existing.get("finished_group"), 0
        )
        next_group = payload.next_group or parse_int(existing.get("next_group"), 0)
        role_index = (
            payload.role_index
            if payload.role_index is not None
            else parse_int(existing.get("role_index"), 0)
        )
        report = {
            "event": f"recovering:{payload.reason or 'restart'}",
            "agent_id": payload.agent_id,
            "region": region,
            "current_group": current_group,
            "finished_group": finished_group,
            "next_group": next_group,
            "role_index": role_index,
            "client_ts": payload.ts,
            "server_time": server_time,
            "server_epoch": synthetic_epoch,
        }
        agent_states[payload.agent_id] = report
        stale_state[payload.agent_id] = False
        completed_state[payload.agent_id] = False
        completed_notice_sent.pop(payload.agent_id, None)
        last_alert_sent_at.pop(payload.agent_id, None)
        alert_stale_started_at.pop(payload.agent_id, None)
        alert_sent_count.pop(payload.agent_id, None)
        history_cache.appendleft(
            {
                "event": report["event"],
                "agent_id": payload.agent_id,
                "region": region,
                "current_group": current_group,
                "finished_group": finished_group,
                "next_group": next_group,
                "role_index": role_index,
                "client_ts": payload.ts,
                "server_time": server_time,
                "created_at": int(now_ts),
            }
        )

    logger.info(
        "agent recovering: agent=%s reason=%s hold=%s group=%s role=%s",
        payload.agent_id,
        payload.reason,
        hold_seconds,
        current_group,
        role_index,
    )
    return {
        "ok": True,
        "server_time": server_time,
        "hold_seconds": hold_seconds,
        "status": "recovering",
    }


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
        if payload.agent_id in heartbeat_states:
            heartbeat_states.pop(payload.agent_id, None)
            removed = True
        stale_state.pop(payload.agent_id, None)
        completed_state.pop(payload.agent_id, None)
        completed_notice_sent.pop(payload.agent_id, None)
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
        agent_count = len(set(agent_states.keys()) | set(heartbeat_states.keys()))
        agent_states.clear()
        heartbeat_states.clear()
        stale_state.clear()
        completed_state.clear()
        completed_notice_sent.clear()
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
        app,
        host=settings.listen_host,
        port=settings.listen_port,
        reload=False,
    )
