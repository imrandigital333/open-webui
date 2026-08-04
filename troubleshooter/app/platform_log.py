"""Platform activity logging.

A single rotating log file captures detailed, structured activity for every
functionality of the platform — API calls (method, path, status, duration,
actor), semantic audit events (discovery, knowledge ingest, change plans, user
management…) and any internal warnings/errors bubbling up through Python's
logging. Records are written as JSON lines so the Logs page can filter them the
way enterprise tools do (by level, category, actor, free text and time).

Rotation (size- or time-based), the log file path, backup count and level are
all configurable at runtime from Settings → Logs and persisted to a
chmod-600, gitignored logging.yaml.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.handlers
import os
import threading
from pathlib import Path

import yaml

from .inventory import BASE_DIR

CONFIG_PATH = BASE_DIR / "logging.yaml"
DEFAULT_LOG = BASE_DIR / "data" / "logs" / "platform.log"
LOGGER_NAME = "troubleshooter"

_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_LEVEL_RANK = {name: i for i, name in enumerate(_LEVELS)}

# categories surfaced in the Logs filter (functionality areas of the platform)
CATEGORIES = [
    "auth", "access", "investigation", "knowledge", "discovery", "changes",
    "integrations", "inventory", "itsm", "settings", "system", "api", "error",
]

_lock = threading.RLock()
_handler: logging.Handler | None = None
_logger = logging.getLogger(LOGGER_NAME)


def _defaults() -> dict:
    return {"level": "INFO", "strategy": "size", "max_mb": 10, "backup_count": 5,
            "when": "midnight", "interval": 1, "path": str(DEFAULT_LOG),
            "capture_framework": True}


def load_config() -> dict:
    cfg = _defaults()
    try:
        if CONFIG_PATH.exists():
            data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            if isinstance(data, dict):
                for k in cfg:
                    if k in data and data[k] is not None:
                        cfg[k] = data[k]
    except (OSError, yaml.YAMLError):
        pass
    cfg["level"] = str(cfg["level"]).upper()
    if cfg["level"] not in _LEVEL_RANK:
        cfg["level"] = "INFO"
    if cfg["strategy"] not in ("size", "time"):
        cfg["strategy"] = "size"
    try:
        cfg["max_mb"] = max(1, int(cfg["max_mb"]))
        cfg["backup_count"] = max(0, min(100, int(cfg["backup_count"])))
        cfg["interval"] = max(1, int(cfg["interval"]))
    except (TypeError, ValueError):
        cfg.update(max_mb=10, backup_count=5, interval=1)
    return cfg


def _save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(yaml.safe_dump(cfg, sort_keys=False))
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


class _JsonFormatter(logging.Formatter):
    """One JSON object per line, with the fields the Logs page filters on."""

    def format(self, record: logging.LogRecord) -> str:
        cat = getattr(record, "category", None) or record.name.split(".")[-1]
        obj = {
            "ts": record.created,
            "level": record.levelname,
            "category": cat,
            "actor": getattr(record, "actor", "") or "",
            "msg": record.getMessage(),
        }
        detail = getattr(record, "detail", None)
        if detail:
            obj["detail"] = detail
        if record.exc_info:
            obj["msg"] += "\n" + self.formatException(record.exc_info)
        return json.dumps(obj, default=str, ensure_ascii=False)


def _build_handler(cfg: dict) -> logging.Handler:
    path = Path(cfg["path"]).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if cfg["strategy"] == "time":
        h = logging.handlers.TimedRotatingFileHandler(
            path, when=cfg.get("when", "midnight"),
            interval=cfg["interval"], backupCount=cfg["backup_count"],
            encoding="utf-8", utc=False)
    else:
        h = logging.handlers.RotatingFileHandler(
            path, maxBytes=cfg["max_mb"] * 1024 * 1024,
            backupCount=cfg["backup_count"], encoding="utf-8")
    h.setFormatter(_JsonFormatter())
    return h


def configure(cfg: dict | None = None) -> dict:
    """(Re)install the rotating file handler from config. Idempotent."""
    global _handler
    with _lock:
        cfg = cfg or load_config()
        level = _LEVEL_RANK[cfg["level"]]
        try:
            new = _build_handler(cfg)
        except OSError as exc:  # e.g. bad path — fall back to the default file
            fallback = _defaults()
            fallback["path"] = str(DEFAULT_LOG)
            new = _build_handler(fallback)
            new.setLevel(logging.getLevelName(cfg["level"]))
            cfg = fallback
            _install(new, cfg)
            _logger.warning("log path unusable (%s); using default", exc,
                            extra={"category": "system"})
            return cfg
        new.setLevel(logging.getLevelName(cfg["level"]))
        _install(new, cfg)
        return cfg


def _install(new: logging.Handler, cfg: dict) -> None:
    global _handler
    # app logger
    if _handler is not None:
        _logger.removeHandler(_handler)
        with contextlib.suppress(Exception):
            _handler.close()
    _logger.setLevel(logging.getLevelName(cfg["level"]))
    _logger.addHandler(new)
    _logger.propagate = False
    # optionally capture framework/root logging (uvicorn, libraries)
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_troubleshooter", False):
            root.removeHandler(h)
            with contextlib.suppress(Exception):
                h.close()
    if cfg.get("capture_framework", True):
        fw = _build_handler(cfg)
        fw.setLevel(logging.WARNING)          # only warnings+ from the framework
        fw._troubleshooter = True             # type: ignore[attr-defined]
        root.addHandler(fw)
    _handler = new


def _ensure() -> None:
    if _handler is None:
        configure()


def event(category: str, msg: str, *, level: str = "INFO",
          actor: str = "", detail: dict | None = None) -> None:
    """Emit a structured platform log record."""
    _ensure()
    lvl = getattr(logging, str(level).upper(), logging.INFO)
    _logger.log(lvl, msg, extra={"category": category or "system",
                                 "actor": actor or "", "detail": detail or None})


# ---------- reading / filtering ----------

def _current_path() -> Path:
    return Path(load_config()["path"]).expanduser()


def list_files() -> list[dict]:
    """Current log file + its rotated backups, newest first."""
    p = _current_path()
    out = []
    if p.exists():
        out.append({"name": p.name, "size": p.stat().st_size, "current": True})
    if p.parent.exists():
        for f in sorted(p.parent.glob(p.name + ".*")):
            try:
                out.append({"name": f.name, "size": f.stat().st_size, "current": False})
            except OSError:
                pass
    return out


def read(level: str = "", category: str = "", q: str = "",
         since: float = 0.0, limit: int = 500, file: str = "") -> list[dict]:
    """Return matching log entries, newest first."""
    p = _current_path()
    target = p if not file else (p.parent / file)
    # guard against path traversal — only files in the log directory
    try:
        target = target.resolve()
        if target.parent != p.parent.resolve() or not target.exists():
            return []
    except OSError:
        return []
    min_rank = _LEVEL_RANK.get((level or "").upper(), 0)
    cat = (category or "").strip().lower()
    ql = (q or "").strip().lower()
    entries: list[dict] = []
    try:
        with target.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    e = {"ts": 0, "level": "INFO", "category": "raw", "actor": "",
                         "msg": line}
                if _LEVEL_RANK.get(str(e.get("level", "INFO")).upper(), 1) < min_rank:
                    continue
                if cat and str(e.get("category", "")).lower() != cat:
                    continue
                if since and float(e.get("ts") or 0) < since:
                    continue
                if ql:
                    blob = (str(e.get("msg", "")) + " " + str(e.get("actor", "")) + " "
                            + json.dumps(e.get("detail", ""), default=str)).lower()
                    if ql not in blob:
                        continue
                entries.append(e)
    except OSError:
        return []
    entries.reverse()
    return entries[:max(1, min(limit, 5000))]


def meta() -> dict:
    cfg = load_config()
    files = list_files()
    return {"config": cfg, "path": cfg["path"], "categories": CATEGORIES,
            "levels": _LEVELS, "files": files,
            "total_size": sum(f["size"] for f in files)}


# ---------- admin actions ----------

def save_config(new: dict) -> dict:
    cfg = load_config()
    for k in ("level", "strategy", "when"):
        if k in new and new[k]:
            cfg[k] = str(new[k])
    for k in ("max_mb", "backup_count", "interval"):
        if k in new and new[k] is not None:
            with contextlib.suppress(TypeError, ValueError):
                cfg[k] = int(new[k])
    if "capture_framework" in new:
        cfg["capture_framework"] = bool(new["capture_framework"])
    if new.get("path"):
        cfg["path"] = str(new["path"]).strip()
    # normalise
    cfg["level"] = str(cfg["level"]).upper()
    if cfg["level"] not in _LEVEL_RANK:
        cfg["level"] = "INFO"
    if cfg["strategy"] not in ("size", "time"):
        cfg["strategy"] = "size"
    cfg["max_mb"] = max(1, int(cfg["max_mb"]))
    cfg["backup_count"] = max(0, min(100, int(cfg["backup_count"])))
    cfg["interval"] = max(1, int(cfg["interval"]))
    _save_config(cfg)
    cfg = configure(cfg)
    event("settings", "logging configuration updated",
          detail={"strategy": cfg["strategy"], "level": cfg["level"],
                  "max_mb": cfg["max_mb"], "backup_count": cfg["backup_count"]})
    return cfg


def rotate_now() -> dict:
    _ensure()
    with _lock:
        if isinstance(_handler, logging.handlers.BaseRotatingHandler):
            _handler.doRollover()
    event("system", "log file rotated manually")
    return meta()


def clear() -> dict:
    p = _current_path()
    try:
        p.write_text("")
    except OSError:
        pass
    event("system", "current log file cleared")
    return meta()


def current_file_path() -> Path:
    return _current_path()
