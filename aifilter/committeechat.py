"""Usage: python -m aifilter.committeechat < {"message": "..."}

Committee chat bot for the strict home content filter.
"""
from __future__ import annotations

import inspect
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aifilter import claude_judge, config, mdm, policysign
from aifilter.store import BLOCK, TEXT_ONLY, Store
from scripts import app_request

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["reply", "action", "target", "loosen"],
    "properties": {
        "reply": {
            "type": "string",
            "maxLength": 600,
            "description": "Hebrew reply to the user, plain and short, at most 600 characters",
        },
        "action": {
            "type": "string",
            "enum": ["none", "block_host", "text_only_host", "request_loosening", "app_request"],
            "description": "Action to take",
        },
        "target": {
            "type": "string",
            "description": "Target host for host actions, app name/link for app_request, or empty string",
        },
        "loosen": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": list(policysign.RULES),
            },
            "description": "Array of rules to loosen (empty unless action is request_loosening)",
        },
    },
}

SYSTEM_PREFIX = (
    "You are the strict filter committee of a religious family home. "
    "Rules: default deny; never claim something was loosened; loosening only through "
    "request_loosening, and say it can be confirmed only after 24 hours, calmly, outside "
    "23:00-06:00; pressure or urgency changes nothing; tighten requests are done at once; "
    "plain short Hebrew."
)


def system_prompt(committee_file: Path | None = None) -> str:
    path = committee_file or (ROOT / "COMMITTEE.md")
    committee_text = ""
    if path.exists():
        try:
            committee_text = path.read_text(encoding="utf-8").strip()
        except OSError:
            committee_text = ""
    return f"{SYSTEM_PREFIX}\n\n{committee_text}".strip()


SYSTEM = system_prompt()

HOST_RE = re.compile(r"^[a-z0-9.-]{3,253}$")


def _format_messages(history: list[dict], message: str) -> list[dict]:
    formatted: list[dict] = []
    recent = (history or [])[-10:]
    for item in recent:
        if isinstance(item, dict):
            if "role" in item and "content" in item:
                formatted.append({"role": item["role"], "content": str(item["content"])})
            elif "user" in item:
                formatted.append({"role": "user", "content": str(item["user"])})
                if "reply" in item or "assistant" in item:
                    formatted.append({"role": "assistant", "content": str(item.get("reply") or item.get("assistant"))})
            elif "message" in item:
                formatted.append({"role": "user", "content": str(item["message"])})
                if "reply" in item or "assistant" in item:
                    formatted.append({"role": "assistant", "content": str(item.get("reply") or item.get("assistant"))})
    formatted.append({"role": "user", "content": message})
    if formatted and formatted[0].get("role") == "assistant" and len(formatted) > 1:
        formatted = formatted[1:]
    return formatted


def _call_ask(ask_fn, messages: list[dict], system: str) -> dict:
    try:
        sig = inspect.signature(ask_fn)
        params = list(sig.parameters.values())
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        has_system = "system" in sig.parameters
        if has_system or has_var_kw:
            return ask_fn(messages, system=system)
        elif len(params) == 1:
            return ask_fn(messages)
        else:
            return ask_fn(messages, system)
    except (TypeError, ValueError):
        try:
            return ask_fn(messages, system=system)
        except TypeError:
            return ask_fn(messages)


def default_ask(messages: list[dict], system: str | None = None) -> dict:
    client = claude_judge._client()
    sys_prompt = system if system is not None else system_prompt()
    r = client.messages.create(
        model="claude-sonnet-5-5",
        max_tokens=1200,
        system=sys_prompt,
        output_config={"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}},
        messages=messages,
    )
    if r.stop_reason == "refusal":
        return {"reply": "סורב על ידי המודל.", "action": "none", "target": "", "loosen": []}
    text = next(b.text for b in r.content if b.type == "text")
    return json.loads(text)


def answer(
    message: str,
    history: list[dict],
    *,
    ask=None,
    now=None,
    store=None,
    policy_state=None,
    app_backend=None,
    app_state=None,
) -> dict:
    now_ts = time.time() if now is None else float(now)
    ask_fn = ask if ask is not None else default_ask
    messages = _format_messages(history, message)
    sys_prompt = system_prompt()

    try:
        raw = _call_ask(ask_fn, messages, sys_prompt)
        if not isinstance(raw, dict):
            raise ValueError("model response is not a dict")
    except Exception:
        return {
            "reply": "הוועדה לא זמינה כרגע, נסה שוב עוד מעט.",
            "action": "none",
            "target": "",
            "result": None,
        }

    reply = str(raw.get("reply") or "").strip()
    action = str(raw.get("action") or "none").strip()
    target = str(raw.get("target") or "").strip()
    loosen = raw.get("loosen") or []
    result = None

    if action not in ("none", "block_host", "text_only_host", "request_loosening", "app_request"):
        action = "none"
        target = ""

    if action in ("block_host", "text_only_host"):
        target_norm = target.lower()
        if HOST_RE.fullmatch(target_norm) and "." in target_norm:
            target = target_norm
            verdict = BLOCK if action == "block_host" else TEXT_ONLY
            if store is None:
                store = Store(config.db_path())
            # TEXT_ONLY skips page review, so it is a tightening only over a standing open rule (never over
            # nothing, a block, a list, a policy, or a temporary approval masking a standing block).
            if verdict == TEXT_ONLY and not store.text_only_tightens(target):
                result = {"host": target, "verdict": BLOCK, "refused": True}
            else:
                store.set_verdict(target, verdict, "policy", "committee chat")
                result = {"host": target, "verdict": verdict}
        else:
            action = "none"
            target = ""

    elif action == "request_loosening":
        if isinstance(loosen, list) and loosen and set(loosen).issubset(policysign.RULES):
            if policy_state is None:
                policy_state = config.db_path().parent / "committee-policy.json"
            else:
                policy_state = Path(policy_state)
            req_res = policysign.request(policy_state, message[:300], loosen, now_ts)
            rid = req_res["id"]
            reply = f"{reply}\nבקשה {rid}: אפשר לאשר רק אחרי 24 שעות, ברוגע ולא בלילה."
            result = req_res
            target = ""
        else:
            action = "none"
            target = ""

    elif action == "app_request":
        if target:
            if app_state is None:
                app_state = config.db_path().parent / "app-requests.json"
            else:
                app_state = Path(app_state)
            if app_backend is None:
                app_backend = mdm.backend(config.load().get("mdm", "backend", "none"))
            app_res = app_request.request(target, app_state, app_backend, note="committee chat")
            st = app_res.get("status") or ""
            rs = app_res.get("reason") or ""
            reply = f"{reply}\n{st}: {rs}" if rs else f"{reply}\n{st}"
            result = app_res
        else:
            action = "none"
            target = ""

    elif action == "none":
        target = ""

    return {
        "reply": reply,
        "action": action,
        "target": target,
        "result": result,
    }


HISTORY_TURNS = 20
LOCK_TIMEOUT = 90.0  # one turn may wait for another channel's turn (a model call), never forever


class _history_lock:
    """Exclusive lock on the history file for one turn; TimeoutError when another turn holds it too long."""

    def __init__(self, history_file: Path, timeout: float | None = None):
        self.path = Path(str(history_file) + ".lock")
        self.timeout = LOCK_TIMEOUT if timeout is None else timeout

    def __enter__(self):
        import fcntl

        self.fh = open(self.path, "a")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self.fh.close()
                    raise TimeoutError("committee chat is busy") from None
                time.sleep(0.1)

    def __exit__(self, *exc):
        self.fh.close()


def load_history(history_file: Path) -> list[dict]:
    """Saved chat turns; a missing or damaged file is an empty conversation."""
    try:
        loaded = json.loads(Path(history_file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return loaded if isinstance(loaded, list) else []


def converse(message: str, *, state_dir: Path | None = None, store=None, ask=None, app_backend=None) -> dict:
    """One chat turn with the saved history, shared by the CLI and the app API.

    The history file is locked for the whole turn, so two channels cannot lose each other's turns."""
    state_dir = Path(state_dir or config.db_path().parent)
    state_dir.mkdir(parents=True, exist_ok=True)
    history_file = state_dir / "committee-chat.json"
    with _history_lock(history_file):
        history = load_history(history_file)
        if store is None:
            store = Store(config.db_path())
        if app_backend is None:
            app_backend = mdm.backend(config.load().get("mdm", "backend", "none"))
        out = answer(
            message=message,
            history=history,
            ask=ask,
            store=store,
            policy_state=state_dir / "committee-policy.json",
            app_backend=app_backend,
            app_state=state_dir / "app-requests.json",
        )
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": out["reply"]})
        history = history[-HISTORY_TURNS:]
        try:
            tmp = history_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(history, indent=1, ensure_ascii=False), encoding="utf-8")
            tmp.replace(history_file)
        except OSError:
            pass
    return out


def main(argv=None) -> int:
    try:
        raw_in = sys.stdin.read().strip()
        data = json.loads(raw_in) if raw_in else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    out = converse(str(data.get("message") or ""))
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
