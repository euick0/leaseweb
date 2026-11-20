"""Notify piece: tell people when a decision needs them or an action ends.

  notify:
    - kind: slack                     # incoming webhook
      webhook: ${SLACK_WEBHOOK_URL}
      on: [awaiting_approval, failed, rolled_back, escalated]
    - kind: teams                     # incoming webhook / Workflows URL
      webhook: ${TEAMS_WEBHOOK_URL}
    - kind: webhook                   # any JSON endpoint (PagerDuty, Jira automation, ...)
      url: https://hooks.example.com/lighthouse
      headers: {Authorization: "Bearer ${HOOK_TOKEN}"}
    - kind: email
      smtp_host: smtp.example.com
      smtp_port: 587
      username: ${SMTP_USER}
      password: ${SMTP_PASSWORD}
      from: lighthouse@example.com
      to: [secops@example.com]

`on` defaults to the statuses where a human is needed or something went wrong.
Messages are sent on a background thread; a failing channel is logged and
never blocks a rollout. A custom piece is a class with `send(message: dict)`.
"""
from __future__ import annotations

import smtplib
import threading
from email.message import EmailMessage
from typing import Optional

import requests

from . import db, settings

DEFAULT_ON = ["awaiting_approval", "failed", "rolled_back", "escalated", "blocked"]
HEADLINE = {
    "awaiting_approval": "needs your approval",
    "queued": "queued for the next maintenance window",
    "done": "fixed",
    "failed": "failed",
    "rolled_back": "rolled back",
    "escalated": "needs a human",
    "blocked": "blocked",
    "ignored": "ignored (not reachable)",
}


def message(item: dict) -> dict:
    """The facts every channel renders: plain values, no markup."""
    run = db.get_run(item["run_id"]) or {}
    wl, comp, decision = item.get("workload") or {}, item.get("component") or {}, item.get("decision") or {}
    triage = item.get("triage") or {}
    package = f"{comp.get('group') + ':' if comp.get('group') else ''}{comp.get('name', '?')} {comp.get('version', '')}"
    return {
        "event": item["status"],
        "title": f"{run.get('title', 'Advisory')} on {wl.get('name', item.get('workload_id'))}: "
                 f"{HEADLINE.get(item['status'], item['status'])}",
        "advisory": run.get("advisory_id"),
        "workload": item.get("workload_id"),
        "environment": wl.get("target"),
        "package": package.strip(),
        "fixed_version": item.get("fixed_version"),
        "severity": triage.get("severity_for_this_workload"),
        "action": decision.get("action"),
        "reason": decision.get("reason") or item.get("outcome"),
        "outcome": item.get("outcome"),
        "url": f"{settings.public_url()}/#run={item['run_id']}&item={item['id']}",
    }


def _text(m: dict) -> str:
    lines = [m["title"], f"Package: {m['package']}" + (f" → {m['fixed_version']}" if m["fixed_version"] else "")]
    if m["severity"]:
        lines.append(f"Severity here: {m['severity']}")
    if m["reason"]:
        lines.append(f"Why: {m['reason']}")
    lines.append(m["url"])
    return "\n".join(lines)


class Slack:
    kind = "slack"

    def __init__(self, cfg: dict):
        self.webhook = cfg.get("webhook")

    def send(self, m: dict) -> None:
        requests.post(self.webhook, json={"text": _text(m)}, timeout=10).raise_for_status()

    def check(self) -> list[tuple[bool, str]]:
        return [(bool(self.webhook), "Slack webhook set" if self.webhook else "fill in the Slack webhook URL")]


class Teams(Slack):
    kind = "teams"

    def send(self, m: dict) -> None:
        requests.post(self.webhook, json={"text": _text(m).replace("\n", "<br>")}, timeout=10).raise_for_status()

    def check(self) -> list[tuple[bool, str]]:
        return [(bool(self.webhook), "Teams webhook set" if self.webhook else "fill in the Teams webhook URL")]


class Webhook:
    kind = "webhook"

    def __init__(self, cfg: dict):
        self.url, self.headers = cfg.get("url"), cfg.get("headers") or {}

    def send(self, m: dict) -> None:
        requests.post(self.url, json=m, headers=self.headers, timeout=10).raise_for_status()

    def check(self) -> list[tuple[bool, str]]:
        return [(bool(self.url), f"webhook {self.url}" if self.url else "fill in the webhook url")]


class Email:
    kind = "email"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.to = cfg.get("to") or []
        if isinstance(self.to, str):
            self.to = [self.to]

    def send(self, m: dict) -> None:
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = f"[LightHouse] {m['title']}", self.cfg["from"], ", ".join(self.to)
        msg.set_content(_text(m))
        with smtplib.SMTP(self.cfg["smtp_host"], int(self.cfg.get("smtp_port", 587)), timeout=20) as smtp:
            if self.cfg.get("starttls", True):
                smtp.starttls()
            if self.cfg.get("username"):
                smtp.login(self.cfg["username"], self.cfg.get("password", ""))
            smtp.send_message(msg)

    def check(self) -> list[tuple[bool, str]]:
        missing = [k for k in ("smtp_host", "from") if not self.cfg.get(k)] + ([] if self.to else ["to"])
        return [(not missing, "email via " + str(self.cfg.get("smtp_host")) if not missing
                 else "fill in email " + ", ".join(missing))]


BUILTIN = {"slack": Slack, "teams": Teams, "webhook": Webhook, "email": Email}


class Channel:
    def __init__(self, cfg: dict):
        self.piece = settings.load_class(cfg.get("kind", ""), BUILTIN, "notify")(cfg)
        self.on = set(cfg.get("on") or DEFAULT_ON)


_channels: Optional[list[Channel]] = None


def channels() -> list[Channel]:
    global _channels
    if _channels is None:
        _channels = [Channel(c) for c in settings.section("notify", []) or []]
    return _channels


def reset() -> None:
    global _channels
    _channels = None


def on_status(item: dict) -> None:
    """db.STATUS_HOOKS entry: fan the change out to every interested channel."""
    targets = [c for c in channels() if item["status"] in c.on]
    if not targets:
        return
    m = message(item)

    def deliver():
        for c in targets:
            try:
                c.piece.send(m)
            except Exception as exc:
                print(f"[notify] {c.piece.kind}: {type(exc).__name__}: {exc}", flush=True)

    threading.Thread(target=deliver, daemon=True).start()
