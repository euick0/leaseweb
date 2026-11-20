"""Example custom notify piece: open a Jira issue for every decision that needs a human.

  notify:
    - kind: "example_jira:JiraIssue"
      url: https://example.atlassian.net
      project: SEC
      user: ${JIRA_USER}
      token: ${JIRA_TOKEN}
      on: [awaiting_approval, escalated]
"""
import requests


class JiraIssue:
    kind = "jira"

    def __init__(self, cfg: dict):
        self.url = (cfg.get("url") or "").rstrip("/")
        self.project, self.user, self.token = cfg.get("project"), cfg.get("user"), cfg.get("token")
        self.issue_type = cfg.get("issue_type", "Task")

    def send(self, message: dict) -> None:
        description = "\n".join(f"{k}: {v}" for k, v in message.items() if v and k != "title")
        requests.post(f"{self.url}/rest/api/2/issue", auth=(self.user, self.token), timeout=20, json={
            "fields": {"project": {"key": self.project}, "issuetype": {"name": self.issue_type},
                       "summary": f"[LightHouse] {message['title']}"[:250], "description": description,
                       "labels": ["lighthouse", "security"]}}).raise_for_status()

    def check(self):
        missing = [k for k in ("url", "project", "user", "token") if not getattr(self, k)]
        return [(not missing, f"Jira project {self.project}" if not missing else "fill in Jira " + ", ".join(missing))]
