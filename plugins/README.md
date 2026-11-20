# Your own puzzle pieces

Every slot in `patchpilot.yaml` and `fleet.yaml` takes a built-in piece by name
or your own class by `"module:Class"`. Modules in this folder are importable
by their file name.

| Slot | Where | Your class needs | Built-in pieces to copy from |
|------|-------|------------------|------------------------------|
| auth | `patchpilot.yaml` `auth.kind` | `__init__(cfg)`, `identify(headers) -> user or None`, `kind` | `agent/auth.py` |
| forge | `patchpilot.yaml` `forge.kind` or a source's `forge:` | subclass `agent.drivers.forge._Forge`, implement `open_review(branch, title, body) -> url` | `agent/drivers/forge.py` |
| feed | `patchpilot.yaml` `feed.kind` | `__init__(cfg)`, `poll() -> [OSV records]`, `every` (seconds), `kind` | `agent/feeds.py` |
| notify | `patchpilot.yaml` `notify[].kind` | `__init__(cfg)`, `send(message: dict)`, `kind` | `agent/notify.py` |
| target | `fleet.yaml` `targets[].kind` | `__init__(spec, repo_for)` + the `Target` methods | `agent/drivers/base.py`, `kubernetes.py`, `compose.py` |
| ecosystem | `fleet.yaml` `ecosystems: [...]` | the `Ecosystem` methods, `name` | `agent/drivers/base.py`, `maven.py`, `pypi.py` |
| model | environment (`LLM_PROVIDER`) | see `agent/providers.py` | `openai-compatible` covers most self-hosted servers |

Every piece may also have `check() -> [(ok: bool, message: str)]`; `python -m agent.doctor` prints it.

`example_jira.py` is a complete notify piece: it opens a Jira issue when an approval is waiting.

```yaml
notify:
  - kind: "example_jira:JiraIssue"
    url: https://example.atlassian.net
    project: SEC
    user: ${JIRA_USER}
    token: ${JIRA_TOKEN}
    on: [awaiting_approval, escalated]
```
