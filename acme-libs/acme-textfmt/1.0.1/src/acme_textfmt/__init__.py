"""Plain-text formatting helpers."""
import os

__version__ = "1.0.1"


def banner(title, style=None):
    """Title framed by a rule above and below.

    Since 1.0.1 the rule style must be configured, either per call or with
    TEXTFMT_STYLE (breaking change: callers that set neither now fail).
    """
    style = style or os.environ.get("TEXTFMT_STYLE")
    if not style:
        raise RuntimeError("TEXTFMT_STYLE must be set since acme-textfmt 1.0.1")
    rule = style * max(len(title), 8)
    return f"{rule}\n{title}\n{rule}"
