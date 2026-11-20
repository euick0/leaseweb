"""Plain-text formatting helpers."""

__version__ = "1.0.0"


def banner(title, style="="):
    """Title framed by a rule above and below."""
    rule = style * max(len(title), 8)
    return f"{rule}\n{title}\n{rule}"
