"""Small cross-platform helpers."""
from __future__ import annotations

import os
import shlex


def split_command(cmd: str, windows: bool | None = None) -> list[str]:
    """Split a command line the way the host shell would, including on Windows.

    shlex in POSIX mode treats backslashes as escapes, which destroys paths like
    C:\\Program Files\\Python313\\python.exe. On Windows we use non-POSIX mode (keeps backslashes)
    and strip the surrounding double quotes that mode leaves on quoted tokens.
    """
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return shlex.split(cmd)
    out = []
    for tok in shlex.split(cmd, posix=False):
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        out.append(tok)
    return out
