"""Optional Docker isolation for launching untrusted MCP servers during a scan."""
from __future__ import annotations

import shutil

from .models import ServerSpec


def docker_available() -> bool:
    return shutil.which("docker") is not None


def wrap(spec: ServerSpec, image: str, network: str = "none", memory: str = "512m") -> ServerSpec:
    """Return a spec that runs the server inside a locked-down container.

    Notes: the server's command must exist inside `image`. Servers that need the network to start
    (e.g. `npx` downloading a package) need network="bridge" or a pre-built image.
    """
    cmd = ["run", "--rm", "-i", f"--network={network}", "--read-only", "--cap-drop=ALL",
           "--security-opt=no-new-privileges", f"--memory={memory}", "--pids-limit=128",
           "--tmpfs", "/tmp:rw,size=64m"]
    for k, v in (spec.env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [image, spec.command, *map(str, spec.args)]
    return ServerSpec(name=spec.name, command="docker", args=cmd, env={}, source=spec.source, transport="stdio")
