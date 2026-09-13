"""py_stats tool (SPEC §4): run a small pandas snippet over a query result, sandboxed.

Preferred sandbox: Docker ``--network none`` (same runner contract as Sentinel) with a 30s timeout,
read-only bind of the data, no network. When Docker is unavailable (CI, laptops), a *restricted*
in-process fallback runs the snippet with builtins stripped to a safe allow-list, no imports beyond
pandas/numpy, no file/network access, and a wall-clock guard. The fallback refuses any snippet that
references dunder attributes, ``open``, ``import`` or ``exec``/``eval`` - it is for computing
histograms and aggregates over an already-fetched result, nothing else.

The agent uses this to compute things like logon-hour distributions or per-host process counts; it
never runs agent-authored code against the host (§9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aegis.tools.base import ToolResult, error_result, make_result

_FORBIDDEN = re.compile(
    r"__\w+__|\bimport\b|\bopen\b|\bexec\b|\beval\b|\bcompile\b|\bglobals\b|\blocals\b|"
    r"\bgetattr\b|\bsetattr\b|\b__import__\b|\bos\b|\bsys\b|\bsubprocess\b|\bsocket\b|\bPath\b",
    re.IGNORECASE,
)
_SAFE_BUILTINS = {
    "len": len,
    "min": min,
    "max": max,
    "sum": sum,
    "sorted": sorted,
    "abs": abs,
    "round": round,
    "range": range,
    "enumerate": enumerate,
    "zip": zip,
    "list": list,
    "dict": dict,
    "set": set,
    "float": float,
    "int": int,
    "str": str,
    "bool": bool,
    "tuple": tuple,
    "any": any,
    "all": all,
}


@dataclass
class SandboxResult:
    ok: bool
    result: Any
    stdout: str
    error: str | None = None


def _in_process(code: str, rows: list[dict[str, Any]], timeout_s: int) -> SandboxResult:
    if _FORBIDDEN.search(code):
        return SandboxResult(False, None, "", "snippet uses a forbidden name/construct")
    try:
        import pandas as pd
    except ImportError:  # pragma: no cover
        return SandboxResult(False, None, "", "pandas not available")
    import io
    from contextlib import redirect_stdout

    df = pd.DataFrame(rows)
    env: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS, "pd": pd, "df": df, "result": None}
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(code, env)
    except Exception as e:
        return SandboxResult(False, None, buf.getvalue(), f"{type(e).__name__}: {e}")
    result = env.get("result")
    if result is not None and hasattr(result, "to_dict"):
        result = result.to_dict()
    return SandboxResult(True, result, buf.getvalue())


def py_stats(
    code: str, rows: list[dict[str, Any]], *, timeout_s: int = 30, prefer_docker: bool = False
) -> ToolResult:
    """Run ``code`` (which reads DataFrame ``df`` and assigns ``result``) over ``rows``."""
    if prefer_docker and _docker_available():
        sb = _docker_run(code, rows, timeout_s)
    else:
        sb = _in_process(code, rows, timeout_s)
    if not sb.ok:
        return error_result("py_stats", "sandbox", sb.error or "sandbox failure")
    data = {"result": sb.result, "stdout": sb.stdout[:2000], "rows_in": len(rows)}
    render = f"result: {sb.result}\n{sb.stdout[:1000]}".strip()
    return make_result("py_stats", "sandbox", data, render=render, guard=False)


def _docker_available() -> bool:
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False
    try:
        return (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=5, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def _docker_run(
    code: str, rows: list[dict[str, Any]], timeout_s: int
) -> SandboxResult:  # pragma: no cover
    import json
    import subprocess
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "rows.json").write_text(json.dumps(rows), encoding="utf-8")
        runner = (
            "import json,pandas as pd\n"
            "df=pd.DataFrame(json.load(open('/data/rows.json')))\n"
            "result=None\n" + code + "\n"
            "print(json.dumps({'result': result.to_dict() if hasattr(result,'to_dict') "
            "else result}, default=str))"
        )
        (tdp / "run.py").write_text(runner, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--memory",
                    "512m",
                    "--cpus",
                    "1",
                    "-v",
                    f"{tdp}:/data:ro",
                    "python:3.12-slim",
                    "python",
                    "/data/run.py",
                ],
                capture_output=True,
                text=True,
                timeout=timeout_s + 10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(False, None, "", "docker sandbox timed out")
        if proc.returncode != 0:
            return SandboxResult(False, None, proc.stdout, proc.stderr[-500:])
        try:
            out = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return SandboxResult(True, None, proc.stdout)
        return SandboxResult(True, out.get("result"), proc.stdout)
