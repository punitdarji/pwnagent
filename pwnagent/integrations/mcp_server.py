"""MCP server that wraps Pwnagent for two-way third-party integration.

Design
------
The server drives the ``pwnagent`` CLI as a **non-interactive subprocess**
(``-n``) rather than importing Pwnagent's async/Docker orchestration in-process.
This keeps the integration decoupled from the scan runtime's event loop, signal
handling, and sandbox lifecycle — the server only launches runs and reads the
structured artifacts each run writes to ``pwnagent_runs/<run_name>/``:

    run.json                       run record (inputs, ids)
    vulnerabilities.json           list of findings
    findings.sarif                 SARIF 2.1.0 (code-scanning compatible)
    penetration_test_report.md     executive report

Exposed to MCP clients (e.g. a custom web app)
----------------------------------------------
Tools:   start_scan, cancel_scan, get_scan_status, list_scans,
         list_findings, get_report, get_sarif
Resources: pwnagent://scans
           pwnagent://scans/{scan_id}/report
           pwnagent://scans/{scan_id}/findings

Transport
---------
Defaults to Streamable HTTP so a web-app backend can connect over the network:

    PWNAGENT_MCP_TRANSPORT=streamable-http   # default (also: stdio, sse)
    PWNAGENT_MCP_HOST=127.0.0.1              # default
    PWNAGENT_MCP_PORT=8848                   # default
    PWNAGENT_MCP_WORKDIR=<dir>               # where scans run; default cwd
    PWNAGENT_BIN="pwnagent"                  # override how the CLI is launched

The scan itself needs ``PWNAGENT_LLM`` (+ provider API keys) in the server's
environment; subprocesses inherit it. See docs/llm-providers for the matrix.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from pwnagent.core.paths import RUNS_DIR_NAME, run_dir_for


logger = logging.getLogger(__name__)

# How long to wait for a launched run to materialize its run directory before
# reporting the scan as failed-to-start. The dir is created early (run.json is
# written near the top of a run), so this is generous.
_RUN_DIR_DETECT_TIMEOUT_S = 45.0
_RUN_DIR_POLL_INTERVAL_S = 0.5

_VALID_SCAN_MODES = ("quick", "standard", "deep")


def _workdir() -> Path:
    return Path(os.environ.get("PWNAGENT_MCP_WORKDIR", "")).resolve() or Path.cwd()


def _runs_dir(workdir: Path) -> Path:
    return workdir / RUNS_DIR_NAME


def _index_path(workdir: Path) -> Path:
    return _runs_dir(workdir) / ".mcp_index.json"


def _pwnagent_command() -> list[str]:
    """Return the argv prefix used to launch the Pwnagent CLI.

    Order: explicit ``PWNAGENT_BIN`` override → ``pwnagent`` console script on
    PATH → ``python -m pwnagent.interface.main`` (always available in-repo).
    """
    override = os.environ.get("PWNAGENT_BIN")
    if override:
        return shlex.split(override, posix=os.name != "nt")
    exe = shutil.which("pwnagent")
    if exe:
        return [exe]
    return [sys.executable, "-m", "pwnagent.interface.main"]


@dataclass
class ScanHandle:
    """Tracks one launched scan and maps our scan_id onto Pwnagent's run_name."""

    scan_id: str
    targets: list[str]
    scan_mode: str
    started_at: float
    workdir: str
    run_name: str | None = None
    proc: subprocess.Popen[bytes] | None = None
    log_path: str | None = None
    cancelled: bool = False
    # Populated for scans recovered from the on-disk index after a restart,
    # where the live process handle is gone.
    detached: bool = False


class ScanRegistry:
    """Thread-safe registry of launched/recovered scans."""

    def __init__(self, workdir: Path) -> None:
        self._workdir = workdir
        self._lock = threading.RLock()
        self._scans: dict[str, ScanHandle] = {}
        self._load_index()

    # ----- persistence (best-effort; survives server restarts) -------------
    def _load_index(self) -> None:
        path = _index_path(self._workdir)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Ignoring unreadable MCP scan index at %s", path)
            return
        for scan_id, rec in data.items():
            self._scans[scan_id] = ScanHandle(
                scan_id=scan_id,
                targets=rec.get("targets", []),
                scan_mode=rec.get("scan_mode", "standard"),
                started_at=rec.get("started_at", 0.0),
                workdir=rec.get("workdir", str(self._workdir)),
                run_name=rec.get("run_name"),
                detached=True,
            )

    def _save_index(self) -> None:
        path = _index_path(self._workdir)
        path.parent.mkdir(parents=True, exist_ok=True)
        snapshot = {
            h.scan_id: {
                "targets": h.targets,
                "scan_mode": h.scan_mode,
                "started_at": h.started_at,
                "workdir": h.workdir,
                "run_name": h.run_name,
            }
            for h in self._scans.values()
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        tmp.replace(path)

    # ----- accessors --------------------------------------------------------
    def add(self, handle: ScanHandle) -> None:
        with self._lock:
            self._scans[handle.scan_id] = handle
            self._save_index()

    def get(self, scan_id: str) -> ScanHandle | None:
        with self._lock:
            return self._scans.get(scan_id)

    def all(self) -> list[ScanHandle]:
        with self._lock:
            return list(self._scans.values())

    def persist(self) -> None:
        with self._lock:
            self._save_index()

    @property
    def lock(self) -> threading.RLock:
        return self._lock


# Module-level singletons, initialized in build_server().
_REGISTRY: ScanRegistry | None = None


def _registry() -> ScanRegistry:
    global _REGISTRY  # noqa: PLW0603
    if _REGISTRY is None:
        _REGISTRY = ScanRegistry(_workdir())
    return _REGISTRY


# ---------------------------------------------------------------------------
# Run-directory helpers
# ---------------------------------------------------------------------------
def _existing_run_names(workdir: Path) -> set[str]:
    runs = _runs_dir(workdir)
    if not runs.exists():
        return set()
    return {p.name for p in runs.iterdir() if p.is_dir() and not p.name.startswith(".")}


def _detect_new_run_name(
    workdir: Path, before: set[str], proc: subprocess.Popen[bytes]
) -> str | None:
    """Poll for the run directory the launched process creates."""
    deadline = time.monotonic() + _RUN_DIR_DETECT_TIMEOUT_S
    while time.monotonic() < deadline:
        new = _existing_run_names(workdir) - before
        if new:
            # Newest by mtime, in case something else created a dir concurrently.
            return max(new, key=lambda n: (_runs_dir(workdir) / n).stat().st_mtime)
        if proc.poll() is not None:
            # Process exited before creating a run dir — check once more, then give up.
            new = _existing_run_names(workdir) - before
            return max(new, key=lambda n: (_runs_dir(workdir) / n).stat().st_mtime) if new else None
        time.sleep(_RUN_DIR_POLL_INTERVAL_S)
    return None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _log_tail(handle: ScanHandle, lines: int = 30) -> str:
    if not handle.log_path:
        return ""
    try:
        text = Path(handle.log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def _status_for(handle: ScanHandle) -> dict[str, Any]:
    """Compute a status snapshot for a scan from its process + artifacts."""
    workdir = Path(handle.workdir)
    run_name = handle.run_name
    run_dir = run_dir_for(run_name, cwd=workdir) if run_name else None

    findings_count = 0
    severity_counts: dict[str, int] = {}
    cost_usd: float | None = None
    if run_dir is not None:
        vulns = _read_json(run_dir / "vulnerabilities.json")
        if isinstance(vulns, list):
            findings_count = len(vulns)
            for v in vulns:
                sev = str(v.get("severity", "unknown")).lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        record = _read_json(run_dir / "run.json")
        if isinstance(record, dict):
            for key in ("cost_usd", "total_cost_usd", "cost", "total_cost"):
                if isinstance(record.get(key), (int, float)):
                    cost_usd = float(record[key])
                    break

    # Determine lifecycle state.
    if handle.cancelled:
        state = "cancelled"
        exit_code = handle.proc.returncode if handle.proc else None
    elif handle.detached:
        # Recovered from index; no live process handle.
        report_exists = run_dir is not None and (run_dir / "penetration_test_report.md").exists()
        state = "completed" if report_exists else "unknown"
        exit_code = None
    elif handle.proc is None:
        state = "unknown"
        exit_code = None
    else:
        rc = handle.proc.poll()
        if rc is None:
            state = "starting" if run_name is None else "running"
            exit_code = None
        else:
            state = "completed" if rc == 0 else "failed"
            exit_code = rc

    status: dict[str, Any] = {
        "scan_id": handle.scan_id,
        "run_name": run_name,
        "state": state,
        "exit_code": exit_code,
        "targets": handle.targets,
        "scan_mode": handle.scan_mode,
        "started_at": handle.started_at,
        "findings_count": findings_count,
        "severity_counts": severity_counts,
        "cost_usd": cost_usd,
        "run_dir": str(run_dir) if run_dir else None,
    }
    if state == "failed":
        status["log_tail"] = _log_tail(handle)
    return status


# ---------------------------------------------------------------------------
# MCP server definition
# ---------------------------------------------------------------------------
def build_server() -> FastMCP:
    host = os.environ.get("PWNAGENT_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("PWNAGENT_MCP_PORT", "8848"))
    workdir = _workdir()
    global _REGISTRY  # noqa: PLW0603
    _REGISTRY = ScanRegistry(workdir)

    mcp = FastMCP(
        "pwnagent",
        instructions=(
            "Control Pwnagent autonomous penetration-test scans. Call start_scan "
            "to launch a scan (returns a scan_id immediately; scans run in the "
            "background for minutes to hours), then poll get_scan_status and read "
            "results with list_findings / get_report / get_sarif."
        ),
        host=host,
        port=port,
    )

    @mcp.tool()
    def start_scan(
        target: str,
        scan_mode: str = "standard",
        instruction: str | None = None,
        extra_targets: list[str] | None = None,
        max_budget_usd: float | None = None,
    ) -> dict[str, Any]:
        """Launch a Pwnagent scan in the background.

        Returns immediately with a ``scan_id`` used to poll status/results.

        Args:
            target: Primary target (URL, repo URL, domain, IP, or local path).
            scan_mode: One of quick | standard | deep.
            instruction: Optional free-form guidance (focus areas, credentials).
            extra_targets: Additional targets for a multi-target scan.
            max_budget_usd: Optional hard USD cap; the scan stops cleanly at it.
        """
        if scan_mode not in _VALID_SCAN_MODES:
            return {"error": f"scan_mode must be one of {_VALID_SCAN_MODES}"}
        if not os.environ.get("PWNAGENT_LLM"):
            return {
                "error": "PWNAGENT_LLM is not set in the server environment; "
                "scans cannot run. Configure the LLM + provider keys first."
            }

        targets = [target, *(extra_targets or [])]
        argv = [*_pwnagent_command(), "-n", "-m", scan_mode]
        for t in targets:
            argv += ["-t", t]
        if instruction:
            argv += ["--instruction", instruction]
        if max_budget_usd is not None:
            argv += ["--max-budget-usd", str(max_budget_usd)]

        reg = _registry()
        scan_id = uuid.uuid4().hex[:12]
        log_dir = _runs_dir(workdir) / ".mcp_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{scan_id}.log"

        # Serialize launch + run-dir detection so concurrent launches don't
        # steal each other's freshly created run directory.
        with reg.lock:
            before = _existing_run_names(workdir)
            log_file = log_path.open("wb")
            try:
                proc = subprocess.Popen(  # noqa: S603
                    argv,
                    cwd=str(workdir),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=os.environ.copy(),
                )
            except OSError as exc:
                log_file.close()
                return {"error": f"failed to launch pwnagent: {exc}", "argv": argv}

            handle = ScanHandle(
                scan_id=scan_id,
                targets=targets,
                scan_mode=scan_mode,
                started_at=time.time(),
                workdir=str(workdir),
                proc=proc,
                log_path=str(log_path),
            )
            run_name = _detect_new_run_name(workdir, before, proc)
            handle.run_name = run_name
            reg.add(handle)

        if run_name is None and proc.poll() is not None:
            handle_status = _status_for(handle)
            handle_status["error"] = (
                "pwnagent exited before creating a run directory; see log_tail."
            )
            return handle_status

        return {
            "scan_id": scan_id,
            "run_name": run_name,
            "state": "running" if run_name else "starting",
            "targets": targets,
            "scan_mode": scan_mode,
        }

    @mcp.tool()
    def get_scan_status(scan_id: str) -> dict[str, Any]:
        """Return the lifecycle state + finding counts for a scan."""
        handle = _registry().get(scan_id)
        if handle is None:
            return {"error": f"unknown scan_id: {scan_id}"}
        status = _status_for(handle)
        _registry().persist()
        return status

    @mcp.tool()
    def list_scans() -> dict[str, Any]:
        """List all scans this server has launched or recovered."""
        return {"scans": [_status_for(h) for h in _registry().all()]}

    @mcp.tool()
    def list_findings(
        scan_id: str, severity: str | None = None, full: bool = False
    ) -> dict[str, Any]:
        """Return findings for a scan.

        Args:
            scan_id: The scan handle from start_scan.
            severity: Optional filter (critical|high|medium|low|info).
            full: If true, return each finding's full record; otherwise a
                summary (id, title, severity, timestamp, file).
        """
        handle = _registry().get(scan_id)
        if handle is None:
            return {"error": f"unknown scan_id: {scan_id}"}
        if not handle.run_name:
            return {"scan_id": scan_id, "findings": [], "note": "run not started yet"}
        run_dir = run_dir_for(handle.run_name, cwd=Path(handle.workdir))
        vulns = _read_json(run_dir / "vulnerabilities.json")
        if not isinstance(vulns, list):
            return {"scan_id": scan_id, "findings": []}
        if severity:
            want = severity.lower()
            vulns = [v for v in vulns if str(v.get("severity", "")).lower() == want]
        if not full:
            vulns = [
                {
                    "id": v.get("id"),
                    "title": v.get("title"),
                    "severity": v.get("severity"),
                    "timestamp": v.get("timestamp"),
                    "file": v.get("file"),
                }
                for v in vulns
            ]
        return {"scan_id": scan_id, "count": len(vulns), "findings": vulns}

    @mcp.tool()
    def get_report(scan_id: str) -> dict[str, Any]:
        """Return the executive markdown report for a scan (if generated yet)."""
        handle = _registry().get(scan_id)
        if handle is None:
            return {"error": f"unknown scan_id: {scan_id}"}
        if not handle.run_name:
            return {"error": "run not started yet"}
        run_dir = run_dir_for(handle.run_name, cwd=Path(handle.workdir))
        report = run_dir / "penetration_test_report.md"
        if not report.exists():
            return {"scan_id": scan_id, "report": None, "note": "report not generated yet"}
        return {"scan_id": scan_id, "report": report.read_text(encoding="utf-8")}

    @mcp.tool()
    def get_sarif(scan_id: str) -> dict[str, Any]:
        """Return the SARIF 2.1.0 document for a scan (for security dashboards)."""
        handle = _registry().get(scan_id)
        if handle is None:
            return {"error": f"unknown scan_id: {scan_id}"}
        if not handle.run_name:
            return {"error": "run not started yet"}
        run_dir = run_dir_for(handle.run_name, cwd=Path(handle.workdir))
        sarif = _read_json(run_dir / "findings.sarif")
        if sarif is None:
            return {"scan_id": scan_id, "sarif": None, "note": "sarif not generated yet"}
        return {"scan_id": scan_id, "sarif": sarif}

    @mcp.tool()
    def cancel_scan(scan_id: str) -> dict[str, Any]:
        """Terminate a running scan's process."""
        handle = _registry().get(scan_id)
        if handle is None:
            return {"error": f"unknown scan_id: {scan_id}"}
        if handle.proc is None or handle.proc.poll() is not None:
            return {"scan_id": scan_id, "state": "not_running"}
        handle.cancelled = True
        handle.proc.terminate()
        return {"scan_id": scan_id, "state": "cancelling"}

    # ----- resources --------------------------------------------------------
    @mcp.resource("pwnagent://scans")
    def scans_resource() -> str:
        return json.dumps({"scans": [_status_for(h) for h in _registry().all()]}, indent=2)

    @mcp.resource("pwnagent://scans/{scan_id}/report")
    def report_resource(scan_id: str) -> str:
        handle = _registry().get(scan_id)
        if handle is None or not handle.run_name:
            return f"# No report for scan {scan_id}"
        run_dir = run_dir_for(handle.run_name, cwd=Path(handle.workdir))
        report = run_dir / "penetration_test_report.md"
        if report.exists():
            return report.read_text(encoding="utf-8")
        return f"# Report pending for {scan_id}"

    @mcp.resource("pwnagent://scans/{scan_id}/findings")
    def findings_resource(scan_id: str) -> str:
        handle = _registry().get(scan_id)
        if handle is None or not handle.run_name:
            return json.dumps({"findings": []})
        vulns = _read_json(
            run_dir_for(handle.run_name, cwd=Path(handle.workdir)) / "vulnerabilities.json"
        )
        return json.dumps(vulns if isinstance(vulns, list) else [], indent=2, default=str)

    return mcp


def main() -> None:
    """Console entry point: ``pwnagent-mcp``."""
    logging.basicConfig(
        level=os.environ.get("PWNAGENT_MCP_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    transport = os.environ.get("PWNAGENT_MCP_TRANSPORT", "streamable-http")
    server = build_server()
    logger.info(
        "Starting Pwnagent MCP server (transport=%s host=%s port=%s workdir=%s)",
        transport,
        os.environ.get("PWNAGENT_MCP_HOST", "127.0.0.1"),
        os.environ.get("PWNAGENT_MCP_PORT", "8848"),
        _workdir(),
    )
    server.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
