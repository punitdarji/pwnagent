"""``find_cve_nuclei_templates`` + ``run_cve_nuclei_scan`` — CVE-targeted nuclei scanning."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import requests
from agents import RunContextWrapper, function_tool

from pwnagent.config import load_settings


logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
)
_NUCLEI_TEMPLATES_REPO = "projectdiscovery/nuclei-templates"

_MAX_CVES_PER_CALL = 50
_MAX_TARGETS_PER_CALL = 200


def _validate_cve_id(cve: str) -> str | None:
    if not _CVE_RE.match(cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_year(cve_id: str) -> str:
    return cve_id.split("-")[1]


def _github_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    token = load_settings().integrations.github_token
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _search_template_github(cve_id: str) -> list[dict[str, str]]:
    """Search GitHub code API for nuclei templates matching a CVE ID."""
    headers = _github_headers()
    query = f"{cve_id} repo:{_NUCLEI_TEMPLATES_REPO} extension:yaml"
    try:
        resp = requests.get(
            _GITHUB_SEARCH_URL,
            params={"q": query, "per_page": 10},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403:
            logger.warning("GitHub API rate limited for %s, falling back to direct URL probe", cve_id)
            return []
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        logger.warning("GitHub search failed for %s, falling back to direct URL probe", cve_id)
        return []

    templates: list[dict[str, str]] = []
    for item in data.get("items", []):
        path = item.get("path", "")
        if cve_id.lower() not in path.lower():
            continue
        protocol = path.split("/")[0] if "/" in path else "unknown"
        templates.append({
            "path": path,
            "raw_url": f"{_GITHUB_RAW_BASE}/{path}",
            "protocol": protocol,
        })
    return templates


def _probe_direct_urls(cve_id: str) -> list[dict[str, str]]:
    """Try predictable nuclei-templates paths for a CVE."""
    year = _extract_year(cve_id)
    candidates = [
        f"http/cves/{year}/{cve_id}.yaml",
        f"network/cves/{year}/{cve_id}.yaml",
        f"dns/cves/{year}/{cve_id}.yaml",
        f"http/cves/{year}/{cve_id.lower()}.yaml",
    ]
    templates: list[dict[str, str]] = []
    for path in candidates:
        url = f"{_GITHUB_RAW_BASE}/{path}"
        try:
            resp = requests.head(url, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                protocol = path.split("/")[0]
                templates.append({
                    "path": path,
                    "raw_url": url,
                    "protocol": protocol,
                })
        except requests.RequestException:
            continue
    return templates


def _find_templates_for_cve(cve_id: str) -> dict[str, Any]:
    """Find nuclei templates for a single CVE, trying GitHub search then direct probe."""
    templates = _search_template_github(cve_id)
    if not templates:
        templates = _probe_direct_urls(cve_id)
    return {
        "cve_id": cve_id,
        "found": len(templates) > 0,
        "templates": templates,
        **({"error": "No nuclei template found for this CVE"} if not templates else {}),
    }


def _do_find_templates(cve_ids: list[str]) -> dict[str, Any]:
    """Synchronous implementation — runs in a thread."""
    results: list[dict[str, Any]] = []
    for cve_id in cve_ids:
        results.append(_find_templates_for_cve(cve_id))

    found_count = sum(1 for r in results if r["found"])
    return {
        "results": results,
        "summary": f"Found templates for {found_count}/{len(cve_ids)} CVEs",
    }


@function_tool(timeout=120)
async def find_cve_nuclei_templates(
    ctx: RunContextWrapper,
    cve_ids: list[str],
) -> str:
    """Search for nuclei vulnerability templates on GitHub for specific CVE IDs.

    Queries the projectdiscovery/nuclei-templates repository for YAML
    templates matching each CVE. Returns download URLs and metadata for
    each found template. Use this to check template availability before
    running a scan, or when you only need to know whether a template
    exists.

    For a complete scan pipeline (find + download + run + parse), use
    ``run_cve_nuclei_scan`` instead.

    Args:
        cve_ids: List of CVE identifiers (e.g. ``["CVE-2021-44228",
            "CVE-2023-22515"]``). Maximum {max_cves} per call.
    """.format(max_cves=_MAX_CVES_PER_CALL)
    if not cve_ids:
        return json.dumps({"success": False, "error": "cve_ids cannot be empty"})
    if len(cve_ids) > _MAX_CVES_PER_CALL:
        return json.dumps({
            "success": False,
            "error": f"Too many CVEs: {len(cve_ids)} (max {_MAX_CVES_PER_CALL})",
        })

    errors: list[str] = []
    cleaned: list[str] = []
    for cve in cve_ids:
        cve = cve.strip().upper()
        err = _validate_cve_id(cve)
        if err:
            errors.append(err)
        else:
            cleaned.append(cve)

    if errors:
        return json.dumps({"success": False, "errors": errors})

    logger.info("Searching nuclei templates for %d CVEs: %s", len(cleaned), cleaned)
    result = await asyncio.to_thread(_do_find_templates, cleaned)
    result["success"] = True
    return json.dumps(result, ensure_ascii=False)


async def _sandbox_exec(session: Any, command: str) -> str:
    """Execute a command in the sandbox and return stdout."""
    result = await session.exec(["bash", "-c", command])
    stdout = getattr(result, "stdout", None) or getattr(result, "output", None) or ""
    stderr = getattr(result, "stderr", None) or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return stdout.strip(), stderr.strip()


def _parse_nuclei_jsonl(raw: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings."""
    findings: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        finding = {
            "template_id": entry.get("template-id", entry.get("templateID", "")),
            "template_name": entry.get("info", {}).get("name", ""),
            "severity": entry.get("info", {}).get("severity", "unknown"),
            "target": entry.get("host", entry.get("matched-at", "")),
            "matched_at": entry.get("matched-at", ""),
            "type": entry.get("type", ""),
            "extracted_results": entry.get("extracted-results", []),
            "matcher_name": entry.get("matcher-name", ""),
            "curl_command": entry.get("curl-command", ""),
        }
        cve_tags = [
            tag for tag in entry.get("info", {}).get("classification", {}).get("cve-id", []) or []
        ]
        if not cve_tags:
            tid = finding["template_id"].upper()
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", tid)
            if cve_match:
                cve_tags = [cve_match.group(0)]
        finding["cve_ids"] = cve_tags
        findings.append(finding)

    return findings


@function_tool(timeout=600)
async def run_cve_nuclei_scan(
    ctx: RunContextWrapper,
    cve_ids: list[str],
    targets: list[str],
    severity_filter: str = "critical,high,medium,low",
    rate_limit: int = 100,
) -> str:
    """Full CVE scanning pipeline: find nuclei templates, download them,
    run nuclei against targets, and return parsed results.

    Handles all CVE × target combinations natively — nuclei runs every
    downloaded template against every target in one pass.

    | Scenario               | What happens                          |
    |------------------------|---------------------------------------|
    | 1 CVE, 1 target        | Single template, single target        |
    | 1 CVE, N targets       | Single template, targets file         |
    | N CVEs, 1 target       | N templates, single target            |
    | N CVEs, N targets      | N templates, targets file (full matrix)|

    Results are returned as structured JSON with per-finding detail
    grouped by CVE and target. Use ``create_vulnerability_report`` to
    file each confirmed finding.

    Args:
        cve_ids: CVE identifiers to scan for (e.g.
            ``["CVE-2021-44228"]``). Max {max_cves}.
        targets: Target URLs or IPs to scan (e.g.
            ``["https://example.com", "10.0.0.1"]``). Max {max_targets}.
        severity_filter: Comma-separated nuclei severity levels.
            Defaults to ``"critical,high,medium,low"``.
        rate_limit: Maximum requests per second for nuclei.
            Defaults to ``100``.
    """.format(max_cves=_MAX_CVES_PER_CALL, max_targets=_MAX_TARGETS_PER_CALL)

    # --- validate inputs ---
    if not cve_ids:
        return json.dumps({"success": False, "error": "cve_ids cannot be empty"})
    if not targets:
        return json.dumps({"success": False, "error": "targets cannot be empty"})
    if len(cve_ids) > _MAX_CVES_PER_CALL:
        return json.dumps({
            "success": False,
            "error": f"Too many CVEs: {len(cve_ids)} (max {_MAX_CVES_PER_CALL})",
        })
    if len(targets) > _MAX_TARGETS_PER_CALL:
        return json.dumps({
            "success": False,
            "error": f"Too many targets: {len(targets)} (max {_MAX_TARGETS_PER_CALL})",
        })

    cve_errors: list[str] = []
    cleaned_cves: list[str] = []
    for cve in cve_ids:
        cve = cve.strip().upper()
        err = _validate_cve_id(cve)
        if err:
            cve_errors.append(err)
        else:
            cleaned_cves.append(cve)
    if cve_errors:
        return json.dumps({"success": False, "errors": cve_errors})

    cleaned_targets = [t.strip() for t in targets if t.strip()]
    if not cleaned_targets:
        return json.dumps({"success": False, "error": "No valid targets provided"})

    # --- get sandbox session ---
    session = ctx.context.get("sandbox_session") if isinstance(ctx.context, dict) else None
    if session is None:
        return json.dumps({
            "success": False,
            "error": "Sandbox session not available. This tool must run inside a pwnagent scan.",
        })

    logger.info(
        "CVE nuclei scan: %d CVEs × %d targets (rate_limit=%d, severity=%s)",
        len(cleaned_cves),
        len(cleaned_targets),
        rate_limit,
        severity_filter,
    )

    # --- step 1: find templates ---
    template_search = await asyncio.to_thread(_do_find_templates, cleaned_cves)
    templates_found: list[dict[str, Any]] = []
    templates_not_found: list[str] = []
    for result in template_search["results"]:
        if result["found"]:
            templates_found.append(result)
        else:
            templates_not_found.append(result["cve_id"])

    if not templates_found:
        return json.dumps({
            "success": True,
            "scan_summary": {
                "total_cves_requested": len(cleaned_cves),
                "templates_found": 0,
                "templates_not_found": templates_not_found,
                "targets_scanned": 0,
                "total_findings": 0,
            },
            "findings": [],
            "message": "No nuclei templates found for any of the requested CVEs. "
                       "Consider using web_search to research these CVEs manually, "
                       "or try a broad nuclei scan with -tags cve.",
        })

    # --- step 2: download templates into sandbox ---
    template_dir = "/tmp/cve-nuclei-templates"
    await _sandbox_exec(session, f"rm -rf {template_dir} && mkdir -p {template_dir}")

    downloaded: list[str] = []
    download_errors: list[str] = []
    for tpl_result in templates_found:
        cve_id = tpl_result["cve_id"]
        for tpl in tpl_result["templates"]:
            raw_url = tpl["raw_url"]
            filename = tpl["path"].replace("/", "_")
            dest = f"{template_dir}/{filename}"
            stdout, stderr = await _sandbox_exec(
                session,
                f'curl -sL -o "{dest}" -w "%{{http_code}}" "{raw_url}"',
            )
            http_code = stdout.strip()[-3:] if stdout.strip() else ""
            if http_code == "200":
                downloaded.append(dest)
                logger.info("Downloaded template %s for %s", tpl["path"], cve_id)
            else:
                download_errors.append(
                    f"Failed to download {tpl['path']} for {cve_id} (HTTP {http_code})"
                )
                logger.warning("Failed to download template %s: HTTP %s", tpl["path"], http_code)

    if not downloaded:
        return json.dumps({
            "success": True,
            "scan_summary": {
                "total_cves_requested": len(cleaned_cves),
                "templates_found": len(templates_found),
                "templates_not_found": templates_not_found,
                "targets_scanned": 0,
                "total_findings": 0,
            },
            "findings": [],
            "download_errors": download_errors,
            "message": "Templates were found but could not be downloaded. "
                       "Check network connectivity in the sandbox.",
        })

    # --- step 3: write targets file ---
    targets_file = "/tmp/cve-nuclei-targets.txt"
    targets_content = "\\n".join(cleaned_targets)
    await _sandbox_exec(session, f'printf "%b" "{targets_content}" > {targets_file}')

    # --- step 4: run nuclei ---
    output_file = "/tmp/cve-nuclei-results.jsonl"
    nuclei_cmd = (
        f"nuclei -l {targets_file} "
        f"-t {template_dir}/ "
        f"-s {severity_filter} "
        f"-rl {rate_limit} "
        f"-c 20 -bs 20 "
        f"-timeout 15 -retries 1 "
        f"-silent -j "
        f"-o {output_file} "
        f"2>/dev/null; echo EXIT_CODE:$?"
    )

    logger.info("Running nuclei: %s", nuclei_cmd)
    stdout, stderr = await _sandbox_exec(session, nuclei_cmd)

    exit_code = "unknown"
    for line in stdout.splitlines():
        if line.startswith("EXIT_CODE:"):
            exit_code = line.split(":")[1]

    # --- step 5: read and parse output ---
    raw_output, _ = await _sandbox_exec(session, f"cat {output_file} 2>/dev/null || true")
    findings = _parse_nuclei_jsonl(raw_output)

    # --- step 6: build grouped results ---
    by_cve: dict[str, list[dict[str, Any]]] = {}
    by_target: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        for cve in f.get("cve_ids", []):
            by_cve.setdefault(cve, []).append(f)
        target = f.get("target", "")
        by_target.setdefault(target, []).append(f)

    tested_cves = [r["cve_id"] for r in templates_found]
    no_finding_cves = [c for c in tested_cves if c not in by_cve]

    scan_result = {
        "success": True,
        "scan_summary": {
            "total_cves_requested": len(cleaned_cves),
            "templates_found": len(templates_found),
            "templates_downloaded": len(downloaded),
            "templates_not_found": templates_not_found,
            "targets_scanned": len(cleaned_targets),
            "total_findings": len(findings),
            "nuclei_exit_code": exit_code,
        },
        "findings": findings,
        "by_cve": {cve: len(items) for cve, items in by_cve.items()},
        "by_target": {target: len(items) for target, items in by_target.items()},
        "no_findings_for_cves": no_finding_cves,
    }

    if download_errors:
        scan_result["download_errors"] = download_errors

    logger.info(
        "CVE nuclei scan complete: %d findings across %d CVEs and %d targets",
        len(findings),
        len(by_cve),
        len(by_target),
    )

    return json.dumps(scan_result, ensure_ascii=False, default=str)
