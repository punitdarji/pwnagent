---
name: cve-nuclei-scanning
description: Active CVE validation using nuclei templates from GitHub — find, download, run, and report CVE-specific scans against targets.
---

# CVE Nuclei Template Scanning

Validate whether specific CVEs affect target systems by fetching and running
CVE-specific nuclei templates from ProjectDiscovery's GitHub repository.

## When to use

- User asks to "check CVE-XXXX-XXXXX" against a target
- Confirming whether a known CVE is exploitable
- Bulk CVE validation across multiple targets
- Post-remediation verification of patched CVEs

## Tools

Two dedicated tools handle the full pipeline:

- **`find_cve_nuclei_templates`** — lookup only. Check if a nuclei template
  exists for a CVE without running a scan. Use for planning or when the user
  just wants to know whether a template is available.

- **`run_cve_nuclei_scan`** — full pipeline. Finds templates on GitHub,
  downloads them into the sandbox, runs nuclei, and returns parsed structured
  results. This is the primary tool — use it for actual scanning.

## Quick workflow (1-5 CVEs, 1-10 targets)

1. Call `run_cve_nuclei_scan` with the CVE IDs and targets.
2. Interpret the structured results.
3. For each confirmed finding, file `create_vulnerability_report` with:
   - `cve` field set to the CVE ID
   - Nuclei match details and curl command as evidence
   - Matched URL as the PoC
4. Report CVEs with no findings to the user (negative results are valuable).

## Large-scale workflow (>5 CVEs or >10 targets)

1. Call `find_cve_nuclei_templates` first to check availability for all CVEs.
2. Split into batches of ~20 CVEs if needed (nuclei performance).
3. Call `run_cve_nuclei_scan` per batch.
4. Aggregate results and file reports for confirmed findings.

## When a template is not found

1. Use `web_search` to research the CVE details (affected software, versions,
   attack vector).
2. Check if manual testing is possible using the CVE description.
3. Try a broad nuclei scan: `nuclei -tags cve -l targets.txt` as fallback.
4. Inform the user that no template exists and suggest alternative approaches.

## Multi-agent strategy

For large matrices (>10 CVEs x >10 targets):
- Create child agents, each assigned a subset of targets.
- Each child loads this skill + the `nuclei` skill.
- Parent aggregates results via `wait_for_message`.

## Reporting rules

- Every confirmed finding requires `create_vulnerability_report` with the
  `cve` field populated.
- Include nuclei template output as `evidence`.
- Include the `matched_at` URL and `curl_command` in `poc_description`.
- Use `severity` from nuclei output to inform CVSS scoring.
- Do NOT file a report for CVEs where nuclei found no match — but DO inform
  the user about negative results.

## Anti-patterns

- Do not skip `create_vulnerability_report` for confirmed findings.
- Do not guess CVE IDs — validate format before scanning.
- Do not run unscoped broad nuclei scans when specific CVEs are requested.
- Do not suppress negative results — the user needs to know what was tested
  and what was not found.
