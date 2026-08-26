"""Tests for CVE nuclei scanner tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pwnagent.tools.cve_scanner.tool import (
    _extract_year,
    _find_templates_for_cve,
    _parse_nuclei_jsonl,
    _validate_cve_id,
)


class TestValidateCveId:
    def test_valid_cve(self) -> None:
        assert _validate_cve_id("CVE-2021-44228") is None

    def test_valid_cve_long_number(self) -> None:
        assert _validate_cve_id("CVE-2023-123456") is None

    def test_invalid_format_missing_prefix(self) -> None:
        assert _validate_cve_id("2021-44228") is not None

    def test_invalid_format_lowercase(self) -> None:
        assert _validate_cve_id("cve-2021-44228") is not None

    def test_invalid_format_short_number(self) -> None:
        assert _validate_cve_id("CVE-2021-123") is not None

    def test_invalid_format_empty(self) -> None:
        assert _validate_cve_id("") is not None

    def test_invalid_format_garbage(self) -> None:
        assert _validate_cve_id("not-a-cve") is not None


class TestExtractYear:
    def test_extracts_year(self) -> None:
        assert _extract_year("CVE-2021-44228") == "2021"

    def test_extracts_year_2023(self) -> None:
        assert _extract_year("CVE-2023-22515") == "2023"


class TestParseNucleiJsonl:
    def test_empty_input(self) -> None:
        assert _parse_nuclei_jsonl("") == []

    def test_single_finding(self) -> None:
        entry = {
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "classification": {"cve-id": ["CVE-2021-44228"]},
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/api",
            "type": "http",
            "matcher-name": "log4j",
        }
        raw = json.dumps(entry) + "\n"
        findings = _parse_nuclei_jsonl(raw)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "CVE-2021-44228"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cve_ids"] == ["CVE-2021-44228"]

    def test_multiple_findings(self) -> None:
        entries = [
            {"template-id": "CVE-2021-44228", "info": {"name": "Log4Shell", "severity": "critical"}, "host": "a.com"},
            {"template-id": "CVE-2023-22515", "info": {"name": "Confluence RCE", "severity": "high"}, "host": "b.com"},
        ]
        raw = "\n".join(json.dumps(e) for e in entries)
        findings = _parse_nuclei_jsonl(raw)
        assert len(findings) == 2

    def test_invalid_json_lines_skipped(self) -> None:
        raw = "not json\n" + json.dumps({"template-id": "test", "info": {"name": "t", "severity": "low"}, "host": "a.com"})
        findings = _parse_nuclei_jsonl(raw)
        assert len(findings) == 1

    def test_cve_extracted_from_template_id(self) -> None:
        entry = {
            "template-id": "CVE-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical", "classification": {}},
            "host": "https://example.com",
        }
        raw = json.dumps(entry)
        findings = _parse_nuclei_jsonl(raw)
        assert findings[0]["cve_ids"] == ["CVE-2021-44228"]

    def test_empty_lines_ignored(self) -> None:
        entry = {"template-id": "test", "info": {"name": "t", "severity": "low"}, "host": "a.com"}
        raw = "\n\n" + json.dumps(entry) + "\n\n"
        findings = _parse_nuclei_jsonl(raw)
        assert len(findings) == 1


class TestFindTemplatesForCve:
    @patch("pwnagent.tools.cve_scanner.tool._search_template_github")
    def test_found_via_github(self, mock_search: MagicMock) -> None:
        mock_search.return_value = [
            {"path": "http/cves/2021/CVE-2021-44228.yaml", "raw_url": "https://raw...", "protocol": "http"}
        ]
        result = _find_templates_for_cve("CVE-2021-44228")
        assert result["found"] is True
        assert len(result["templates"]) == 1
        assert result["cve_id"] == "CVE-2021-44228"

    @patch("pwnagent.tools.cve_scanner.tool._probe_direct_urls")
    @patch("pwnagent.tools.cve_scanner.tool._search_template_github")
    def test_fallback_to_direct_probe(self, mock_search: MagicMock, mock_probe: MagicMock) -> None:
        mock_search.return_value = []
        mock_probe.return_value = [
            {"path": "http/cves/2021/CVE-2021-44228.yaml", "raw_url": "https://raw...", "protocol": "http"}
        ]
        result = _find_templates_for_cve("CVE-2021-44228")
        assert result["found"] is True
        mock_probe.assert_called_once_with("CVE-2021-44228")

    @patch("pwnagent.tools.cve_scanner.tool._probe_direct_urls")
    @patch("pwnagent.tools.cve_scanner.tool._search_template_github")
    def test_not_found(self, mock_search: MagicMock, mock_probe: MagicMock) -> None:
        mock_search.return_value = []
        mock_probe.return_value = []
        result = _find_templates_for_cve("CVE-9999-00000")
        assert result["found"] is False
        assert "error" in result
        assert result["templates"] == []


@pytest.mark.asyncio
class TestFindCveNucleiTemplates:
    async def test_empty_cve_ids(self) -> None:
        from pwnagent.tools.cve_scanner.tool import find_cve_nuclei_templates

        ctx = MagicMock()
        result = json.loads(await find_cve_nuclei_templates.on_invoke_tool(ctx, json.dumps({"cve_ids": []})))
        assert result["success"] is False

    async def test_invalid_cve_format(self) -> None:
        from pwnagent.tools.cve_scanner.tool import find_cve_nuclei_templates

        ctx = MagicMock()
        result = json.loads(await find_cve_nuclei_templates.on_invoke_tool(ctx, json.dumps({"cve_ids": ["bad-id"]})))
        assert result["success"] is False
        assert "errors" in result

    async def test_too_many_cves(self) -> None:
        from pwnagent.tools.cve_scanner.tool import find_cve_nuclei_templates

        ctx = MagicMock()
        cves = [f"CVE-2021-{i:05d}" for i in range(51)]
        result = json.loads(await find_cve_nuclei_templates.on_invoke_tool(ctx, json.dumps({"cve_ids": cves})))
        assert result["success"] is False
        assert "Too many" in result["error"]


@pytest.mark.asyncio
class TestRunCveNucleiScan:
    async def test_empty_cve_ids(self) -> None:
        from pwnagent.tools.cve_scanner.tool import run_cve_nuclei_scan

        ctx = MagicMock()
        result = json.loads(await run_cve_nuclei_scan.on_invoke_tool(
            ctx, json.dumps({"cve_ids": [], "targets": ["https://example.com"]}),
        ))
        assert result["success"] is False

    async def test_empty_targets(self) -> None:
        from pwnagent.tools.cve_scanner.tool import run_cve_nuclei_scan

        ctx = MagicMock()
        result = json.loads(await run_cve_nuclei_scan.on_invoke_tool(
            ctx, json.dumps({"cve_ids": ["CVE-2021-44228"], "targets": []}),
        ))
        assert result["success"] is False

    async def test_invalid_cve_rejected(self) -> None:
        from pwnagent.tools.cve_scanner.tool import run_cve_nuclei_scan

        ctx = MagicMock()
        result = json.loads(await run_cve_nuclei_scan.on_invoke_tool(
            ctx, json.dumps({"cve_ids": ["not-valid"], "targets": ["https://example.com"]}),
        ))
        assert result["success"] is False
        assert "errors" in result

    async def test_no_sandbox_session(self) -> None:
        from pwnagent.tools.cve_scanner.tool import run_cve_nuclei_scan

        ctx = MagicMock()
        ctx.context = {}
        result = json.loads(await run_cve_nuclei_scan.on_invoke_tool(
            ctx, json.dumps({"cve_ids": ["CVE-2021-44228"], "targets": ["https://example.com"]}),
        ))
        assert result["success"] is False
        assert "Sandbox session" in result["error"]
