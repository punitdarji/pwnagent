"""Third-party integration surfaces for Pwnagent.

Currently ships an MCP (Model Context Protocol) server that exposes Pwnagent
scan control + results as MCP tools/resources so external applications
(custom web apps, AI agents, MCP-aware clients) can trigger scans and read
findings back over a standard protocol.
"""
