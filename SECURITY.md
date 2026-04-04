# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, open a [GitHub Security Advisory](../../security/advisories/new) in this repository. You will receive a response within 5 business days. If the issue is confirmed, a patch will be released as soon as possible.

When reporting, please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (if applicable)
- Any suggested mitigations you have identified

## Scope

This plugin generates threat model documents by reading local repository source code. It does not transmit source code to any external service other than the Anthropic API (which processes prompts to generate analysis). Please review [Anthropic's privacy policy](https://www.anthropic.com/privacy) before running this plugin on sensitive codebases.

The MCP context server (`mcp/appsec-context/`) is a **mock** that ships with illustrative data. Do not store real credentials, findings, or sensitive architecture data in it.
