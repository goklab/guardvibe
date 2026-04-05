# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| 2.x     | Security fixes only |
| < 2.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in GuardVibe, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **info@goklab.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. We will acknowledge your report within 48 hours.
4. We will publish a fix and credit you (unless you prefer anonymity).

## Scope

- GuardVibe CLI and MCP server code
- Security rule patterns (false negatives that miss real vulnerabilities)
- npm package supply chain (compromised builds, malicious dependencies)

## Out of Scope

- False positives (use the [false positive issue template](https://github.com/goklab/guardvibe/issues/new?template=false_positive.yml) instead)
- Feature requests
