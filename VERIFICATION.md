# Release verification — 0.1.0

Date: 2026-11-23. All test keys and connections are generated or fictitious.
No production vault data or connections were migrated.

| Check | Linux x86_64 | macOS 15.8.1 Intel |
|---|---|---|
| Python used | 3.12.14 | 3.13.7 |
| cryptography | 46.0.7 | 46.0.7 |
| Independent pipx wheel install | PASS | PASS |
| init and inactive templates | PASS | PASS |
| Idempotent init, atomic writes, private permissions | PASS | PASS |
| Paths with spaces / generated OpenSSH config | PASS | PASS |
| Exact item UUID, key and scope validation | PASS | PASS |
| Real ssh-agent load / signature / explicit lock | PASS | PASS |
| Real OpenSSH descriptor handoff on nondefault port | PASS | PASS |
| v2 cold recovery to empty home, real agents/signatures | PASS | PASS |
| v1 parsing including legacy metadata | PASS | PASS |
| Wrong password / tampering / unsafe paths rejected | PASS | PASS |
| Optional MCP profile separation / ACL / stdio tools | PASS | PASS |
| doctor with official bw 2026.10.1 | PASS | PASS |
| Real vault login, 2FA, online CRUD | NOT TESTED | NOT TESTED |
| Apple Silicon | NOT TESTED | NOT TESTED |

Tests are run from the source archive with the wheel installed in isolated pipx
environments. No test needs vault credentials. The checked-in workflow defines
Linux/macOS Python 3.11/3.13 jobs, but hosted GitHub Actions have not run before
publication. A passing Intel Mac test does not prove Apple Silicon support.
The final local suite contains 19 tests on each platform; no real online
authentication or server-side membership change is included in those tests.

## Existing installation isolation

The pre-existing local helper, MCP code, SSH connection registry and generated
configuration are outside this repository. Their SHA-256 values were recorded
before development and compared afterwards. Pipx home/bin directories were
isolated and not added to PATH. No current sessions, key material or running
tunnels were changed. Public build artifacts contain no copied personal files.

## Mac prerequisite setup note

An initial Homebrew attempt to install Python/pipx started a source build on an
unsupported Intel configuration. Only its tracked process tree was stopped.
It had already upgraded `pkgconf` to 3.0.11 and `ca-certificates` to 2026-11-05;
the latter reported an unsuccessful post-install step. These host package
changes were not rolled back automatically. Python, pipx and bw tests then ran
entirely in a temporary environment using standalone Python and an isolated Node
distribution. No shell configuration or permanent Python command was installed.

## Limitations

- A normal SSH unlock is intentionally persistent until explicit lock, including
  across reboot. Protect the local account and sensitive session file.
- Remote revocation cannot erase an offline key or archive. Existing SSH sessions
  remain open after lock.
- MCP revisions are pre-write checks, not an atomic server-side transaction.
- Backups fail rather than silently skip unavailable keys. They are not full vault
  exports or server backups. Store independent copies and passwords yourself.
- A restore I/O failure can leave a partially copied **new** configuration. Existing
  configuration is never overwritten; inspect or use another fresh home to retry.
- v1 archives missing legacy metadata require that metadata separately.
