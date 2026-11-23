# vw-ssh

SSH keys from a Vaultwarden vault, loaded into local OpenSSH agents. Linux and
macOS. MIT licensed. Python 3.11+. No Windows support.

The SSH utility works on its own. An AI agent, MCP server and OpenCode are **not
required**. Optional MCP uses a separate account profile and explicit collection
allowlist. No server, email, organization, host or connection is preconfigured.

## How it works

```text
vw-ssh -> official bw CLI -> HTTPS Vaultwarden
                     |
               private key in memory
                     v
             managed ssh-agent
                     ^
ssh ALIAS -> generated SSH config -> TCP socket handed directly to OpenSSH

encrypted recovery archive -> offline restore -> managed ssh-agent
```

OpenSSH still verifies server host keys and performs SSH encryption. The helper
hands over the connected socket with `ProxyUseFdpass`; there is no Python TCP
relay in the data path. Keys are never written as plaintext private-key files.
The CLI session is sensitive and stored privately on disk, not in shell arguments.

## Install

Install Python 3.11+ and pipx using your OS package manager. For example:

```sh
# macOS (existing Homebrew)
brew install python@3.13 pipx
pipx ensurepath

# Debian/Ubuntu with Python 3.11+ available
sudo apt install pipx openssh-client
pipx ensurepath
```

Install the wheel downloaded from [GitHub Releases](https://github.com/drsdgdbye/vw_ssh/releases/tag/v0.1.0):

```sh
pipx install ./vw_ssh-0.1.0-py3-none-any.whl
vw-ssh help
```

Or install directly from the pinned GitHub tag:

```sh
pipx install "git+https://github.com/drsdgdbye/vw_ssh.git@v0.1.0"
```

For GitHub SSH access, use `git+ssh://git@github.com/drsdgdbye/vw_ssh.git@v0.1.0`.
Alternatively clone the repository, check out the release tag, then `pipx install .`.
Do not install an unreviewed branch with access to your vault.

Install the official **Bitwarden Password Manager CLI** (`bw`) separately:
<https://bitwarden.com/help/cli/>. It is not the Secrets Manager CLI. The tested
version for this release is 2026.10.1. For npm installations:

```sh
npm install -g @bitwarden/cli@2026.10.1
```

An official native `bw` executable also works; Node is only needed for the npm
build. OpenSSH `ssh`, `ssh-agent`, `ssh-add`, `ssh-keygen` and `ProxyUseFdpass`
support are required. Run `vw-ssh doctor` to inspect prerequisites. Node builds
use a private compile cache when supported by Node; native CLI builds ignore it.

## First run

```sh
vw-ssh init
vw-ssh doctor
vw-ssh login
vw-ssh discover
```

`init` asks for your HTTPS vault URL and email. It creates a private, isolated CLI
profile, empty connection registry and **inactive example templates**. Repeating
`init` preserves existing files. `--bw /absolute/path/to/bw` selects the CLI.
The master password and CLI-supported 2FA are entered locally in your terminal.
No GUI/desktop application is required. No master password is saved.

If you are already logged in, use `vw-ssh unlock`. The normal SSH profile remains
unlocked **until explicit `vw-ssh lock`**. Its session file survives reboot; agent
memory does not. A separate `--profile agent` session expires after 12 hours.

Global options come **before** commands:

```sh
vw-ssh --home /private/test-home init
vw-ssh --home /private/test-home status
vw-ssh --profile agent init
```

`VW_SSH_HOME` is equivalent to `--home`. It isolates all persistent files and
selects a different runtime socket namespace. Never point it at another app's
configuration. `help` works before configuration or vault access.

## Files and directories

`vw-ssh doctor` prints exact paths. Normal defaults:

| Kind | Linux | macOS |
|---|---|---|
| Configuration | `$XDG_CONFIG_HOME/vw-ssh/ssh` or `~/.config/vw-ssh/ssh` | `~/Library/Application Support/vw-ssh/config/ssh` |
| State | `$XDG_STATE_HOME/vw-ssh/ssh` or `~/.local/state/vw-ssh/ssh` | `~/Library/Application Support/vw-ssh/state/ssh` |
| Data/archives | `$XDG_DATA_HOME/vw-ssh/ssh` or `~/.local/share/vw-ssh/ssh` | `~/Library/Application Support/vw-ssh/data/ssh` |
| Runtime | private short `vws-UID-HASH` under `$XDG_RUNTIME_DIR` or `/tmp` | private short `/tmp/vws-UID-HASH` |

With `--home DIR`: `DIR/config/ssh`, `DIR/state/ssh`, `DIR/data/ssh`.
The optional agent profile uses `agent` in place of `ssh` and different sockets.

| File | Purpose | Created by |
|---|---|---|
| `config.json` | Server, email, CLI command, optional scopes (inside selected profile directory) | init |
| `connections.json` | Alias -> host/user/port/key reference mapping | init, then edited by user |
| `templates/*.example.json` | Examples, never active profiles | init |
| `known_hosts` | Independently verified server host keys | init, then populated by user |
| `public/KEY.pub` | Public key matching a pinned fingerprint | config or recovery |
| `ssh_config` | Machine-specific generated OpenSSH configuration | config or recovery |
| `legacy-identity.json` | Optional identity without a destination host | user |
| State `bw/` | Isolated official CLI encrypted cache and authentication state | login/sync |
| State `session.json` | Sensitive decryption session; 0600 | login/unlock |
| State `node-compile-cache/` | Compiled CLI code, not vault exports | CLI environment |
| Runtime `*.sock`, `*.pid`, `*.failed`, `.lock` | Managed agents, errors, process coordination | load/recover |
| Data `recovery/*.json.enc` | Versioned encrypted copies | backup |

Directories are 0700 and generated files 0600. Do not commit personal runtime
files or archives. Same-Unix-user processes are not a security boundary.

## Add a new connection

1. Create an SSH-key item in your vault. For personal use a human account is fine;
   organizations and an agent account are not required. Install the **public**
   key in the destination user's `authorized_keys` using your existing trusted
   access. The utility does not change remote accounts or revoke keys.
2. `vw-ssh discover` prints only SSH item IDs, names and SHA256 fingerprints.
   Pick the exact item UUID, not a search term or a guessed name.
3. Copy the fields from `templates/connection.example.json` into
   `connections.json`. Replace every placeholder. Example structure:

```json
{
  "example-server": {
    "host": "server.example.com",
    "user": "deploy",
    "port": 22,
    "keyName": "example-key",
    "itemId": "00000000-0000-4000-8000-000000000001",
    "fingerprint": "SHA256:REPLACE_WITH_REAL_FINGERPRINT_FROM_DISCOVER"
  }
}
```

The displayed UUID and fingerprint are illustrative, not runnable credentials.
Aliases, key names and usernames accept letters/digits/underscore/hyphen, max 48
characters. Multiple aliases may share a `keyName` only for the same item and
fingerprint. Port defaults to 22. IPv6 hosts are unbracketed in `host`.

4. Put **verified** host keys in the managed `known_hosts` file. A non-default
   port uses `[host]:port`. `ssh-keyscan` collects candidates; compare the
   fingerprint through an independent trusted channel before trusting them.
5. Run `vw-ssh config`. It obtains missing public keys from the vault, checks
   fingerprints and generates local paths. Add the printed `Include` line in
   the **global section before any `Host` blocks** of `~/.ssh/config` (preserve a
   copy first). The utility does not edit your existing SSH configuration.
6. Check:

```sh
vw-ssh doctor
vw-ssh load example-server
ssh example-server
```

`scp` and `rsync` using these aliases use the same keys. Never put private keys,
passwords or arbitrary `ProxyCommand` text in connection profiles.

### Existing keys, legacy identity and tunnels

For an existing key, add it as an SSH item using a trusted vault client, verify
its public fingerprint, then follow the same steps. Source private files are
**never deleted** by this package. Establish a verified backup and test new SSH
access before deciding independently whether to remove any old files.

For a key without a destination profile, copy the legacy template into
`legacy-identity.json` and fill its item UUID/fingerprint. `vw-ssh load legacy`
loads it; `load all` only covers `connections.json`. It is included in backup.
There is no global `Host *` fallback automatically installed.

For tunnels, use `templates/tunnel.example.json`. Local listeners are always
bound to `127.0.0.1`; remote targets accept `host:port` or `[IPv6]:port`. Profiles
with forwards open transport-only SSH sessions; do not bind a second tunnel to
an occupied port. Automatic reconnection is not provided.

## Daily use and locking

```sh
vw-ssh unlock
vw-ssh load all
vw-ssh status
ssh example-server
vw-ssh lock
```

Loading is also automatic on the first SSH connection. Already loaded keys work
offline without calling the vault. `load all` silently skips failed/invalid
profiles and continues; inspect `status` afterwards:

- `loaded`: the pinned identity is present in its agent.
- `unloaded`: it is not loaded.
- `unavailable`: the last load failed or the profile is invalid. This is **not**
  a remote server health check. Successful load or lock clears the failure marker.

`lock` removes the profile's session and clears **only its managed agents**.
It does not close established SSH sessions/tunnels, lock the desktop vault, clear
another profile, or erase keys already copied elsewhere. Reboot clears agent
memory, not the persistent no-expiry SSH session. Use explicit lock.

`sync` refreshes the encrypted CLI cache when online. Ordinary SSH loading does
not require a network sync, but first login and cache updates do. Server-side
revocation cannot erase previously obtained offline keys.

## Move connections to another machine — manual procedure

The utility never transfers anything automatically.

1. Source: run `doctor`; select `connections.json`, `public/`, verified
   `known_hosts`, and optional `legacy-identity.json` from its configuration path.
   These contain no private keys, but reveal infrastructure; use a trusted channel.
2. Destination: install the package and `bw`; run `init`, `login`, `unlock` for
   the intended account/server. Obtain vault access independently.
3. Place the selected files in the destination configuration directory (0700
   directories/0600 files), reviewing conflicts rather than overwriting blindly.
4. Run `config` to regenerate machine-specific paths and add its Include locally.
5. Run `doctor`, `load all`, `status`, then test selected aliases.

Do **not** transfer `session.json`, CLI `bw/`, compile cache, agents/sockets/PIDs,
or source-machine `ssh_config`. Do not blindly copy `config.json`: the destination
may use another CLI path, account or permissions. For a different vault/account,
item IDs may change; run `discover` and explicitly remap profiles by fingerprint.

## Recovery lifecycle

### Create and update

```sh
vw-ssh sync
vw-ssh backup
vw-ssh recover --check /path/to/archive.json.enc
```

`backup` performs its own sync, gathers every configured SSH identity and optional
legacy identity, verifies private/public fingerprints, and requests an independent
password (at least 16 characters, twice). It writes a **new** versioned encrypted
archive atomically, reads it back and decrypts it to verify the saved bytes. A
failed key aborts the backup; there is no silent partial backup. Existing archives
are never replaced, including with `--output`.

Create a new archive after key rotation, adding/removing connections, changes to
host trust or destination settings. Retain previous successful versions. Copy
encrypted archives to independent storage; store the password separately from
the vault and machine. No timer or stored backup password is installed.

v2 contains portable connection/configuration metadata, verified host keys, public
keys and encrypted private SSH keys. It excludes master passwords, sessions,
CLI authentication caches and source-machine paths. Encryption: Scrypt
`N=131072,r=8,p=1`, random 16-byte salt, AES-256-GCM with random 12-byte nonce and
authenticated format name. There is a 32 MiB archive limit. This is an SSH-key
copy, **not** a complete vault/server backup; it excludes memberships,
`authorized_keys`, login items, attachments and other vault data.

### Restore without the server

Install Python/package/OpenSSH beforehand; offline restore does not need `bw`,
Node, network, login or MCP. `cryptography` must already be installed by pipx.

```sh
# Validate only. No files changed and no agents started.
vw-ssh recover --check /path/to/archive.json.enc

# Restore into a new, empty application home and load keys.
vw-ssh --home /private/recovered-vw-ssh recover --restore /path/to/archive.json.enc
vw-ssh --home /private/recovered-vw-ssh status
```

Review restored metadata and add the generated Include before connecting. Private
keys only enter agents, with a 12-hour recovery lifetime. Without `--restore`,
`recover FILE` only loads keys into this home's agents; use it when configuration
already exists. `--restore` refuses existing configuration, even an initialized
empty one: select a fresh home and merge manually. Invalid password, modified
ciphertext, mismatched keys and unsafe names are rejected before restoration.
Online access after recovery requires a new login; no session is in the archive.

v1 archives can be read. Older v1 archives that omitted legacy metadata require
a private `legacy-identity.json` in the selected source configuration; they cannot
reconstruct omitted metadata. Prefer creating v2 while the vault is available.
v1 has no vault settings, so offline SSH recovery can work but a later online
login requires `init`.

After a drill: `vw-ssh --home /private/recovered-vw-ssh lock`. Do not delete or
replace the source archive until an independently stored replacement is verified.

## Optional MCP / AI agents

Skip this section for ordinary SSH use. No MCP service starts during installation
or normal commands. MCP uses stdio only, not an HTTP endpoint.

```sh
vw-ssh --profile agent init
vw-ssh --profile agent login
vw-ssh --profile agent discover --scopes
```

Use a dedicated non-owner agent account with access only to intended collections.
In **agent** `config.json`, set `scopes` to named organization/collection pairs:

```json
{
  "team": {
    "organizationId": "00000000-0000-4000-8000-000000000002",
    "collectionId": "00000000-0000-4000-8000-000000000003"
  }
}
```

Replace these examples with verified real IDs. They are the **value of `scopes`**,
not the whole config file. No scopes means MCP CRUD refuses access. Only items
in exactly one configured collection of its matching organization are allowed;
personal-vault and multi-collection items are rejected. The SSH profile's account,
session, cache and keys are separate. Run `vw-ssh mcp serve` from an MCP client.
Example optional OpenCode entry:

```json
{
  "mcp": {
    "vw-ssh": {
      "type": "local",
      "command": ["/absolute/path/from-command-v-vw-ssh", "mcp", "serve"],
      "enabled": true
    }
  }
}
```

This is an example, not an installed configuration. Preserve existing settings
and restart the client after configuring it. Unlock/lock the agent profile with
`vw-ssh --profile agent unlock` / `vw-ssh --profile agent lock`. Agent sessions
expire after 12 hours; SSH unlock never unlocks MCP automatically.

Tools: metadata-only search, selected login read, create in explicit scope, patch
with revision check, trash delete with revision check. No shell/export/purge/move
or SSH private-key tools. Reads expose username/password/notes to the model and
possibly client history. Record text is untrusted data, not instructions.
Patches preserve other fields. Revision checks detect stale reads but are not an
atomic server-side compare-and-swap against concurrent clients. Each operation
checks session/server/account/scope and syncs; failures are returned without CLI
stderr or payloads. An in-flight call may finish during lock; stop the client for
immediate process termination. Offline copies cannot be revoked remotely.

## Upgrade, diagnostics, uninstall

`pipx upgrade vw-ssh` or install a reviewed newer release. Then `vw-ssh config` to
regenerate Python/installation paths. Keep a verified archive before changes. A
copied old `ssh -F` configuration must be regenerated with its matching helper.
Run `doctor` and inspect `status`; do not enable shell tracing around passwords.
CLI error bodies are suppressed deliberately. `lock` before returning to an older
version if session formats differ. No daemon/autostart or remote server changes
are installed.

Uninstall: lock each used profile, remove only the Include you added, then
`pipx uninstall vw-ssh`. User configurations and encrypted archives are retained
for explicit manual removal. Do not delete another application's directories.

## Development and verification

```sh
python3 -m venv .venv
.venv/bin/pip install -e . build
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/release.py
```

Tests use generated keys, temporary application homes and only their own agents.
They must not access a real vault or modify a user's SSH config. CI runs on Linux
and macOS. See `VERIFICATION.md` for actual release checks and limitations.
