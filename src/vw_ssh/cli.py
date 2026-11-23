"""Console commands. MCP is imported only when explicitly requested."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from importlib.resources import files

from . import __version__
from .storage import Error, Paths, write_file, write_json

GUIDE = '''
Daily use:
  vw-ssh init                 Create private configuration and inactive templates.
  vw-ssh login                Login with email/password and CLI-supported 2FA.
  vw-ssh unlock               Unlock until explicit lock (no time limit).
  vw-ssh discover             Show SSH record IDs/names/fingerprints, no secrets.
  vw-ssh discover --scopes    Show organization/collection IDs for optional allowlists.
  vw-ssh config               Validate profiles, obtain missing public keys, generate SSH config.
  vw-ssh load ALIAS|all        Load one/all connections; all silently skips failures.
  vw-ssh status               loaded / unloaded / unavailable (not remote host health).
  vw-ssh lock                 Clear managed agents and session; existing SSH stays open.
  vw-ssh sync                 Refresh the isolated encrypted CLI cache.
  vw-ssh doctor               Check prerequisites and show local paths.
  vw-ssh backup               Create a new verified, password-encrypted recovery archive.
  vw-ssh recover --check FILE Validate an archive without loading keys.
  vw-ssh recover FILE         Load archived keys offline for 12 hours.
  vw-ssh recover --restore FILE  Also restore portable config in a fresh --home.
  vw-ssh mcp serve            Optional agent-profile MCP; never started automatically.

Adding connections:
  1. Create an SSH-key item in your vault. Install its PUBLIC key on the server.
  2. Run discover. Select the exact item UUID and SHA256 fingerprint.
  3. Copy fields from templates/connection.example.json into connections.json.
     Use templates/tunnel.example.json for loopback-only local forwards.
     Example: alias "example", host "server.example.com", user "deploy", port 22.
     keyName can be reused only for the same item/fingerprint. Never store private keys here.
  4. Verify server host keys independently and place them in known_hosts.
     ssh-keyscan only collects candidates; it does not establish trust.
  5. Run config; add its Include line BEFORE Host blocks in ~/.ssh/config.
     Then: vw-ssh load example; ssh example
  Use load legacy for an optional legacy-identity.json; it is not part of load all.

Moving between machines (manual, never automatic):
  Run doctor for source paths. Copy connections.json, public/, known_hosts and optional
  legacy-identity.json through a trusted channel. On destination install, init, login,
  unlock, place those files and run config. Recheck trust and item IDs if vault changed.
  Do NOT copy session.json, bw/, sockets, PID files or generated ssh_config.
  --home DIR isolates every persistent file; socket names are derived from that home.

Recovery lifecycle:
  After adding/changing a key or host trust: sync, backup, recover --check FILE.
  Keep older archives and a copy outside this machine; password outside the vault.
  Clean-machine example: vw-ssh --home /private/new-home recover --restore FILE
  Review restored profiles, add the generated Include, test SSH, then lock.
  Existing config is never overwritten by --restore; use a fresh home and merge manually.
  Recovery is not a server backup and does not restore account memberships or authorized_keys.

Profiles:
  Default "ssh" is independent of "agent". --profile agent init/login configures MCP
  separately; set explicit organization/collection scopes. Agent unlock lasts 12 hours.
  The normal SSH session has no expiry and survives reboot until lock removes it.
  Same-OS-user processes are not a security boundary. Reboot removes agent memory only.
'''


def initialize(paths, server=None, email=None, bw=None):
    from .vault import validate_config
    paths.create()
    path = paths.config / 'config.json'
    if not path.exists():
        config = validate_config({'server': (server or input('Vault HTTPS URL: ')).rstrip('/'),
            'email': email or input('Account email: '), 'bw': bw or shutil.which('bw') or 'bw', 'scopes': {}})
        write_json(path, config, replace=False)
    for filename, content in [('connections.json', '{}\n'), ('known_hosts', '')]:
        target = paths.config / filename
        if not target.exists():
            write_file(target, content, replace=False)
    for template in files('vw_ssh').joinpath('templates').iterdir():
        target = paths.config / 'templates' / template.name
        if not target.exists():
            write_file(target, template.read_text(), replace=False)
    print('Initialized:', paths.config)
    print('Templates are inactive. Next: login, discover, edit connections.json, config.')


def doctor(paths):
    checks = []
    for executable in ['ssh', 'ssh-agent', 'ssh-add', 'ssh-keygen']:
        found = shutil.which(executable)
        print(executable + ':', found or 'MISSING')
        checks.append(bool(found))
    if shutil.which('ssh'):
        result = subprocess.run(['ssh', '-G', '-F', '/dev/null', '-o', 'ProxyUseFdpass=yes', 'example.invalid'],
                                text=True, capture_output=True, timeout=10)
        ok = result.returncode == 0 and 'proxyusefdpass yes' in result.stdout
        print('ProxyUseFdpass:', 'PASS' if ok else 'FAIL')
        checks.append(ok)
    for label in ['config', 'state', 'data', 'runtime']:
        print(label + ':', getattr(paths, label))
    config_file = paths.config / 'config.json'
    if config_file.exists():
        from .vault import Vault
        vault = Vault(paths)
        bw = shutil.which(vault.config['bw'])
        print('bw:', bw or 'MISSING')
        checks.append(bool(bw))
        if bw:
            result = subprocess.run([bw, '--version'], capture_output=True, text=True, timeout=30)
            print('bw version:', result.stdout.strip() if result.returncode == 0 else 'FAILED')
            checks.append(result.returncode == 0)
        from .ssh import connections, legacy
        connections(paths)
        legacy(paths)
        print('Connection schema: PASS')
    else:
        print('Configuration: not initialized (offline recovery is still available).')
    if not all(checks):
        raise Error('Prerequisites incomplete; see README installation instructions.')


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='SSH keys from Vaultwarden, without a required agent or MCP.',
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=GUIDE)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--home', help='Isolated application root (or VW_SSH_HOME)')
    parser.add_argument('--profile', choices=['ssh', 'agent'], default='ssh')
    sub = parser.add_subparsers(dest='action')
    sub.add_parser('help')
    init = sub.add_parser('init')
    init.add_argument('--server')
    init.add_argument('--email')
    init.add_argument('--bw')
    for action in ['login', 'unlock', 'lock', 'sync', 'doctor', 'config', 'status']:
        sub.add_parser(action)
    discover = sub.add_parser('discover')
    discover.add_argument('--scopes', action='store_true')
    load = sub.add_parser('load')
    load.add_argument('alias')
    proxy = sub.add_parser('proxy')
    proxy.add_argument('alias')
    backup = sub.add_parser('backup')
    backup.add_argument('--output')
    recovery = sub.add_parser('recover')
    recovery.add_argument('file')
    mode = recovery.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--restore', action='store_true')
    mcp = sub.add_parser('mcp')
    mcp.add_argument('mode', choices=['serve'])
    args = parser.parse_args(argv)
    if args.home:
        os.environ['VW_SSH_HOME'] = str(Path(args.home).expanduser().resolve())
    paths = Paths('agent' if args.action == 'mcp' else args.profile)
    if args.action in {None, 'help'}:
        parser.print_help()
    elif args.action == 'init':
        initialize(paths, args.server, args.email, args.bw)
    elif args.action == 'doctor':
        doctor(paths)
    elif args.action == 'mcp':
        from .mcp import serve
        serve(paths)
    elif args.action in {'backup', 'recover'}:
        from . import recovery
        if args.action == 'backup':
            recovery.backup(paths, args.output)
        else:
            recovery.recover(paths, args.file, check=args.check, restore=args.restore)
    elif args.action in {'login', 'unlock', 'discover', 'sync'}:
        from .vault import Vault
        vault = Vault(paths)
        if args.action in {'login', 'unlock'}:
            vault.authenticate(args.action)
        elif args.action == 'discover':
            print(json.dumps(vault.discover(scopes=args.scopes), indent=2))
        else:
            vault.check()
            vault.run(['sync'])
            print('Encrypted CLI cache synchronized.')
    else:
        from . import ssh
        if args.action == 'config':
            ssh.generate_config(paths)
        elif args.action == 'status':
            ssh.status(paths)
        elif args.action == 'lock':
            ssh.lock(paths)
        elif args.action == 'load' and args.alias == 'all':
            ssh.load_all(paths)
        else:
            data = ssh.inventory(paths)
            connection = ssh.legacy(paths) if args.alias == 'legacy' and args.action == 'load' else data.get(args.alias)
            if connection is None:
                raise Error('Unknown connection alias.')
            if args.action == 'proxy':
                ssh.proxy(paths, connection)
            else:
                ssh.ensure(paths, connection)
                print(args.alias + ': loaded')


def entrypoint():
    try:
        main()
    except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('vw-ssh: ' + (str(exc) if isinstance(exc, Error) else 'Operation failed; details suppressed. Run doctor.'), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == '__main__':
    entrypoint()
