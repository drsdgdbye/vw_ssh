"""Local OpenSSH agents and descriptor handoff; no SSH protocol implementation."""
import array
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid

from cryptography.hazmat.primitives import serialization

from .storage import Error, name, private_dir, read_json, write_file


def fingerprint(public):
    try:
        blob = base64.b64decode(public.split()[1], validate=True)
        return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    except (ValueError, IndexError, TypeError):
        raise Error('Invalid public SSH key.') from None


def validate_material(material, expected):
    try:
        key = serialization.load_ssh_private_key(material['privateKey'].encode(), password=None)
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                               serialization.PublicFormat.OpenSSH).decode()
        if public.split()[:2] != material['publicKey'].split()[:2] or fingerprint(public) != expected:
            raise Error('Private/public key or fingerprint mismatch.')
    except (ValueError, TypeError, KeyError):
        raise Error('Invalid SSH private/public key material.') from None


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise Error('Ports must be integers from 1 to 65535.')
    return value


def validate_connection(connection, *, identity=False):
    required = {'keyName', 'itemId', 'fingerprint'} | (set() if identity else {'host', 'user'})
    allowed = required | (set() if identity else {'port', 'forwards'})
    if not isinstance(connection, dict) or not required <= connection.keys() or connection.keys() - allowed:
        raise Error('Invalid connection fields; use the templates.')
    name(connection['keyName'])
    try:
        if str(uuid.UUID(connection['itemId'])) != connection['itemId']:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Error('itemId must be an exact canonical UUID, not a search string.') from None
    if not isinstance(connection['fingerprint'], str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', connection['fingerprint']):
        raise Error('A SHA256 SSH fingerprint is required.')
    if not identity:
        if not isinstance(connection['host'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:%_-]*', connection['host']):
            raise Error('Invalid host; use a hostname, IPv4 or unbracketed IPv6 address.')
        name(connection['user'])
        port(connection.get('port', 22))
        if not isinstance(connection.get('forwards', []), list):
            raise Error('forwards must be a list.')
        for forward in connection.get('forwards', []):
            if not isinstance(forward, dict) or set(forward) != {'local', 'remote'}:
                raise Error('Invalid forward fields.')
            port(forward['local'])
            if not isinstance(forward['remote'], str) or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9a-fA-F:]+\]):[0-9]+', forward['remote']):
                raise Error('Forward destination must be host:port or [IPv6]:port.')
            port(int(forward['remote'].rsplit(':', 1)[1]))
    return connection


def inventory(paths):
    data = read_json(paths.config / 'connections.json')
    if not isinstance(data, dict):
        raise Error('connections.json must map aliases to profiles.')
    return data


def connections(paths):
    data = inventory(paths)
    used = {}
    for alias, connection in data.items():
        name(alias)
        validate_connection(connection)
        signature = connection['itemId'], connection['fingerprint']
        if connection['keyName'] in used and used[connection['keyName']] != signature:
            raise Error('Profiles sharing keyName must select the same item and fingerprint.')
        used[connection['keyName']] = signature
    return data


def legacy(paths):
    path = paths.config / 'legacy-identity.json'
    return validate_connection(read_json(path), identity=True) if path.exists() else None


def agent_env(paths, connection):
    sock = paths.runtime / (name(connection['keyName']) + '.sock')
    if len(os.fsencode(sock)) > 100:
        raise Error('SSH socket path too long; use a shorter XDG_RUNTIME_DIR.')
    return dict(os.environ, SSH_AUTH_SOCK=str(sock))


@contextmanager
def agent_lock(paths):
    private_dir(paths.runtime)
    with (paths.runtime / '.lock').open('a') as handle:
        os.chmod(handle.name, 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def listing(paths, connection):
    return subprocess.run(['ssh-add', '-l'], env=agent_env(paths, connection),
                          text=True, capture_output=True, timeout=10)


def load_material(paths, connection, material, *, ttl=None):
    validate_material(material, connection['fingerprint'])
    env = agent_env(paths, connection)
    check = listing(paths, connection)
    if check.returncode == 2:
        sock = paths.runtime / (connection['keyName'] + '.sock')
        sock.unlink(missing_ok=True)
        result = subprocess.run(['ssh-agent', '-a', str(sock), '-s'], capture_output=True,
                                text=True, check=True, timeout=10)
        match = re.search(r'SSH_AGENT_PID=(\d+)', result.stdout)
        if not match:
            raise Error('SSH agent startup failed.')
        write_file(paths.runtime / (connection['keyName'] + '.pid'), match[1])
    elif check.returncode not in {0, 1}:
        raise Error('Unable to query managed SSH agent.')
    result = subprocess.run(['ssh-add', *(['-t', str(ttl)] if ttl is not None else []), '-'],
        input=material['privateKey'] + '\n', env=env, capture_output=True, text=True, timeout=15)
    if result.returncode or connection['fingerprint'] not in listing(paths, connection).stdout:
        raise Error('SSH key load failed; details suppressed.')
    (paths.runtime / (connection['keyName'] + '.failed')).unlink(missing_ok=True)


def ensure(paths, connection):
    validate_connection(connection, identity='host' not in connection)
    from .vault import Vault
    with agent_lock(paths):
        marker = paths.runtime / (connection['keyName'] + '.failed')
        try:
            check = listing(paths, connection)
            if check.returncode == 0 and connection['fingerprint'] in check.stdout:
                marker.unlink(missing_ok=True)
                return
            vault = Vault(paths)
            material = vault.ssh_key(connection)
            session = read_json(paths.state / 'session.json')
            ttl = None if session['expires'] is None else int(session['expires'] - time.time())
            if ttl is not None and ttl < 1:
                raise Error('Session expired.')
            load_material(paths, connection, material, ttl=ttl)
        except Exception:
            write_file(marker, 'unavailable\n')
            raise


def load_all(paths):
    for connection in inventory(paths).values():
        try:
            ensure(paths, connection)
        except Exception:
            pass


def status(paths):
    for alias, connection in inventory(paths).items():
        try:
            name(alias)
            validate_connection(connection)
            result = listing(paths, connection)
            state = 'loaded' if result.returncode == 0 and connection['fingerprint'] in result.stdout else 'unloaded'
            if (paths.runtime / (connection['keyName'] + '.failed')).exists():
                state = 'unavailable'
            print(alias, state, connection['fingerprint'])
        except (Error, KeyError, TypeError, OSError, subprocess.SubprocessError):
            print(str(alias).encode('unicode_escape').decode(), 'unavailable')


def lock(paths):
    from .vault import Vault
    with agent_lock(paths):
        (paths.state / 'session.json').unlink(missing_ok=True)
        failed = False
        for sock in paths.runtime.glob('*.sock'):
            result = subprocess.run(['ssh-add', '-D'], env=dict(os.environ, SSH_AUTH_SOCK=str(sock)),
                                    capture_output=True, timeout=10)
            failed |= result.returncode not in {0, 2}
        for marker in paths.runtime.glob('*.failed'):
            marker.unlink(missing_ok=True)
        # A recovered offline home has no CLI login to lock.
        if (paths.config / 'config.json').exists() and (paths.state / 'bw').exists():
            Vault(paths).run(['lock'], authenticated=False)
        if failed:
            raise Error('Session removed, but an SSH agent could not be cleared; inspect status.')
    print('Locked. Existing SSH connections remain open.')


def config_text(paths, data):
    command = [sys.executable, '-m', 'vw_ssh.cli']
    if os.environ.get('VW_SSH_HOME'):
        command += ['--home', str(Path(os.environ['VW_SSH_HOME']).expanduser().resolve())]
    command += ['--profile', paths.profile]
    lines = ['# Generated by vw-ssh config. Edit connections.json, not this file.']
    def quote(value):
        value = str(value)
        if any(c in value for c in '\r\n\0"'):
            raise Error('Unsupported character in local path.')
        return '"' + value.replace('\\', '\\\\').replace('%', '%%') + '"'
    for alias, c in data.items():
        lines += [f'Host {alias}', f'    HostName {c["host"]}', f'    User {c["user"]}',
            f'    Port {c.get("port", 22)}', '    BatchMode yes', '    IdentitiesOnly yes',
            '    StrictHostKeyChecking yes', '    ForwardAgent no',
            f'    UserKnownHostsFile {quote(paths.config / "known_hosts")}',
            f'    IdentityFile {quote(paths.config / "public" / (c["keyName"] + ".pub"))}',
            f'    IdentityAgent {quote(agent_env(paths, c)["SSH_AUTH_SOCK"])}',
            '    ProxyCommand ' + shlex.join(command + ['proxy', alias]).replace('%', '%%'),
            '    ProxyUseFdpass yes', '    ServerAliveInterval 30', '    ServerAliveCountMax 3',
            '    ControlMaster no']
        if c.get('forwards'):
            lines += ['    SessionType none', '    RequestTTY no', '    ExitOnForwardFailure yes']
            lines += [f'    LocalForward 127.0.0.1:{f["local"]} {f["remote"]}' for f in c['forwards']]
        lines.append('')
    return '\n'.join(lines) + '\n'


def generate_config(paths):
    from .vault import Vault
    data = connections(paths)
    vault = None
    for c in data.values():
        path = paths.config / 'public' / (c['keyName'] + '.pub')
        if not path.exists():
            vault = vault or Vault(paths)
            material = vault.ssh_key(c)
            write_file(path, material['publicKey'].strip() + '\n')
        if fingerprint(path.read_text()) != c['fingerprint']:
            raise Error('Local public key fingerprint mismatch; inspect before replacing.')
    write_file(paths.config / 'ssh_config', config_text(paths, data))
    print('SSH config generated. Add this global line before Host blocks in ~/.ssh/config:')
    print('Include "' + str(paths.config / 'ssh_config') + '"')


def proxy(paths, connection):
    ensure(paths, connection)
    with socket.create_connection((connection['host'], connection.get('port', 22)), timeout=15) as sock:
        sock.settimeout(None)
        with socket.socket(fileno=os.dup(1)) as output:
            output.sendmsg([b'\0'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [sock.fileno()]))])
