"""Private local files and portable application paths."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


class Error(Exception):
    """Safe message for the terminal; never include secret payloads."""


def private_dir(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Error('Unsafe private directory; check ownership, symlinks and permissions.')
    return path


def read_json(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Error('Unsafe configuration file; expected an owned regular file with mode 0600.')
    return json.loads(path.read_text())


def write_file(path, content, *, replace=True):
    private_dir(path.parent)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, mode='w', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json(path, value, *, replace=True):
    write_file(path, json.dumps(value, indent=2) + '\n', replace=replace)


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}', value):
        raise Error('Names must be 1–48 letters, digits, underscores or hyphens.')
    return value


class Paths:
    def __init__(self, profile='ssh'):
        if profile not in {'ssh', 'agent'}:
            raise Error('Unknown profile.')
        self.profile = profile
        override = os.environ.get('VW_SSH_HOME')
        if override:
            root = Path(override).expanduser().resolve()
            config, state, data = root / 'config', root / 'state', root / 'data'
        elif sys.platform == 'darwin':
            root = Path.home() / 'Library/Application Support/vw-ssh'
            config, state, data = root / 'config', root / 'state', root / 'data'
        else:
            config = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'vw-ssh'
            state = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'vw-ssh'
            data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share')) / 'vw-ssh'
        self.config, self.state, self.data = (p / profile for p in (config, state, data))
        digest = hashlib.sha256(str(self.config).encode()).hexdigest()[:12]
        base = Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp')) if sys.platform != 'darwin' else Path('/tmp')
        self.runtime = base / f'vws-{os.getuid()}-{digest}'

    def create(self):
        for path in [self.config, self.state, self.data, self.config / 'public', self.config / 'templates']:
            private_dir(path)
