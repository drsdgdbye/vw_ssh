"""Official Password Manager CLI and independent local sessions."""
import base64
import getpass
import os
import subprocess
import time
from urllib.parse import urlsplit

from .storage import Error, private_dir, read_json, write_json


def validate_config(config):
    if not isinstance(config, dict) or set(config) != {'server', 'email', 'bw', 'scopes'}:
        raise Error('Invalid config.json fields.')
    url = urlsplit(config['server'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise Error('Use an HTTPS server URL without credentials, query or fragment.')
    if not isinstance(config['email'], str) or '@' not in config['email'] or any(c.isspace() for c in config['email']):
        raise Error('A valid account email is required.')
    if not isinstance(config['bw'], str) or not config['bw']:
        raise Error('A bw executable is required.')
    if not isinstance(config['scopes'], dict):
        raise Error('Scopes must be a mapping of names to organization/collection pairs.')
    for scope, pair in config['scopes'].items():
        from .storage import name
        name(scope)
        if not isinstance(pair, dict) or set(pair) != {'organizationId', 'collectionId'} or not all(
            isinstance(v, str) and v for v in pair.values()
        ):
            raise Error('Invalid scope pair.')
    return config


class Vault:
    def __init__(self, paths):
        self.paths = paths
        self.config = validate_config(read_json(paths.config / 'config.json'))

    def environment(self):
        private_dir(self.paths.state)
        cache = private_dir(self.paths.state / 'node-compile-cache')
        env = {k: v for k, v in os.environ.items() if not k.startswith('BW_')}
        env.update(BITWARDENCLI_APPDATA_DIR=str(self.paths.state / 'bw'), NODE_COMPILE_CACHE=str(cache))
        return env

    def token(self):
        try:
            session = read_json(self.paths.state / 'session.json')
        except FileNotFoundError:
            raise Error('Vault locked; run vw-ssh unlock.') from None
        if session['expires'] is not None and time.time() >= session['expires']:
            raise Error('Session expired; unlock again.')
        return session['token']

    def save_session(self, token):
        expiry = time.time() + 43200 if self.paths.profile == 'agent' else None
        write_json(self.paths.state / 'session.json', {'token': token, 'expires': expiry})

    def run(self, args, value=None, *, authenticated=True):
        import json
        env = self.environment()
        env['BW_NOINTERACTION'] = 'true'
        if authenticated:
            env['BW_SESSION'] = self.token()
        result = subprocess.run([self.config['bw'], *args], env=env,
            input=base64.b64encode(json.dumps(value).encode()).decode() if value is not None else '',
            text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise Error('Bitwarden CLI failed; check login, permissions and connectivity. Details suppressed.')
        if args[0] in {'sync', 'delete', 'lock', 'config'}:
            return None
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise Error('Unexpected Bitwarden CLI response.') from None

    def check(self):
        status = self.run(['status'])
        if (status.get('serverUrl') or '').rstrip('/') != self.config['server'].rstrip('/') or status.get('status') != 'unlocked':
            raise Error('Wrong server or locked vault.')
        if (status.get('userEmail') or '').casefold() != self.config['email'].casefold():
            raise Error('Wrong account in the isolated CLI profile.')

    def authenticate(self, action):
        if action == 'login':
            self.run(['config', 'server', self.config['server']], authenticated=False)
        else:
            status = self.run(['status'], authenticated=False)
            if (status.get('serverUrl') or '').rstrip('/') != self.config['server'].rstrip('/'):
                raise Error('Wrong server; run login in this profile.')
        env = self.environment()
        env['VW_SSH_PASSWORD'] = getpass.getpass('Master password: ')
        args = [action, '--raw', '--passwordenv', 'VW_SSH_PASSWORD']
        if action == 'login':
            args.insert(1, self.config['email'])
        try:
            result = subprocess.run([self.config['bw'], *args], env=env, text=True,
                                    stdout=subprocess.PIPE, timeout=300)
        finally:
            env.pop('VW_SSH_PASSWORD', None)
        token = result.stdout.strip()
        if result.returncode or not token or '\n' in token:
            raise Error('Login/unlock failed; output suppressed.')
        self.save_session(token)
        print('Unlocked for 12 hours.' if self.paths.profile == 'agent' else 'Unlocked until explicit lock.')

    def area(self, item, *, required=False):
        for scope, pair in self.config['scopes'].items():
            if item.get('organizationId') == pair['organizationId'] and item.get('collectionIds') == [pair['collectionId']]:
                return scope
        if required or self.config['scopes'] or self.paths.profile == 'agent':
            raise Error('Item outside allowed exclusive collection.')
        return None

    def ssh_key(self, connection):
        from .ssh import validate_material
        self.check()
        item = self.run(['get', 'item', connection['itemId']])
        self.area(item)
        if item.get('id') != connection['itemId'] or item.get('type') != 5 or item.get('deletedDate'):
            raise Error('Not the selected active SSH-key record.')
        key = item['sshKey']
        validate_material(key, connection['fingerprint'])
        return key

    def discover(self, *, scopes=False):
        from .ssh import fingerprint
        self.check()
        self.run(['sync'])
        if scopes:
            return {entity: [{k: row[k] for k in ['id', 'name', 'organizationId'] if k in row}
                             for row in self.run(['list', entity])]
                    for entity in ['organizations', 'collections']}
        result = []
        for item in self.run(['list', 'items']):
            if item.get('type') != 5 or item.get('deletedDate'):
                continue
            try:
                self.area(item)
                result.append({'id': item['id'], 'name': item['name'],
                               'fingerprint': fingerprint(item['sshKey']['publicKey'])})
            except Error:
                continue
        return result
