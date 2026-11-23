"""Versioned password-encrypted archives; private keys only live in memory."""
import getpass
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import ssh
from .storage import Error, name, private_dir, read_json, write_file, write_json
from .vault import Vault, validate_config

FORMAT = 'vw-ssh-recovery-v2'


def derive(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())


def validate_payload(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('connections'), dict) or not isinstance(payload.get('keys'), dict):
        raise Error('Invalid recovery payload.')
    all_connections = []
    used = {}
    for alias, c in payload['connections'].items():
        name(alias)
        ssh.validate_connection(c)
        all_connections.append(c)
    legacy = payload.get('legacy')
    if legacy:
        ssh.validate_connection(legacy, identity=True)
        all_connections.append(legacy)
    if {c['itemId'] for c in all_connections} != set(payload['keys']):
        raise Error('Archive contains keys without matching metadata, or is incomplete.')
    for c in all_connections:
        signature = c['itemId'], c['fingerprint']
        if c['keyName'] in used and used[c['keyName']] != signature:
            raise Error('Conflicting keyName in archive.')
        used[c['keyName']] = signature
        ssh.validate_material(payload['keys'][c['itemId']], c['fingerprint'])
    if not isinstance(payload.get('known_hosts'), str) or '\0' in payload['known_hosts']:
        raise Error('Invalid known_hosts in archive.')
    if payload.get('config'):
        validate_config(payload['config'])
    return list({c['keyName']: c for c in all_connections}.values())


def backup(paths, output=None):
    vault = Vault(paths)
    vault.check()
    vault.run(['sync'])
    data = ssh.connections(paths)
    old = ssh.legacy(paths)
    selected = list(data.values()) + ([old] if old else [])
    if not selected:
        raise Error('No keys configured; refusing an empty backup.')
    items = {}
    for c in selected:
        items[c['itemId']] = vault.ssh_key(c)
    portable = dict(vault.config, bw='bw')
    payload = {'connections': data, 'legacy': old, 'keys': items, 'config': portable,
               'known_hosts': (paths.config / 'known_hosts').read_text()}
    validate_payload(payload)
    password = getpass.getpass('Recovery password (at least 16 characters): ')
    if len(password) < 16 or password != getpass.getpass('Repeat recovery password: '):
        raise Error('Passwords differ or are shorter than 16 characters.')
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive(password, salt)
    content = json.dumps(payload).encode()
    encrypted = AESGCM(key).encrypt(nonce, content, FORMAT.encode())
    directory = private_dir(paths.data / 'recovery')
    path = Path(output).expanduser() if output else directory / (time.strftime('%Y%m%d-%H%M%S-') + os.urandom(3).hex() + '.json.enc')
    envelope = {'format': FORMAT, 'salt': salt.hex(), 'nonce': nonce.hex(), 'ciphertext': encrypted.hex()}
    write_json(path, envelope, replace=False)
    saved = read_json(path)
    if AESGCM(key).decrypt(bytes.fromhex(saved['nonce']), bytes.fromhex(saved['ciphertext']), FORMAT.encode()) != content:
        raise Error('Written archive verification failed; previous backups were not replaced.')
    print('Verified encrypted archive:', path)
    print('Copy it to independent storage; keep the password separately. Older archives are retained.')
    return path


def decrypt(path, paths):
    path = Path(path).expanduser()
    if path.stat().st_size > 32 * 1024 * 1024:
        raise Error('Recovery archive exceeds the 32 MiB limit.')
    envelope = json.loads(path.read_text())
    format_name = envelope.get('format')
    if format_name not in {FORMAT, 'vw-ssh-recovery-v1'}:
        raise Error('Unknown recovery format.')
    salt, nonce = bytes.fromhex(envelope['salt']), bytes.fromhex(envelope['nonce'])
    if len(salt) != 16 or len(nonce) != 12:
        raise Error('Invalid encryption parameters.')
    key = derive(getpass.getpass('Recovery password: '), salt)
    try:
        payload = json.loads(AESGCM(key).decrypt(nonce, bytes.fromhex(envelope['ciphertext']), format_name.encode()))
    except InvalidTag:
        raise Error('Wrong recovery password or damaged archive; no files changed.') from None
    if format_name == 'vw-ssh-recovery-v1' and 'legacy' not in payload:
        extra = set(payload['keys']) - {c['itemId'] for c in payload['connections'].values()}
        if extra:
            metadata = paths.config / 'legacy-identity.json'
            if not metadata.exists():
                raise Error('Old v1 archive needs legacy-identity.json. Use --home pointing to metadata or create a new archive.')
            payload['legacy'] = read_json(metadata)
    validate_payload(payload)
    return payload


def recover(paths, archive, *, check=False, restore=False):
    payload = decrypt(archive, paths)
    selected = validate_payload(payload)
    if check:
        print(f'Archive valid: {len(selected)} identities; no files changed, no agents started.')
        return
    if restore:
        if paths.config.exists():
            raise Error('Configuration exists; restore requires a fresh --home. Nothing overwritten.')
        parent = private_dir(paths.config.parent)
        with tempfile.TemporaryDirectory(prefix='.restore-', dir=parent) as directory:
            stage = Path(directory) / 'profile'
            private_dir(stage)
            private_dir(stage / 'public')
            for c in selected:
                write_file(stage / 'public' / (c['keyName'] + '.pub'), payload['keys'][c['itemId']]['publicKey'] + '\n')
            write_json(stage / 'connections.json', payload['connections'])
            if payload.get('legacy'):
                write_json(stage / 'legacy-identity.json', payload['legacy'])
            if payload.get('config'):
                write_json(stage / 'config.json', dict(payload['config'], bw='bw'))
            write_file(stage / 'known_hosts', payload['known_hosts'])
            write_file(stage / 'ssh_config', ssh.config_text(paths, payload['connections']))
            # copytree exclusively creates the destination, including against concurrent init.
            shutil.copytree(stage, paths.config)
        print('Portable configuration restored. Add the generated Include manually; login again for online vault access.')
    with ssh.agent_lock(paths):
        for c in selected:
            ssh.load_material(paths, c, payload['keys'][c['itemId']], ttl=43200)
    print(f'Recovered {len(selected)} identities for 12 hours. No private key files written.')
