import array
from contextlib import redirect_stdout, redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from vw_ssh import cli, mcp, recovery, ssh, vault
from vw_ssh.storage import Error, Paths, private_dir, read_json, write_file, write_json

ITEM = '00000000-0000-4000-8000-000000000001'
OTHER = '00000000-0000-4000-8000-000000000002'
SCOPE = {'organizationId': 'organization', 'collectionId': 'collection'}


def material():
    key = Ed25519PrivateKey.generate()
    return {'privateKey': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode(), 'publicKey': key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='vws tests ')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.env = patch.dict(os.environ, {'VW_SSH_HOME': str(self.root / 'home with spaces')})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.paths = Paths()
        self.paths.create()
        write_json(self.paths.config / 'config.json', {'server': 'https://vault.example.com',
            'email': 'user@example.com', 'bw': 'bw', 'scopes': {}})
        write_json(self.paths.config / 'connections.json', {})
        write_file(self.paths.config / 'known_hosts', '')
        self.key = material()
        self.c = {'host': 'server.example.com', 'user': 'deploy', 'port': 2222,
                  'keyName': 'example', 'itemId': ITEM, 'fingerprint': ssh.fingerprint(self.key['publicKey'])}
        self.vault = vault.Vault(self.paths)

    def test_init_templates_repeat_and_help_without_mcp(self):
        with redirect_stdout(io.StringIO()):
            cli.initialize(self.paths)
            cli.initialize(self.paths)
            cli.main(['help'])
        self.assertEqual(read_json(self.paths.config / 'connections.json'), {})
        self.assertEqual(len(list((self.paths.config / 'templates').glob('*.json'))), 3)
        for p in self.paths.config.rglob('*'):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)
        self.assertNotEqual(self.paths.state, Paths('agent').state)
        self.assertNotEqual(self.paths.runtime, Paths('agent').runtime)

    def test_atomic_files_permissions_and_no_overwrite(self):
        path = self.paths.config / 'atomic.json'
        write_json(path, {'dummy': 1})
        with patch('vw_ssh.storage.os.replace', side_effect=OSError('dummy failure')):
            with self.assertRaises(OSError):
                write_json(path, {'dummy': 2})
        self.assertEqual(read_json(path), {'dummy': 1})
        with self.assertRaises(FileExistsError):
            write_json(path, {}, replace=False)
        self.assertEqual(list(self.paths.config.glob('tmp*')), [])
        path.chmod(0o644)
        with self.assertRaises(Error):
            read_json(path)
        link = self.paths.config / 'symlink'
        link.symlink_to(path)
        with self.assertRaises(Error):
            read_json(link)

    def test_server_and_scope_validation(self):
        for server in ['http://vault.example.com', 'https://user:pass@vault.example.com', 'https://vault.example.com/?secret=x']:
            with self.subTest(server=server), self.assertRaises(Error):
                vault.validate_config(dict(self.vault.config, server=server))
        self.vault.config['scopes'] = {'team': SCOPE}
        item = {'organizationId': 'organization', 'collectionIds': ['collection']}
        self.assertEqual(self.vault.area(item), 'team')
        for fields in [{'organizationId': None}, {'collectionIds': ['collection', 'other']}, {'organizationId': 'foreign'}]:
            with self.subTest(fields=fields), self.assertRaises(Error):
                self.vault.area(dict(item, **fields))

    def test_session_independence_ttl_and_rejection_before_cli(self):
        self.vault.save_session('dummy-token')
        with patch('vw_ssh.vault.time.time', return_value=10**15):
            self.assertEqual(self.vault.token(), 'dummy-token')
        agent = Paths('agent')
        agent.create()
        write_json(agent.config / 'config.json', self.vault.config)
        av = vault.Vault(agent)
        av.save_session('dummy-agent')
        with patch('vw_ssh.vault.time.time', return_value=10**15):
            with self.assertRaises(Error):
                av.token()
        (self.paths.state / 'session.json').unlink()
        with patch.object(vault.subprocess, 'run') as run:
            with self.assertRaises(Error):
                self.vault.run(['get', 'item', ITEM])
            run.assert_not_called()

    def test_cli_environment_private_and_suppressed_error(self):
        self.vault.save_session('dummy-token')
        with patch.dict(os.environ, {'BW_SESSION': 'wrong', 'BW_CLEANEXIT': 'true'}):
            env = self.vault.environment()
            self.assertNotIn('BW_SESSION', env)
            self.assertNotIn('BW_CLEANEXIT', env)
        self.assertEqual(Path(env['NODE_COMPILE_CACHE']).stat().st_mode & 0o777, 0o700)
        with patch.object(vault.subprocess, 'run', return_value=Mock(returncode=1, stdout='secret', stderr='secret')):
            with self.assertRaises(Error) as error:
                self.vault.run(['status'])
            self.assertNotIn('secret', str(error.exception))

    def test_discover_scopes_metadata_only_and_auth_account_checks(self):
        with patch.object(self.vault, 'check'), patch.object(self.vault, 'run', side_effect=[None,
            [{'id': 'org', 'name': 'team', 'secret': 'DUMMY_SECRET'}],
            [{'id': 'collection', 'name': 'keys', 'organizationId': 'org', 'secret': 'DUMMY_SECRET'}]]):
            result = self.vault.discover(scopes=True)
        self.assertNotIn('DUMMY_SECRET', str(result))
        valid = {'serverUrl': self.vault.config['server'], 'userEmail': self.vault.config['email'], 'status': 'unlocked'}
        for fields in [{'serverUrl': 'https://other.example.com'}, {'userEmail': 'other@example.com'}, {'status': 'locked'}]:
            with patch.object(self.vault, 'run', return_value=dict(valid, **fields)), self.assertRaises(Error):
                self.vault.check()

    def test_authenticate_no_password_in_argv_or_stdout(self):
        for profile in ['ssh', 'agent']:
            paths = self.paths if profile == 'ssh' else Paths('agent')
            paths.create()
            if profile == 'agent':
                write_json(paths.config / 'config.json', self.vault.config)
            client = vault.Vault(paths)
            with patch.object(client, 'run'), patch('getpass.getpass', return_value='DUMMY_PASSWORD'), \
                 patch.object(vault.subprocess, 'run', return_value=Mock(returncode=0, stdout='DUMMY_TOKEN')) as run, \
                 redirect_stdout(io.StringIO()) as output:
                client.authenticate('login')
            self.assertNotIn('DUMMY_PASSWORD', str(run.call_args.args))
            self.assertNotIn('DUMMY_TOKEN', output.getvalue())
            session = read_json(paths.state / 'session.json')
            self.assertEqual(session['token'], 'DUMMY_TOKEN')
            self.assertEqual(session['expires'] is None, profile == 'ssh')

    def test_exact_key_and_identity_validated(self):
        item = {'id': ITEM, 'type': 5, 'sshKey': self.key}
        status = {'serverUrl': self.vault.config['server'], 'userEmail': self.vault.config['email'], 'status': 'unlocked'}
        with patch.object(self.vault, 'run', side_effect=[status, item]):
            self.assertEqual(self.vault.ssh_key(self.c), self.key)
        wrong = dict(self.key, privateKey=material()['privateKey'])
        with self.assertRaises(Error):
            ssh.validate_material(wrong, self.c['fingerprint'])
        for item_id in ['search-term', '--help', '../key']:
            with self.assertRaises(Error):
                ssh.validate_connection(dict(self.c, itemId=item_id))

    def test_config_quotes_paths_port_and_no_shell_injection(self):
        write_json(self.paths.config / 'connections.json', {'example': self.c})
        write_file(self.paths.config / 'public/example.pub', self.key['publicKey'])
        with redirect_stdout(io.StringIO()):
            ssh.generate_config(self.paths)
        text = (self.paths.config / 'ssh_config').read_text()
        self.assertIn('ProxyUseFdpass yes', text)
        self.assertIn('Port 2222', text)
        self.assertIn('home with spaces', text)
        result = subprocess.run(['ssh', '-G', '-F', str(self.paths.config / 'ssh_config'), 'example'],
                                text=True, capture_output=True, check=True, timeout=10)
        self.assertIn('hostname server.example.com', result.stdout)
        self.assertIn('port 2222', result.stdout)
        for bad in [{'host': 'example\nProxyCommand bad'}, {'user': 'bad;command'}, {'keyName': '../escape'}]:
            with self.assertRaises(Error):
                ssh.validate_connection(dict(self.c, **bad))

    def test_load_all_silent_and_status(self):
        write_json(self.paths.config / 'connections.json', {'good': self.c, 'bad': {}, 'later': self.c})
        with patch.object(ssh, 'ensure', side_effect=[Error('dummy'), Error('dummy'), None]) as load, \
             redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            ssh.load_all(self.paths)
        self.assertEqual(load.call_count, 3)
        self.assertEqual(output.getvalue() + errors.getvalue(), '')
        with patch.object(ssh, 'listing', return_value=Mock(returncode=1, stdout='')), redirect_stdout(io.StringIO()) as output:
            ssh.status(self.paths)
        self.assertIn('good unloaded', output.getvalue())
        self.assertIn('bad unavailable', output.getvalue())

    def test_real_agent_load_sign_and_lock_offline(self):
        pids = []
        try:
            with ssh.agent_lock(self.paths):
                ssh.load_material(self.paths, self.c, self.key)
            pids.append(int((self.paths.runtime / 'example.pid').read_text()))
            public = self.root / 'test.pub'
            public.write_text(self.key['publicKey'])
            subprocess.run(['ssh-add', '-T', str(public)], env=ssh.agent_env(self.paths, self.c),
                           capture_output=True, check=True, timeout=10)
            with patch.object(vault.Vault, 'ssh_key', side_effect=AssertionError('must remain offline')):
                ssh.ensure(self.paths, self.c)
            with redirect_stdout(io.StringIO()):
                ssh.lock(self.paths)
            self.assertEqual(ssh.listing(self.paths, self.c).returncode, 1)
        finally:
            self.stop_agents(self.paths)

    def stop_agents(self, paths):
        if paths.runtime.exists():
            def missing_only(function, path, exc):
                if not isinstance(exc[1], FileNotFoundError):
                    raise exc[1]
            for pid_file in paths.runtime.glob('*.pid'):
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGTERM)
                except ProcessLookupError:
                    pass
            import shutil
            shutil.rmtree(paths.runtime, onerror=missing_only)

    def make_archive(self):
        write_json(self.paths.config / 'connections.json', {'example': self.c})
        old_key = material()
        old = {'keyName': 'old-key', 'itemId': OTHER, 'fingerprint': ssh.fingerprint(old_key['publicKey'])}
        write_json(self.paths.config / 'legacy-identity.json', old)
        with patch.object(vault.Vault, 'check'), patch.object(vault.Vault, 'run'), \
             patch.object(vault.Vault, 'ssh_key', side_effect=lambda c: self.key if c['itemId'] == ITEM else old_key), \
             patch('getpass.getpass', return_value='dummy-recovery-password'), redirect_stdout(io.StringIO()):
            archive = recovery.backup(self.paths)
        return archive

    def test_cold_recovery_clean_home_new_archive_real_agents(self):
        archive = self.make_archive()
        with patch.dict(os.environ, {'VW_SSH_HOME': str(self.root / 'cold home')}):
            cold = Paths()
            try:
                with patch('getpass.getpass', return_value='dummy-recovery-password'), \
                     patch.object(vault.Vault, 'run', side_effect=AssertionError('offline only')), redirect_stdout(io.StringIO()):
                    recovery.recover(cold, archive, check=True)
                    self.assertFalse(cold.config.exists())
                    recovery.recover(cold, archive, restore=True)
                self.assertEqual(len(list(cold.runtime.glob('*.pid'))), 2)
                for public in (cold.config / 'public').glob('*.pub'):
                    c = {'keyName': public.stem}
                    subprocess.run(['ssh-add', '-T', str(public)], env=ssh.agent_env(cold, c),
                                   capture_output=True, check=True, timeout=10)
                self.assertEqual(read_json(cold.config / 'config.json')['bw'], 'bw')
                with patch('getpass.getpass', return_value='dummy-recovery-password'):
                    with self.assertRaises(Error):
                        recovery.recover(cold, archive, restore=True)
                for p in cold.config.rglob('*'):
                    if p.is_file():
                        self.assertNotIn('PRIVATE KEY', p.read_text())
                with redirect_stdout(io.StringIO()):
                    ssh.lock(cold)
                self.assertTrue(all(ssh.listing(cold, {'keyName': p.stem}).returncode == 1 for p in (cold.config / 'public').glob('*.pub')))
            finally:
                self.stop_agents(cold)

    def test_recovery_wrong_password_tamper_and_v1(self):
        archive = self.make_archive()
        with patch('getpass.getpass', return_value='wrong-password'):
            with self.assertRaises(Error):
                recovery.decrypt(archive, self.paths)
        with patch('getpass.getpass', return_value='dummy-recovery-password'):
            payload = recovery.decrypt(archive, self.paths)
        del payload['legacy']
        salt, nonce = os.urandom(16), os.urandom(12)
        encrypted = recovery.AESGCM(recovery.derive('dummy-recovery-password', salt)).encrypt(
            nonce, json.dumps(payload).encode(), b'vw-ssh-recovery-v1')
        old = self.root / 'v1.enc'
        write_json(old, {'format': 'vw-ssh-recovery-v1', 'salt': salt.hex(), 'nonce': nonce.hex(), 'ciphertext': encrypted.hex()})
        with patch('getpass.getpass', return_value='dummy-recovery-password'):
            self.assertEqual(len(recovery.validate_payload(recovery.decrypt(old, self.paths))), 2)
            try:
                with patch.object(vault.Vault, 'run', side_effect=AssertionError('offline only')), redirect_stdout(io.StringIO()):
                    recovery.recover(self.paths, old)
                self.assertEqual(len(list(self.paths.runtime.glob('*.pid'))), 2)
            finally:
                self.stop_agents(self.paths)
            (self.paths.config / 'legacy-identity.json').unlink()
            with self.assertRaises(Error):
                recovery.decrypt(old, self.paths)
        envelope = read_json(archive)
        raw = bytearray.fromhex(envelope['ciphertext'])
        raw[-1] ^= 1
        envelope['ciphertext'] = raw.hex()
        write_json(archive, envelope)
        with patch('getpass.getpass', return_value='dummy-recovery-password'):
            with self.assertRaises(Error):
                recovery.decrypt(archive, self.paths)

    def test_archive_rejects_unsafe_names_before_writes(self):
        bad = dict(self.c, keyName='../escape')
        with self.assertRaises(Error):
            recovery.validate_payload({'connections': {'example': bad}, 'keys': {ITEM: self.key}, 'known_hosts': ''})

    def test_fdpass_real_openssh_and_nondefault_port(self):
        write_json(self.paths.config / 'connections.json', {'example': self.c})
        write_file(self.paths.config / 'public/example.pub', self.key['publicKey'])
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(10)
            received = []
            def banner():
                try:
                    with listener.accept()[0] as conn:
                        conn.settimeout(10)
                        conn.sendall(b'SSH-2.0-vws-test\r\n')
                        received.append(conn.recv(1024))
                except OSError:
                    pass
            thread = threading.Thread(target=banner)
            thread.start()
            script = 'from vw_ssh import ssh; from vw_ssh.storage import Paths; ssh.ensure=lambda *a:None; ssh.proxy(Paths(), ' + repr(dict(self.c, host='127.0.0.1', port=listener.getsockname()[1])) + ')'
            command = shlex.join([sys.executable, '-c', script])
            result = subprocess.run(['ssh', '-F', '/dev/null', '-o', 'ProxyUseFdpass=yes',
                '-o', 'ProxyCommand=' + command, '-o', 'ConnectTimeout=5', 'example.invalid'],
                capture_output=True, timeout=15)
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertTrue(received and received[0].startswith(b'SSH-2.0-'), result.stderr.decode())


class MCPTests(unittest.TestCase):
    def setUp(self):
        self.item = {'id': ITEM, 'type': 1, 'name': 'dummy', 'revisionDate': 'r1',
            'organizationId': SCOPE['organizationId'], 'collectionIds': [SCOPE['collectionId']],
            'login': {'username': 'dummy', 'password': 'DUMMY_SECRET', 'totp': 'DUMMY_TOTP'},
            'notes': 'DUMMY_NOTES', 'fields': [{'name': 'keep', 'value': 'DUMMY_FIELD'}]}
        self.vault = Mock()
        self.vault.paths.profile = 'agent'
        self.vault.config = {'scopes': {'team': SCOPE}}
        self.vault.area = lambda i, **kw: vault.Vault.area(self.vault, i, **kw)
        def run(args, value=None):
            if args[0] == 'list':
                return [copy.deepcopy(self.item)]
            if args[0] == 'get':
                return copy.deepcopy(self.item)
            if args[0] == 'edit':
                self.edited = value
                return value
        self.vault.run.side_effect = run

    def test_metadata_patch_revision_acl(self):
        self.assertNotIn('DUMMY_SECRET', str(mcp.execute(self.vault, 'search', {'query': 'dummy'})))
        mcp.execute(self.vault, 'update', {'id': ITEM, 'revision': 'r1', 'changes': {'username': 'new'}})
        self.assertEqual(self.edited['fields'], self.item['fields'])
        self.assertEqual(self.edited['login']['totp'], 'DUMMY_TOTP')
        for patch_item in [{'organizationId': None}, {'collectionIds': ['collection', 'other']}, {'organizationId': 'foreign'}]:
            original = self.item
            self.item = dict(original, **patch_item)
            with self.assertRaises(Error):
                mcp.execute(self.vault, 'delete', {'id': ITEM, 'revision': 'r1'})
            self.item = original
        with self.assertRaises(Error):
            mcp.execute(self.vault, 'delete', {'id': ITEM, 'revision': 'old'})
        with self.assertRaises(Error):
            mcp.execute(self.vault, 'update', {'id': ITEM, 'revision': 'r1', 'changes': {'organizationId': 'foreign'}})

    def test_ssh_profile_and_no_scopes_denied(self):
        self.vault.paths.profile = 'ssh'
        with self.assertRaises(Error):
            mcp.execute(self.vault, 'read', {'id': ITEM})
        self.vault.check.assert_not_called()
        self.vault.paths.profile = 'agent'
        self.vault.config['scopes'] = {}
        with self.assertRaises(Error):
            mcp.execute(self.vault, 'read', {'id': ITEM})

    def test_create_read_delete_exact_scope_and_tool_set(self):
        self.vault.run.side_effect = None
        self.vault.run.return_value = self.item
        result = mcp.execute(self.vault, 'create', {'scope': 'team', 'name': 'dummy'})
        self.assertEqual(result['scope'], 'team')
        created = self.vault.run.call_args.args[1]
        self.assertEqual(created['collectionIds'], ['collection'])
        result = mcp.execute(self.vault, 'read', {'id': ITEM})
        self.assertEqual(result['password'], 'DUMMY_SECRET')
        mcp.execute(self.vault, 'delete', {'id': ITEM, 'revision': 'r1'})
        self.vault.run.assert_called_with(['delete', 'item', ITEM])
        with self.assertRaises(Error):
            mcp.execute(self.vault, 'export', {})

    def test_stdio_tools_without_config(self):
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-m', 'vw_ssh.cli', '--home', directory, 'mcp', 'serve'],
                input=json.dumps(request) + '\n', text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual({t['name'] for t in json.loads(result.stdout)['result']['tools']},
                             {'search', 'read', 'create', 'update', 'delete'})
            self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
