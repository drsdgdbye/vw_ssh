"""Optional metadata-first login CRUD. Never uses the normal SSH profile."""
import json
import subprocess
import sys

from . import __version__
from .storage import Error
from .vault import Vault


def obj(properties, required=()):
    return {'type': 'object', 'properties': properties, 'required': list(required), 'additionalProperties': False}


STRING = {'type': 'string'}
TOOLS = [
    {'name': 'search', 'description': 'Search allowed login metadata only.', 'inputSchema': obj({'query': STRING}, ['query'])},
    {'name': 'read', 'description': 'Read selected login; secrets become visible to the model.', 'inputSchema': obj({'id': STRING}, ['id'])},
    {'name': 'create', 'description': 'Create login in an explicit configured scope.', 'inputSchema': obj(
        {k: STRING for k in ['scope', 'name', 'username', 'password', 'notes']}, ['scope', 'name'])},
    {'name': 'update', 'description': 'Patch login preserving other fields; revision required.', 'inputSchema': obj(
        {'id': STRING, 'revision': STRING, 'changes': obj({k: STRING for k in ['name', 'username', 'password', 'notes']})},
        ['id', 'revision', 'changes'])},
    {'name': 'delete', 'description': 'Move selected login to trash; revision required.', 'inputSchema': obj(
        {'id': STRING, 'revision': STRING}, ['id', 'revision'])},
]


def validate(value, schema):
    if schema['type'] == 'object':
        if not isinstance(value, dict) or value.keys() - schema['properties'].keys() or not set(schema['required']) <= value.keys():
            raise Error('Invalid tool arguments.')
        for key, content in value.items():
            validate(content, schema['properties'][key])
    elif not isinstance(value, str):
        raise Error('Expected a string.')


def metadata(vault, item):
    return {'id': item['id'], 'name': item['name'], 'revision': item['revisionDate'],
            'scope': vault.area(item, required=True)}


def execute(vault, tool_name, args):
    tool = next((t for t in TOOLS if t['name'] == tool_name), None)
    if tool is None:
        raise Error('Unknown tool.')
    validate(args, tool['inputSchema'])
    if vault.paths.profile != 'agent' or not vault.config['scopes']:
        raise Error('MCP requires the separate agent profile and explicit allowed scopes.')
    if 'id' in args:
        import uuid
        if str(uuid.UUID(args['id'])) != args['id']:
            raise Error('An exact item UUID is required.')
    vault.check()
    vault.run(['sync'])
    if tool_name == 'search':
        result = []
        for item in vault.run(['list', 'items', '--search', args['query']]):
            if item.get('type') != 1 or item.get('deletedDate'):
                continue
            try:
                result.append(metadata(vault, item))
            except Error:
                pass
        return result
    if tool_name == 'create':
        scope = vault.config['scopes'].get(args['scope'])
        if not scope:
            raise Error('Unknown scope.')
        item = {'type': 1, 'name': args['name'], 'organizationId': scope['organizationId'],
            'collectionIds': [scope['collectionId']], 'login': {'username': args.get('username', ''),
            'password': args.get('password', ''), 'uris': []}, 'notes': args.get('notes', '')}
        return metadata(vault, vault.run(['create', 'item'], item))
    item = vault.run(['get', 'item', args['id']])
    vault.area(item, required=True)
    if item.get('id') != args['id'] or item.get('type') != 1 or item.get('deletedDate'):
        raise Error('Not the selected active login item.')
    if tool_name == 'read':
        return {**metadata(vault, item), 'username': (item.get('login') or {}).get('username'),
                'password': (item.get('login') or {}).get('password'), 'notes': item.get('notes')}
    if args['revision'] != item.get('revisionDate'):
        raise Error('Revision changed; read again.')
    if tool_name == 'delete':
        vault.run(['delete', 'item', args['id']])
        return {'id': args['id'], 'deleted': True}
    for key, value in args['changes'].items():
        if key in {'username', 'password'}:
            item.setdefault('login', {})[key] = value
        else:
            item[key] = value
    return metadata(vault, vault.run(['edit', 'item', args['id']], item))


def serve(paths):
    if paths.profile != 'agent':
        raise Error('MCP only runs with the agent profile.')
    for line in sys.stdin:
        request = None
        try:
            request = json.loads(line)
            if 'id' not in request:
                continue
            method = request['method']
            if method == 'initialize':
                protocol = request.get('params', {}).get('protocolVersion', '2024-11-05')
                result = {'protocolVersion': protocol, 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'vw-ssh-agent', 'version': __version__}}
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'tools/call':
                try:
                    params = request['params']
                    output = execute(Vault(paths), params['name'], params.get('arguments', {}))
                    result = {'content': [{'type': 'text', 'text': json.dumps(output)}]}
                except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    result = {'isError': True, 'content': [{'type': 'text', 'text': 'Operation refused or vault unavailable; details suppressed.'}]}
            else:
                raise Error('Unknown method.')
            response = {'jsonrpc': '2.0', 'id': request['id'], 'result': result}
        except Exception:
            response = {'jsonrpc': '2.0', 'id': request.get('id') if isinstance(request, dict) else None,
                        'error': {'code': -32602, 'message': 'Invalid request; details suppressed.'}}
        print(json.dumps(response), flush=True)
