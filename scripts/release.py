"""Build public artifacts without local user/group identities in tar headers."""
import gzip
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def main():
    subprocess.run([sys.executable, '-m', 'build'], check=True)
    for archive in Path('dist').glob('*.tar.gz'):
        with tempfile.TemporaryDirectory() as directory:
            normalized = Path(directory) / archive.name
            with tarfile.open(archive, 'r:gz') as source, normalized.open('wb') as raw:
                with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w') as target:
                        for member in source:
                            member.uid = member.gid = 0
                            member.uname = member.gname = ''
                            member.pax_headers = {k: v for k, v in member.pax_headers.items()
                                                  if k not in {'uid', 'gid', 'uname', 'gname'}}
                            target.addfile(member, source.extractfile(member) if member.isfile() else None)
            archive.write_bytes(normalized.read_bytes())
    artifacts = sorted(p for p in Path('dist').iterdir() if p.suffix == '.whl' or p.name.endswith('.tar.gz'))
    Path('dist/SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in artifacts))
    print('Normalized source headers and wrote dist/SHA256SUMS.')


if __name__ == '__main__':
    main()
