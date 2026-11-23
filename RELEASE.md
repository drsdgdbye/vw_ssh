# Release 0.1.0 preparation

MIT licensed. Public repository: <https://github.com/drsdgdbye/vw_ssh>.
No personal connections or credentials are included. Release tag: `v0.1.0`.
This document describes the build and publication procedure; the actual release
and CI results are available on GitHub, and local checks in `VERIFICATION.md`.

## Build and test

1. Use Python 3.11+ in a disposable virtual environment.
2. Install the project, `build` and `pipx` there.
3. Run `python -m unittest discover -s tests -v` on Linux and macOS.
4. Run `python scripts/release.py`. It builds artifacts, removes local user/group
   identities from source tar headers and writes SHA256SUMS. Inspect all file lists.
5. Install the wheel with isolated `PIPX_HOME` / `PIPX_BIN_DIR`, not the user's
   active command directory. Run help/init and the test suite with that Python.
6. Check build/source contents for real email addresses, hostnames, IP addresses,
   account/collection IDs, user paths, private keys, sessions and generated data.
   Test UUIDs and documentation examples must be fictitious.
7. Generate `SHA256SUMS` for the wheel and source archive. Keep release notes and
   `VERIFICATION.md` accurate; do not report hosted CI as run before it runs.

## Publish

Review the exact file set and diff, commit the intended files, push and run CI.
Tag only the tested commit as `v0.1.0`, then upload the wheel, source archive and
SHA256SUMS to its GitHub Release. README installation URLs must match the release
tag. Inspect all Git history, not just the working tree, before publishing.

Publishing to PyPI, platform installers, auto-update, background services and
automatic migration are outside this release. Users can install the wheel or
install from the tagged GitHub checkout with pipx.
