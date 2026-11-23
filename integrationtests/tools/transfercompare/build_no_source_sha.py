#!/usr/bin/env python3
"""Build an isolated benchmark binary without source chunk digest verification.

The Go overlay never modifies library sources on disk. Normal builds retain
verification. Only the source content digest is skipped; metadata, read-length,
TLS authentication and QUIC packet protection checks remain enabled.
"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
source = root / 'experimental_worker_runtime.go'
original = source.read_text()
needle = 'if sha256.Sum256(b) != [32]byte(j.Hash) {'
if original.count(needle) != 1:
    raise SystemExit('Source digest guard changed; review the benchmark overlay.')
with tempfile.TemporaryDirectory(prefix='mpquic-no-source-sha-') as directory:
    temporary = Path(directory)
    replacement = temporary / source.name
    replacement.write_text(original.replace(needle, 'if false && sha256.Sum256(b) != [32]byte(j.Hash) {'))
    overlay = temporary / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(source): str(replacement)}}))
    subprocess.run(['go', 'build', '-overlay', str(overlay), '-ldflags',
                    '-X main.sourceSHA256Verification=disabled-build-overlay',
                    '-o', str(args.output.resolve()), './integrationtests/tools/transfercompare'],
                   cwd=root, check=True)
assert source.read_text() == original, 'Library source was unexpectedly modified'
