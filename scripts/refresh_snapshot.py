#!/usr/bin/env python3
"""Refresh scripts/openapi.snapshot.json, the spec the generator and CI use.

    python3 scripts/refresh_snapshot.py                 # fetch the live spec
    python3 scripts/refresh_snapshot.py --spec file.json

Keeps only what gen_catalog.py reads: the BAPI / PLATFORM operations and the
schemas they reach. Spec order is kept, so a refresh diffs cleanly.
Then run `python3 scripts/gen_catalog.py` and review the diff (see README).
"""
import json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = 'https://api.atlasauth.net/v1/openapi.json'
METHODS = ('get', 'post', 'put', 'patch', 'delete')

src = sys.argv[sys.argv.index('--spec') + 1] if '--spec' in sys.argv else URL
if src.startswith('http'):
    with urllib.request.urlopen(urllib.request.Request(src, headers={'user-agent': 'atlasauth-rust-gen'})) as r:
        d = json.load(r)
else:
    with open(src) as f:
        d = json.load(f)

paths = {}
for p, ops in d['paths'].items():
    keep = {m: o for m, o in ops.items() if m in METHODS and o.get('tags', [''])[0] in ('BAPI', 'PLATFORM')}
    if keep:
        paths[p] = keep
schemas = d['components']['schemas']
used, todo = set(), []

def walk(n):
    if isinstance(n, dict):
        r = n.get('$ref')
        if r and r.startswith('#/components/schemas/'):
            todo.append(r.rsplit('/', 1)[1])
        for v in n.values():
            walk(v)
    elif isinstance(n, list):
        for v in n:
            walk(v)

walk(paths)
while todo:
    c = todo.pop()
    if c not in used:
        used.add(c)
        walk(schemas[c])
out = {'openapi': d['openapi'], 'paths': paths, 'components': {'schemas': {k: v for k, v in schemas.items() if k in used}}}
with open(os.path.join(HERE, 'openapi.snapshot.json'), 'w') as f:
    json.dump(out, f, separators=(',', ':'))
    f.write('\n')
print(f'{len(paths)} paths, {len(used)} schemas')
