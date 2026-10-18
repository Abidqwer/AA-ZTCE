#!/usr/bin/env python3
"""Prepare already-present repository reference files for a source-only checkout.

Does not download or publish the original ZIP. Copies the manifest-verified core
from this same repository into the integration's local runtime directory.
"""
import hashlib
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parent

def main():
    if (ROOT/'published/engine.py').is_file():return
    repo=ROOT.parents[1]
    manifest_path=repo/'PUBLICATION_SHA256.json'
    if not manifest_path.is_file():raise SystemExit('Archived reference missing; use the complete downloadable package or a full repository checkout.')
    manifest=json.loads(manifest_path.read_text())
    for name,expected in manifest.items():
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts:raise SystemExit('Unsafe manifest path')
        source=repo/rel
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest()!=expected:
            raise SystemExit('Reference file differs from published manifest: '+name)
    for name in manifest:
        target=ROOT/'published'/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(repo/name,target)
    shutil.copyfile(manifest_path,ROOT/'published/PUBLICATION_SHA256.json')
    print('Prepared manifest-verified reference from existing repository files; publication ZIP is not included.')

if __name__=='__main__':main()
