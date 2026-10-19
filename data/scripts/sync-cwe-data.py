#!/usr/bin/env python3
"""Acquire current official CVE/NVD/CPE/CWE/CAPEC snapshots without flattening fields.
Standard library only. Run --plan to list work without changing the repository.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

SOURCES = [
    ('cpe', 'https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz'),
    ('cpematch', 'https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz'),
    ('cwe', 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'),
    ('cwe', 'https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd'),
    ('capec', 'https://capec.mitre.org/data/archive/capec_latest.zip'),
    ('capec', 'https://capec.mitre.org/data/xsd/ap_schema_latest.xsd'),
]
REPOS = [
    ('data/upstream/cvelistV5', 'https://github.com/CVEProject/cvelistV5.git'),
    ('data/upstream/cve-schema', 'https://github.com/CVEProject/cve-schema.git'),
]

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def git(repo, *args, capture=False):
    return subprocess.run(['git', '-C', str(repo), *args], check=True,
                          text=True, stdout=subprocess.PIPE if capture else None).stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--snapshot', help='New snapshot name, or an existing name to resume')
    parser.add_argument('--plan', action='store_true', help='Print the plan; change nothing')
    parser.add_argument('--update-submodules', action='store_true', help='Explicitly advance existing source submodule pins to upstream main')
    args = parser.parse_args()
    if sys.version_info < (3, 9):
        raise SystemExit("Python 3.9 or later is required")
    repo = args.repo.expanduser().resolve()
    top = Path(git(repo, 'rev-parse', '--show-toplevel', capture=True).strip()).resolve()
    if repo != top:
        raise ValueError('--repo must name the repository root')
    stamp = args.snapshot or dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', stamp):
        raise ValueError('Snapshot names may contain letters, digits, underscores, and hyphens')
    year = dt.datetime.now(dt.timezone.utc).year
    feeds = [(str(y), f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}')
             for y in range(2002, year + 1)]
    if args.plan:
        print(f'Repository: {repo}\nSnapshot: {stamp}')
        for path, url in REPOS:
            print('Git submodule:', path, url)
        for _, base in feeds:
            print('NVD yearly feed:', base + '.json.gz', 'and .meta')
        for group, url in SOURCES:
            print(group + ':', url)
        print('Large files: data/raw/<source>/<snapshot>/; manifest: data/manifests/')
        print('CWE/CAPEC catalog XML is extracted; large NVD/CPE files remain compressed.')
        return
    data = repo / 'data'
    for name in ['scripts', 'manifests', 'raw', 'derived', 'cache', 'historical', 'upstream']:
        (data / name).mkdir(parents=True, exist_ok=True)
    # Preserve the exact tool used alongside the source inventory.
    own = Path(__file__).resolve()
    installed = data / 'scripts/sync-cwe-data.py'
    if own != installed.resolve():
        if installed.exists() and installed.read_bytes() != own.read_bytes():
            raise ValueError('Existing data/scripts/sync-cwe-data.py differs; review it before replacing')
        shutil.copyfile(own, installed)
    ignore = data / '.gitignore'
    existing = ignore.read_text() if ignore.exists() else ''
    additions = [line for line in ['/raw/', '/derived/', '/cache/', '*.part']
                 if line not in existing.splitlines()]
    if additions:
        ignore.write_text(existing.rstrip() + '\n\n# Reproducible bulk downloads and local outputs\n' + '\n'.join(additions) + '\n')
    for rel, text in [
        ('historical/README.md', '# Historical exports\n\nKeep previously recovered CSVs and their original manifests separate from fresh snapshots. Existing data files elsewhere under data/ are not moved or overwritten by this tool.\n'),
        ('SOURCES.md', '# Official source collection\n\n`upstream/cvelistV5/` contains official CVE Program records; `upstream/cve-schema/` contains their record schemas. Both are Git submodules pinned by the parent repository.\n\n`raw/nvd-cve/<snapshot>/` contains all annual NVD JSON 2.0 feeds from 2002 onward, including the earlier CVEs carried in the initial feed. Original records retain descriptions, references, CWE labels, CVSS metrics, applicability configurations, and other published fields without column filtering.\n\n`raw/cpe/` holds the official CPE dictionary; `raw/cpematch/` holds match criteria and their platform mappings. These complement CVE applicability fields. Preserve the logical configuration structure when interpreting affected products.\n\n`raw/cwe/` contains the complete current CWE catalog and schema, including weaknesses, categories, views, and relationship context. `raw/capec/` contains the related attack-pattern catalog and schema. Extracted catalog XML is retained beside its source ZIP.\n\n`manifests/` records acquisition windows, source URLs, file sizes, hashes, validation details, and source Git commits. Downloads are acquired sequentially, not as one transactionally consistent upstream snapshot. Unavailable or absent upstream fields are not invented.\n\nBulk files under `raw/`, `cache/`, and `derived/` are ignored by ordinary Git commits. Commit the tooling, source documentation, manifests, and submodule pins. Large snapshots require separate artifact storage if they must be shared.\n\nRun `python3 data/scripts/sync-cwe-data.py --repo .` for a new snapshot; use `--snapshot NAME` to resume a recorded one. Existing submodules retain their pins unless `--update-submodules` is supplied.\n\nScope is the current public source records/catalogs at acquisition time, not every historical revision, every external referenced document, or every security taxonomy. NVD change history, historical CWE/CAPEC releases, ATT&CK, KEV, EPSS, and external product metadata are separate acquisitions and are not claimed included. This tool does not restore historical CSV bytes.\n')]:
        target = data / rel
        if not target.exists():
            target.write_text(text)
    manifest_path = data / 'manifests' / (stamp + '.json')
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {
        'snapshot': stamp, 'started_utc': utc(), 'status': 'incomplete',
        'files': [], 'git_sources': []}
    if manifest['snapshot'] != stamp:
        raise ValueError('Manifest snapshot mismatch')
    manifest['status'] = 'incomplete'
    def save():
        tmp = manifest_path.with_suffix('.json.part')
        tmp.write_text(json.dumps(manifest, indent=2) + '\n')
        tmp.replace(manifest_path)
    save()
    try:
        manifest['git_sources'] = []
        for rel, url in REPOS:
            path = repo / rel
            tracked = git(repo, 'ls-files', '--stage', '--', rel, capture=True).strip()
            if tracked and not tracked.startswith('160000 '):
                raise ValueError(f'{rel} is tracked as ordinary files, not a submodule')
            if not tracked:
                if path.exists():
                    raise ValueError(f'{rel} already exists without a registered gitlink; review before adding')
                git(repo, 'submodule', 'add', '--depth', '1', '-b', 'main', url, rel)
            else:
                git(repo, 'submodule', 'update', '--init', '--', rel)
                actual = git(path, 'remote', 'get-url', 'origin', capture=True).strip()
                if actual.rstrip('/').removesuffix('.git') != url.rstrip('/').removesuffix('.git'):
                    raise ValueError(f'Unexpected source URL for {rel}: {actual}')
                if git(path, 'status', '--porcelain', capture=True).strip():
                    raise ValueError(f'Uncommitted source changes in {rel}; review before proceeding')
                if args.update_submodules:
                    git(repo, 'submodule', 'update', '--remote', '--', rel)
            commit = git(path, 'rev-parse', 'HEAD', capture=True).strip()
            manifest['git_sources'].append({'path': rel, 'url': url, 'commit': commit, 'observed_utc': utc()})
            save()
        def fetch(group, url):
            target = data / 'raw' / group / stamp / url.rsplit('/', 1)[-1]
            target.parent.mkdir(parents=True, exist_ok=True)
            rel = str(target.relative_to(repo))
            old = next((x for x in manifest['files'] if x['path'] == rel), None)
            if target.exists():
                if old and sha(target) == old['sha256']:
                    print('Verified existing:', rel, flush=True)
                    return target, old
                raise ValueError(f'Unrecorded or changed file: {rel}; use a new snapshot or investigate')
            started = utc()
            print('Downloading:', url, flush=True)
            part = target.with_name(target.name + '.part')
            for attempt in range(4):
                try:
                    request = urllib.request.Request(url, headers={'User-Agent': 'CWE-Prediction-source-collector/1.0'})
                    with urllib.request.urlopen(request, timeout=180) as response, part.open('wb') as out:
                        headers = dict(response.headers)
                        shutil.copyfileobj(response, out, length=1024 * 1024)
                    break
                except (urllib.error.URLError, TimeoutError, OSError):
                    if attempt == 3:
                        raise
                    time.sleep(min(2 ** attempt * 3, 30))
            info = {'path': rel, 'url': url, 'started_utc': started, 'finished_utc': utc(),
                    'bytes': part.stat().st_size, 'sha256': sha(part),
                    'last_modified': headers.get('Last-Modified'), 'etag': headers.get('ETag')}
            if target.name.endswith('.gz'):
                digest = hashlib.sha256()
                size = 0
                with gzip.open(part, 'rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                        size += len(chunk)
                info.update(uncompressed_sha256=digest.hexdigest(), uncompressed_bytes=size, gzip_integrity='passed')
            elif target.name.endswith('.zip'):
                with zipfile.ZipFile(part) as archive:
                    bad = archive.testzip()
                    if bad:
                        raise ValueError(f'ZIP checksum failure: {bad}')
                    info['zip_integrity'] = 'passed'
            elif target.suffix == '.xsd':
                if ET.parse(part).getroot().tag != '{http://www.w3.org/2001/XMLSchema}schema':
                    raise ValueError('Expected an XML Schema document')
            part.replace(target)
            manifest['files'].append(info)
            save()
            return target, info
        for _, base in feeds:
            meta_path, _ = fetch('nvd-cve', base + '.meta')
            meta = dict(line.split(':', 1) for line in meta_path.read_text().splitlines() if ':' in line)
            archive_path, info = fetch('nvd-cve', base + '.json.gz')
            expected = meta.get('sha256', '').strip().lower()
            if not expected or expected != info['uncompressed_sha256']:
                raise ValueError(f'NVD metadata checksum mismatch for {archive_path.name}; upstream may have changed during acquisition. Start a new snapshot.')
            if int(meta['size'].strip()) != info['uncompressed_bytes']:
                raise ValueError('NVD metadata size mismatch')
            info['nvd_meta_verification'] = 'passed'
            save()
            time.sleep(0.5)
        for group, url in SOURCES:
            path, info = fetch(group, url)
            if path.suffix == '.zip' and group in ['cwe', 'capec']:
                # Extract only catalog XML documents; never execute archive content or trust member paths.
                with zipfile.ZipFile(path) as archive:
                    for member in archive.infolist():
                        if not member.is_dir() and member.filename.lower().endswith('.xml'):
                            target = path.parent / 'extracted' / member.filename
                            if not target.resolve().is_relative_to((path.parent / 'extracted').resolve()):
                                raise ValueError('Unsafe archive member path')
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with archive.open(member) as inp, target.open('wb') as out:
                                shutil.copyfileobj(inp, out)
                            root = ET.parse(target).getroot()
                            record = {'path': str(target.relative_to(repo)), 'parent_archive': str(path.relative_to(repo)),
                                      'sha256': sha(target), 'bytes': target.stat().st_size,
                                      'xml_root': root.tag, 'catalog_version': root.attrib.get('Version')}
                            manifest['files'] = [x for x in manifest['files'] if x['path'] != record['path']]
                            manifest['files'].append(record)
                save()
        manifest.update(status='complete', finished_utc=utc())
        manifest.pop('last_error', None)
        save()
        print('Complete. Manifest:', manifest_path)
        print('Bulk downloads stay local under data/raw/. No commit or push performed.')
    except Exception as error:
        manifest.update(status='incomplete', last_error=str(error), last_attempt_utc=utc())
        save()
        print(f'Incomplete acquisition. Resume with --snapshot {stamp}; see {manifest_path}', file=sys.stderr)
        raise

if __name__ == '__main__':
    main()
