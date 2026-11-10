#!/usr/bin/env python3
"""Scan the exact release SBOM set and every declared OCI platform before signing.

Called by the trusted publish gate. This is not a provenance producer or signer.
"""
from pathlib import Path
import json
import tempfile

from scan import Scanner, digest, require


def candidate_inventory(candidate):
    rows = {}
    for directory in ('artifacts', 'sboms', 'internal', 'plugins', 'oci'):
        root = candidate / directory
        require(root.is_dir() and not root.is_symlink(), 'candidate directory missing or symlinked')
        for path in sorted(root.rglob('*')):
            require(not path.is_symlink(), 'symlink in release candidate')
            if path.is_file():
                rows[path.relative_to(candidate).as_posix()] = digest(path)
    require(rows, 'empty release candidate')
    return rows


def scan_candidate(trusted, candidate, platforms):
    before = candidate_inventory(candidate)
    sboms = sorted(name for name in before if name.startswith('sboms/') and name.endswith('.cdx.json'))
    require(sboms and platforms and 'oci/busbar.oci.tar' in before, 'release scan subjects missing')
    # tempfile respects the operator's TMPDIR; CI sets its task-local scratch root.
    with tempfile.TemporaryDirectory(prefix='busbar-artifact-scans-') as temporary:
        scanner = Scanner(trusted, Path(temporary))
        database = scanner.prepare()
        failures = []
        for sbom in sboms:
            # Schema/closure correctness is checked by release conformance; this
            # additionally refuses empty dependency inventories and known CVEs.
            document = json.loads((candidate / sbom).read_text())
            require(document.get('bomFormat') == 'CycloneDX' and document.get('components'),
                    'empty or unsupported SBOM')
            try:
                scanner.scan(sbom, 'dependencies', candidate,
                             scanner.trivy('sbom', 'vuln', ['/input/' + sbom]))
            except ValueError as error:
                failures.append(str(error))
        for platform in sorted(set(platforms)):
            require(platform in ('linux/amd64', 'linux/arm64'), 'unsupported release image platform')
            try:
                scanner.scan('image:' + platform, 'dependencies', candidate,
                             scanner.trivy('image', 'vuln', ['--platform', platform,
                                 '--input', '/input/oci/busbar.oci.tar']))
            except ValueError as error:
                failures.append(str(error))
        require(candidate_inventory(candidate) == before, 'candidate changed during security scans')
        require(not failures, '; '.join(failures))
        return dict(schema='busbar.artifact-security/1', status='pass', subjects=before,
                    database=database, steps=scanner.steps,
                    policy_files={p.name: digest(p) for p in sorted(scanner.policy.iterdir()) if p.is_file()})


def plugin_inventory(directory, names, repository, version, source):
    """Require one digest-bound SBOM for each independently expected plugin archive."""
    require(directory.is_dir() and not directory.is_symlink(), 'invalid plugin candidate directory')
    manifest = directory / 'security-sboms.json'
    require(manifest.is_file() and not manifest.is_symlink(), 'plugin SBOM inventory required')
    document = json.loads(manifest.read_text())
    require(document.get('schema') == 'busbar.plugin-sboms/1'
            and document.get('repository') == repository and document.get('version') == version
            and document.get('source') == source, 'plugin SBOM source binding differs')
    rows = document.get('subjects')
    require(isinstance(rows, list) and len(rows) == len(names) and names, 'plugin SBOM subjects incomplete')
    subjects, used_sboms = {}, set()
    for row in rows:
        require(isinstance(row, dict), 'invalid plugin SBOM subject')
        name, sbom = row.get('artifact'), row.get('sbom')
        require(isinstance(name, str) and name in names and name not in subjects,
                'duplicate or unexpected plugin artifact')
        require(isinstance(sbom, str) and Path(sbom).name == sbom
                and sbom.endswith('.cdx.json') and sbom not in used_sboms, 'invalid or reused plugin SBOM')
        for filename, expected in ((name, row.get('artifact_sha256')), (sbom, row.get('sbom_sha256'))):
            path = directory / filename
            require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                    'plugin artifact/SBOM bytes differ')
        bom = json.loads((directory / sbom).read_text())
        component = bom.get('metadata', {}).get('component', {})
        require(bom.get('bomFormat') == 'CycloneDX' and bom.get('components')
                and component.get('name') == repository.rsplit('/', 1)[1]
                and component.get('version') == version, 'plugin SBOM identity or inventory missing')
        subjects[name] = dict(artifact_sha256=row['artifact_sha256'], sbom=sbom, sbom_sha256=row['sbom_sha256'])
        used_sboms.add(sbom)
    require(set(subjects) == set(names), 'plugin SBOM artifact set differs')
    return subjects


def scan_plugin_candidate(trusted, directory, names, repository, version, source):
    subjects = plugin_inventory(directory, names, repository, version, source)
    manifest_hash = digest(directory / 'security-sboms.json')
    with tempfile.TemporaryDirectory(prefix='busbar-plugin-scans-') as temporary:
        scanner = Scanner(trusted, Path(temporary))
        database = scanner.prepare()
        for row in subjects.values():
            scanner.scan(row['sbom'], 'dependencies', directory,
                         scanner.trivy('sbom', 'vuln', ['/input/' + row['sbom']]))
        require(plugin_inventory(directory, names, repository, version, source) == subjects
                and digest(directory / 'security-sboms.json') == manifest_hash,
                'plugin candidate changed during security scans')
        return dict(schema='busbar.plugin-security/1', status='pass', repository=repository,
                    version=version, source=source, subjects=subjects, database=database,
                    inventory_sha256=manifest_hash, steps=scanner.steps,
                    policy_files={p.name: digest(p) for p in sorted(scanner.policy.iterdir()) if p.is_file()})
