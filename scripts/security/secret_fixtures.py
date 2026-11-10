"""Classify deliberate noncredential fixtures without suppressing scanner findings."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCHEMA = 'busbar.public-secret-fixtures/1'
FIELDS = {'id', 'repository', 'path', 'source_sha256', 'rule_id', 'start_line', 'end_line',
          'reason', 'provenance'}


def relative_path(value):
    if (not isinstance(value, str) or not value or '\\' in value
            or value.startswith('/') or any(p in ('', '.', '..') for p in value.split('/'))):
        raise ValueError('noncanonical scanner source path')
    return PurePosixPath(value)


def policy_entries(data):
    policy = json.loads(data)
    if (not isinstance(policy, dict) or set(policy) != {'schema', 'fixtures'}
            or policy['schema'] != SCHEMA or not isinstance(policy['fixtures'], list)):
        raise ValueError('invalid trusted fixture policy')
    entries = {}
    for entry in policy['fixtures']:
        if not isinstance(entry, dict) or set(entry) != FIELDS:
            raise ValueError('invalid trusted fixture entry')
        relative_path(entry['path'])
        if (any(not isinstance(entry[k], str) or not entry[k] for k in FIELDS - {'start_line', 'end_line'})
                or not re.fullmatch(r'[0-9a-f]{64}', entry['source_sha256'])
                or type(entry['start_line']) is not int or type(entry['end_line']) is not int
                or not 0 < entry['start_line'] <= entry['end_line'] or entry['id'] in entries):
            raise ValueError('invalid or duplicate trusted fixture entry')
        entries[entry['id']] = entry
    return entries


def classify(report, *, repository, source, source_rows, policy):
    """Every match requires exact committed regular-file bytes, location and rule.

    The policy bytes must come from the controller's immutable trusted checkout.
    Source rows are the controller's Git-blob inventory, never candidate metadata.
    """
    entries = policy_entries(policy)
    inventory = {row['path']: row for row in source_rows}
    source = Path(source)
    approved, used, total = [], set(), 0
    for result in report.get('Results', []):
        findings = result.get('Secrets') or []
        if not findings:
            continue
        name = result.get('Target')
        rel = relative_path(name)
        path = source
        if path.is_symlink():
            raise ValueError('indirect scanner source root')
        for part in rel.parts:
            path /= part
            if path.is_symlink():
                raise ValueError('indirect scanner source path')
        row = inventory.get(name)
        if not row or row['mode'] not in ('100644', '100755') or not path.is_file():
            raise ValueError('scanner source is not a committed regular file')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != row['sha256']:
            raise ValueError('scanner source changed after export')
        for finding in findings:
            index = total
            total += 1
            if not isinstance(finding, dict):
                raise ValueError('invalid scanner finding')
            matches = [entry for entry in entries.values() if (
                entry['repository'] == repository and entry['path'] == name
                and entry['source_sha256'] == digest and entry['rule_id'] == finding.get('RuleID')
                and type(finding.get('StartLine')) is int and type(finding.get('EndLine')) is int
                and entry['start_line'] == finding['StartLine'] and entry['end_line'] == finding['EndLine'])]
            if len(matches) == 1 and matches[0]['id'] not in used:
                entry = matches[0]
                used.add(entry['id'])
                approved.append({'finding_index': index, **entry})
    return {'classification_policy_sha256': hashlib.sha256(policy).hexdigest(),
            'classified_public_fixtures': len(approved), 'unresolved_findings': total - len(approved),
            'public_fixture_classifications': approved}
