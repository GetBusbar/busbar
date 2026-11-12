#!/usr/bin/env python3
"""MAIN tier: zero builds. Verify that QA certified exactly this commit's bytes.

main only fast-forwards to a commit QA qualified. For the pushed main commit this
reads, with the job's own CI_JOB_TOKEN, the newest successful protected qa push
pipeline at the same SHA, requires its core-build, core-conformance,
native-qualification and security-scans jobs to have passed, and requires every
receipt to name this source and one certified binary sha256, which the downloaded
core-build binary must have. Anything missing or different fails: no release.
Signing, tagging and publication consume only the digests recorded here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check import Violation  # noqa: E402
import native_certified  # noqa: E402

SCHEMA = 'busbar.release-certification/1'
REQUIRED = ('core-build', 'core-conformance', 'native-qualification', 'security-scans')
RECEIPTS = {'core-build': 'boundary-evidence/receipt.json',
            'core-conformance': 'boundary-evidence/receipt.json',
            'native-qualification': 'boundary-evidence/receipt.json'}


def require(value, message):
    if not value:
        raise Violation(message)


def qa_pipeline(api, project, sha):
    rows = api.json(f'projects/{project}/pipelines?ref=qa&sha={sha}&status=success&order_by=id&sort=desc&per_page=20')
    rows = [row for row in rows if row.get('source') == 'push' and row.get('sha') == sha and row.get('ref') == 'qa']
    require(rows, 'no successful qa push pipeline qualified this commit')
    return rows[0]


def certify(api, env):
    require(env.get('CI_PIPELINE_SOURCE') == 'push' and env.get('CI_COMMIT_BRANCH') == 'main'
            and env.get('CI_COMMIT_REF_PROTECTED') == 'true' and env.get('CI_PROJECT_PATH') == 'GetBusbar/busbar',
            'release certification runs only on the protected core main push')
    sha, project = env['CI_COMMIT_SHA'], env['CI_PROJECT_ID']
    require(re.fullmatch('[0-9a-f]{40}', sha), 'invalid commit')
    pipeline = qa_pipeline(api, project, sha)
    rows = []
    for page in range(1, 6):
        batch = api.json(f'projects/{project}/pipelines/{pipeline["id"]}/jobs?per_page=100&page={page}')
        rows.extend(batch)
        if len(batch) < 100:
            break
    jobs = {}
    for name in REQUIRED:
        found = [job for job in rows if job.get('name') == name]
        require(len(found) == 1 and found[0].get('status') == 'success' and not found[0].get('allow_failure'),
                'qa pipeline lacks a single passing ' + name)
        jobs[name] = found[0]
    receipts = {}
    for name, path in RECEIPTS.items():
        receipt = json.loads(api.raw(f'projects/{project}/jobs/{jobs[name]["id"]}/artifacts/{path}',
                                     native_certified.MAX_RECEIPT_BYTES))
        require(receipt.get('status') == 'pass' and receipt.get('source') == sha
                and receipt.get('job_id') == str(jobs[name]['id']) and receipt.get('pipeline_id') == str(pipeline['id']),
                name + ' receipt does not certify this commit in its qa pipeline')
        receipts[name] = receipt
    build = native_certified.verify_receipt(receipts['core-build'], job_id=jobs['core-build']['id'], source=sha,
                                            policy=receipts['core-build']['policy_revision'],
                                            pipeline=pipeline['id'])
    digests = {name: (receipt.get('certified_binary') or {}).get('sha256') for name, receipt in receipts.items()}
    require(set(digests.values()) == {build['sha256']}
            and all(receipt.get('binary_sha256') == build['sha256'] for receipt in receipts.values()),
            'qa receipts certify different binaries: ' + json.dumps(digests, sort_keys=True))
    policies = {receipt['policy_revision'] for receipt in receipts.values()}
    require(len(policies) == 1, 'qa jobs ran under different controller revisions')
    data = api.raw(f'projects/{project}/jobs/{jobs["core-build"]["id"]}/artifacts/boundary-evidence/busbar',
                   native_certified.MAX_BINARY_BYTES)
    require(hashlib.sha256(data).hexdigest() == build['sha256'], 'qa core-build binary differs from its receipt')
    return {'schema': SCHEMA, 'status': 'pass', 'source': sha, 'qa_pipeline_id': pipeline['id'],
            'jobs': {name: job['id'] for name, job in jobs.items()}, 'policy_revision': policies.pop(),
            'certified_binary': {'sha256': build['sha256'], 'bytes': build['bytes'],
                                 'command': build['command'], 'profile_use': build.get('profile_use')},
            'pipeline_id': env['CI_PIPELINE_ID'], 'job_id': env['CI_JOB_ID'], 'builds': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    record = certify(native_certified.Api(), os.environ)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'release_certification': record['certified_binary']['sha256']}))


if __name__ == '__main__':
    main()
