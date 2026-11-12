#!/usr/bin/env python3
"""QA record and MAIN certification: zero builds, exactly the bytes QA certified.

QA (`--qa-record`, job qa-certification, protected qa push only): after every QA
job of the pipeline passed, read them with the job's own CI_JOB_TOKEN, require
their receipts to name this source, this pipeline, the approved controller
revision and one certified binary sha256 (core-build, core-conformance,
native-qualification), and retain the binary plus every receipt as this job's
artifacts, which never expire.

MAIN (release-certification, protected main push): main only fast-forwards to a
commit QA qualified. For the pushed main commit, find the newest successful
protected qa push pipeline at the same SHA, require each QA job (and
qa-certification) to have passed, and re-verify the retained record, receipts and
binary from qa-certification's non-expiring artifacts against the controller
revision main itself was approved to run. Anything missing or different fails:
no release. Signing, tagging and publication consume only the digest recorded
here; the Sigstore and SLSA verifications of the signed artifact belong to main
after signing, never to QA (which certifies unsigned bytes).
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
QA_SCHEMA = 'busbar.qa-certification/1'
QA_JOB = 'qa-certification'
# Every QA job of a protected qa push pipeline; each must pass exactly once.
REQUIRED = ('core-build', 'core-clippy', 'core-conformance', 'core-conformance-debug',
            'native-qualification', 'security-scans')
RECEIPT = 'boundary-evidence/receipt.json'
RECEIPT_JOBS = ('core-build', 'core-clippy', 'core-conformance', 'core-conformance-debug',
                'native-qualification')
# Receipts that certify (or judged) the one certified binary by sha256.
CERTIFYING = ('core-build', 'core-conformance', 'native-qualification')
RETAINED = 'qa-certified'
# Signed-release verifications that run on main after signing, never in QA.
AFTER_SIGNING = ('sigstore', 'slsa-verifier')


def require(value, message):
    if not value:
        raise Violation(message)


def approved_revision(env):
    """The controller revision this project's CI configuration setting selects."""
    match = re.fullmatch(r'(?:https://)?' + re.escape(env.get('CI_SERVER_HOST', '')) + '/'
                         + re.escape(env.get('CI_PROJECT_PATH', ''))
                         + r'//ci/architecture-pipeline\.yml@GetBusbar/busbar:([0-9a-f]{40})@refs/heads/[^\s]+',
                         env.get('CI_CONFIG_REF_URI', ''))
    require(match is not None, 'CI configuration does not select an approved immutable controller revision')
    return match[1]


def pipeline_jobs(api, project, pipeline):
    rows = []
    for page in range(1, 6):
        batch = api.json(f'projects/{project}/pipelines/{pipeline}/jobs?per_page=100&page={page}')
        rows.extend(batch)
        if len(batch) < 100:
            break
    return rows


def passing(rows, name):
    found = [job for job in rows if job.get('name') == name]
    require(len(found) == 1 and found[0].get('status') == 'success' and not found[0].get('allow_failure')
            and type(found[0].get('id')) is int,
            'qa pipeline lacks a single passing ' + name)
    return found[0]


def verify(fetch, jobs, sha, pipeline, approved):
    """The QA receipts and binary, through `fetch(job name, artifact path, limit)`."""
    receipts = {}
    for name in RECEIPT_JOBS:
        receipt = json.loads(fetch(name, RECEIPT, native_certified.MAX_RECEIPT_BYTES))
        require(isinstance(receipt, dict) and receipt.get('status') == 'pass' and receipt.get('source') == sha
                and receipt.get('job_id') == str(jobs[name]) and receipt.get('pipeline_id') == str(pipeline),
                name + ' receipt does not certify this commit in its qa pipeline')
        require(receipt.get('policy_revision') == approved
                and ':' + approved + '@' in str(receipt.get('config_uri')),
                name + ' ran under a controller revision other than the approved one')
        receipts[name] = receipt
    build = native_certified.verify_receipt(receipts['core-build'], job_id=jobs['core-build'], source=sha,
                                            policy=approved, pipeline=pipeline)
    digests = {name: (receipts[name].get('certified_binary') or {}).get('sha256') for name in CERTIFYING}
    require(set(digests.values()) == {build['sha256']}
            and all(receipts[name].get('binary_sha256') == build['sha256'] for name in CERTIFYING),
            'qa receipts certify different binaries: ' + json.dumps(digests, sort_keys=True))
    require((receipts['core-conformance'].get('conformance_subject') or {}).get('sha256') == build['sha256'],
            'qa conformance did not judge the certified binary')
    require((receipts['core-conformance-debug'].get('conformance_subject') or {}).get('kind') == 'debug-assertions',
            'qa debug-assertion conformance is missing')
    require(receipts['core-clippy'].get('schema') == 'busbar.core-clippy/1', 'qa clippy receipt is missing')
    data = fetch('core-build', 'boundary-evidence/busbar', native_certified.MAX_BINARY_BYTES)
    require(hashlib.sha256(data).hexdigest() == build['sha256'] and len(data) == build.get('bytes'),
            'qa core-build binary differs from its receipt')
    return receipts, build, data


def record_qa(api, env, output):
    """QA tier: verify this pipeline's QA jobs and retain the binary and receipts."""
    require(env.get('CI_PIPELINE_SOURCE') == 'push' and env.get('CI_COMMIT_BRANCH') == 'qa'
            and env.get('CI_COMMIT_REF_PROTECTED') == 'true' and env.get('CI_PROJECT_PATH') == 'GetBusbar/busbar',
            'the qa record runs only on the protected core qa push')
    sha, project, pipeline = env['CI_COMMIT_SHA'], env['CI_PROJECT_ID'], int(env['CI_PIPELINE_ID'])
    require(re.fullmatch('[0-9a-f]{40}', sha), 'invalid commit')
    approved = approved_revision(env)
    rows = pipeline_jobs(api, project, pipeline)
    jobs = {name: passing(rows, name)['id'] for name in REQUIRED}

    def fetch(name, path, limit):
        return api.raw(f'projects/{project}/jobs/{jobs[name]}/artifacts/{path}', limit)
    receipts, build, data = verify(fetch, jobs, sha, pipeline, approved)
    retained = Path(output).parent / RETAINED
    (retained / 'receipts').mkdir(parents=True)
    (retained / 'busbar').write_bytes(data)
    for name, receipt in receipts.items():
        (retained / 'receipts' / (name + '.json')).write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return {'schema': QA_SCHEMA, 'status': 'pass', 'source': sha, 'qa_pipeline_id': pipeline,
            'jobs': jobs, 'policy_revision': approved,
            'certified_binary': {'sha256': build['sha256'], 'bytes': build['bytes'],
                                 'command': build['command'], 'profile_use': build.get('profile_use')},
            'signed': False, 'after_signing': list(AFTER_SIGNING),
            'pipeline_id': env['CI_PIPELINE_ID'], 'job_id': env['CI_JOB_ID'], 'builds': 0}


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
    approved = approved_revision(env)
    pipeline = qa_pipeline(api, project, sha)
    rows = pipeline_jobs(api, project, pipeline['id'])
    jobs = {name: passing(rows, name)['id'] for name in REQUIRED}
    keeper = passing(rows, QA_JOB)['id']
    base = f'projects/{project}/jobs/{keeper}/artifacts/boundary-evidence/'
    record = json.loads(api.raw(base + 'qa-certification.json', native_certified.MAX_RECEIPT_BYTES))
    require(isinstance(record, dict) and record.get('schema') == QA_SCHEMA and record.get('status') == 'pass'
            and record.get('source') == sha and record.get('qa_pipeline_id') == pipeline['id']
            and record.get('jobs') == jobs and record.get('job_id') == str(keeper),
            'qa certification record does not certify this commit in its qa pipeline')
    require(record.get('policy_revision') == approved,
            'qa ran under controller revision ' + str(record.get('policy_revision'))
            + ', not the approved ' + approved)

    def fetch(name, path, limit):
        if path == RECEIPT:
            return api.raw(base + RETAINED + '/receipts/' + name + '.json', limit)
        require(name == 'core-build' and path == 'boundary-evidence/busbar', 'unexpected retained artifact')
        return api.raw(base + RETAINED + '/busbar', limit)
    _, build, _ = verify(fetch, jobs, sha, pipeline['id'], approved)
    require(record['certified_binary'].get('sha256') == build['sha256'], 'qa record names another binary')
    return {'schema': SCHEMA, 'status': 'pass', 'source': sha, 'qa_pipeline_id': pipeline['id'],
            'qa_certification_job_id': keeper, 'jobs': jobs, 'policy_revision': approved,
            'certified_binary': {'sha256': build['sha256'], 'bytes': build['bytes'],
                                 'command': build['command'], 'profile_use': build.get('profile_use')},
            'after_signing': list(AFTER_SIGNING),
            'pipeline_id': env['CI_PIPELINE_ID'], 'job_id': env['CI_JOB_ID'], 'builds': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--qa-record', action='store_true', help='QA tier: retain the certified QA evidence')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.qa_record:
        record = record_qa(native_certified.Api(), os.environ, args.output)
    else:
        record = certify(native_certified.Api(), os.environ)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({record['schema']: record['certified_binary']['sha256']}))


if __name__ == '__main__':
    main()
