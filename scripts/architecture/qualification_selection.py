"""Owner-side, per-job qualification selection; proof files are never credentials.

The caller supplies canonical object stores and its authenticated resolver. No
owner credential or selection authority is made available to candidate jobs.
"""
from __future__ import annotations

import json
from pathlib import Path
import tomllib

import input_identity as identity

KINDS = {'native': 'native-qualification', 'security': 'security-scans',
         'conformance': 'core-conformance'}
LIVE = {'created', 'pending', 'running', 'preparing', 'waiting_for_resource',
        'scheduled', 'manual'}
SCOPES = {'verify-execution-reuse': 'execution-equivalent',
          'verify-retained-check': 'retained-check',
          'verify-component-retention': 'retained-component'}


def requirements(row, objects):
    """Read the current immutable policy, including embedded owner protocols."""
    from native_policy import native_settings
    policy = tomllib.loads(objects.blob(identity.CORE, row['policy'],
                                        'ci/architecture.toml').decode())
    repository = row['repository']
    identity.require(repository in policy['repositories'] or repository in
                     (identity.CORE, 'GetBusbar/busbar-release'), 'unknown qualification owner')
    settings = native_settings(repository, policy)
    coverage = json.loads(objects.blob(identity.CORE, row['policy'],
                                       'conformance/ci-coverage.json'))
    identity.require(coverage.get('schema') == 'busbar.conformance.ci-coverage/1',
                     'unknown current coverage schema')
    suites = {name: value for name, value in coverage['suites'].items()
              if value.get('repo') == repository}
    if settings.get('required_conformance'):
        identity.require(suites and all(isinstance(value.get('command'), str)
                         and value['command'] for value in suites.values()),
                         'current owner conformance inventory incomplete')
    result = {'native': dict(job='native-qualification',
                            suites=sorted(suites) if settings.get('required_conformance') else []),
              'security': dict(job='security-scans', suites=[])}
    if repository == identity.CORE or settings.get('external_conformance'):
        result['conformance'] = dict(job='core-conformance' if repository == identity.CORE
                                     else 'external-conformance', suites=sorted(suites))
    return result


def request_for(row, job):
    return identity.checked_request({**{key: row[key] for key in
        ('repository', 'source', 'host', 'sdk', 'policy')}, 'job': job})


def canonical_observation(resolver, candidate):
    """One bounded read of an explicitly selected original job, never a poller."""
    original = identity.checked_request(candidate['request'])
    # URL escaping is deliberately separate from identity's canonical JSON.
    from urllib.parse import quote
    project = resolver._json(resolver.api, 'projects/' + quote(original['repository'], safe=''))
    identity.require(project.get('path_with_namespace') == original['repository']
                     and project.get('id') == candidate['project'], 'original project differs')
    identity.require(not original['repository'].startswith('BusbarInc/')
                     or project.get('visibility') == 'private', 'private owner became public')
    base = 'projects/' + str(candidate['project'])
    pipeline = resolver._json(resolver.api, base + '/pipelines/' + str(candidate['pipeline']))
    identity.require(pipeline.get('id') == candidate['pipeline']
                     and pipeline.get('project_id') == candidate['project']
                     and pipeline.get('sha') == original['source']
                     and pipeline.get('ref') == 'dev' and pipeline.get('source') in ('api', 'push')
                     and (pipeline.get('user') or {}).get('id') in resolver.owner_users,
                     'original owner pipeline differs')
    jobs = resolver._all(resolver.api, base + '/pipelines/' + str(candidate['pipeline']) + '/jobs')
    matches = [job for job in jobs if job.get('name') == original['job']]
    if not matches and pipeline['status'] in LIVE:
        return dict(project=project['id'], pipeline=pipeline['id'], job=None,
                    status='created', pipeline_status=pipeline['status'])
    identity.require(len(matches) == 1, 'missing or ambiguous original mandatory job')
    job = matches[0]
    identity.require(job.get('allow_failure') is False and type(job.get('id')) is int
                     and (candidate.get('job') is None or job['id'] == candidate['job']),
                     'original mandatory job differs')
    return dict(project=project['id'], pipeline=pipeline['id'], job=job['id'],
                status=job['status'], pipeline_status=pipeline['status'])


def proof_context(entry, resolver, objects, *, database=None, now=None):
    """Load untrusted saved bytes; consumers MUST call verify_reuse with this."""
    result = dict(proof=json.loads(Path(entry['proof_path']).read_bytes()),
                  objects=objects, verifier=identity,
                  receipt_bytes=Path(entry['receipt_path']).read_bytes(),
                  artifact_bytes=Path(entry['artifact_path']).read_bytes(),
                  authenticate_original=resolver.authenticate_original,
                  validate_original=resolver.validate_original)
    if database is not None:
        result['database'] = database
    if now is not None:
        result['now'] = now
    return result


def plan_row(row, candidates, objects, resolver, evidence_dir, *, database=None,
             now=None, observe=None):
    """Retain only authenticated complete checks; keep live originals pending.

    candidates contain controller-known {request, project, pipeline, job?, receipt?}.
    Receipt JSON is merely a locator: resolve() must fetch its canonical bytes.
    The optional observation callback is controller code, never proof input.
    """
    result = {key: row[key] for key in ('repository', 'source', 'sdk', 'host', 'policy', 'project')}
    needed = requirements(row, objects)
    result['required'] = needed
    result['qualifications'] = {}
    observe = observe or (lambda candidate: canonical_observation(resolver, candidate))
    for kind, requirement in needed.items():
        requested = request_for(row, requirement['job'])
        failures, waiting, retained = [], None, None
        for candidate in candidates:
            try:
                original = identity.checked_request(candidate['request'])
                if original['repository'] != row['repository'] or original['job'] != requested['job']:
                    continue
                proposal = identity.plan_reuse(original, requested, objects, database=database, now=now)
                scope = SCOPES.get(proposal['action'])
                if not scope:
                    failures.append(proposal['reason'])
                    continue
                if scope == 'retained-component' and requirement['suites']:
                    failures.append('component evidence cannot satisfy current owner protocol requirements')
                    continue
                observation = observe(candidate)
                origin = {**{k: original[k] for k in ('repository', 'source', 'host', 'sdk', 'policy')},
                          **{k: observation[k] for k in ('project', 'pipeline', 'job')}}
                if observation['status'] in LIVE or (observation['status'] == 'success'
                                                      and observation['pipeline_status'] in LIVE):
                    waiting = dict(mode='pending', origin=origin, proposed_scope=scope,
                                   reason='original qualifying pipeline is still active; no duplicate launch')
                    continue
                identity.require(observation['status'] == 'success', 'original required job did not pass')
                receipt_hint = candidate.get('receipt')
                if receipt_hint is None:
                    filename = 'security.json' if kind == 'security' else 'receipt.json'
                    receipt_hint = json.loads(resolver._raw('projects/' + str(origin['project'])
                        + '/jobs/' + str(origin['job']) + '/artifacts/boundary-evidence/' + filename))
                context = resolver.resolve(original, receipt_hint)
                receipt_bytes, artifact_bytes = context['receipt_bytes'], context['artifact_bytes']
                receipt = json.loads(receipt_bytes)
                identity.require(str(receipt['job_id']) == str(origin['job'])
                                 and str(receipt['pipeline_id']) == str(origin['pipeline']),
                                 'resolved evidence differs from observed original job')
                kwargs = dict(receipt_bytes=receipt_bytes, artifact_bytes=artifact_bytes,
                              authenticate_original=resolver.authenticate_original,
                              validate_original=resolver.validate_original, database=database, now=now)
                proof = identity.make_proof(original, requested, objects, scope=scope, **kwargs)
                verified = identity.verify_reuse(proof, requested, objects, **kwargs)
                destination = (Path(evidence_dir) / row['repository'] / kind / str(origin['job'])
                               / identity.sha(identity.encoded(requested)))
                destination.mkdir(parents=True, exist_ok=True)
                paths = dict(proof_path=destination / 'proof.json', receipt_path=destination / 'receipt.json',
                             artifact_path=destination / 'artifact.zip')
                paths['proof_path'].write_bytes(identity.encoded(proof))
                paths['receipt_path'].write_bytes(receipt_bytes)
                paths['artifact_path'].write_bytes(artifact_bytes)
                retained = dict(mode='retained', origin=origin, scope=scope,
                                **{key: str(path.resolve()) for key, path in paths.items()},
                                identity_sha256=verified['identity_sha256'],
                                requires_fresh_assembly=verified['requires_fresh_assembly'])
                break
            except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
                failures.append(str(error))
        result['qualifications'][kind] = retained or waiting or dict(
            mode='fresh', reason=failures[-1] if failures else 'no authenticated original evidence')
    modes = {value['mode'] for value in result['qualifications'].values()}
    # Existing YAML starts every required kind. Defer an owner with live reusable
    # work even if another kind is fresh, so that launch cannot duplicate it.
    result['state'] = 'pending' if 'pending' in modes else 'selected' if 'fresh' in modes else 'retained'
    result['fresh_kinds'] = [kind for kind, value in result['qualifications'].items() if value['mode'] == 'fresh']
    return result


def plan_cohort(rows, originals, objects, resolver, evidence_dir, **kwargs):
    identity.require(len({row['repository'] for row in rows}) == len(rows), 'duplicate qualification owner')
    return [plan_row(row, originals.get(row['repository'], []), objects, resolver, evidence_dir, **kwargs)
            for row in rows]


def execute_plan(rows, launch, *, fresh_repositories):
    """Only an explicit exact fresh repository set can cause pipeline POSTs.

    launch is trusted owner-side code preserving source/protection checks. The
    existing pipeline YAML can still execute retained kinds in a fresh owner
    pipeline; selection does not pretend that those jobs were suppressed.
    """
    planned = {row['repository'] for row in rows if row['fresh_kinds'] and row['state'] == 'selected'}
    identity.require(set(fresh_repositories) == planned, 'explicit fresh repositories differ from plan')
    for row in rows:
        if row['repository'] not in planned:
            continue
        pipeline = launch(row)
        identity.require(type(pipeline.get('id')) is int and pipeline.get('sha') == row['source'],
                         'launched pipeline source differs')
        row.update(pipeline=pipeline['id'], status=pipeline['status'], state='selected',
                   execution_note='Existing pipeline YAML may also execute retained kinds.')
        for kind in row['fresh_kinds']:
            row['qualifications'][kind]['pipeline'] = pipeline['id']
    return rows


def owner_preflight(api, groups, row):
    from admission import encoded, validate_protection
    base = 'projects/' + encoded(row['repository'])
    project = api.request(base)
    if (project.get('path_with_namespace') != row['repository']
            or ('project' in row and project.get('id') != row['project'])):
        raise ValueError('canonical repository differs')
    if row['repository'].startswith('BusbarInc/') and project.get('visibility') != 'private':
        raise ValueError('private repository visibility changed')
    before = api.all(base + '/protected_branches')
    validate_protection(before, groups[row['repository'].split('/')[0]], {6, 8})
    if api.request(base + '/repository/branches/dev')['commit']['id'] != row['source']:
        raise ValueError('source moved')
    if (project.get('merge_method') != 'ff'
            or project.get('only_allow_merge_if_pipeline_succeeds') is not True
            or project.get('allow_merge_on_skipped_pipeline') is not False
            or project.get('ci_pipeline_variables_minimum_override_role') != 'no_one_allowed'):
        raise ValueError('protected admission settings changed')
    return base, project, before


def launch_fresh(api, groups, row):
    base, project, before = owner_preflight(api, groups, row)
    config = 'ci/architecture-pipeline.yml@GetBusbar/busbar:' + row['policy']
    if project['ci_config_path'] != config:
        api.request(base, 'PUT', {'ci_config_path': config})
    if row['repository'] != 'GetBusbar/busbar':
        key = 'BUSBAR_ADMISSION_CORE_REVISION'
        variables = [value for value in api.all(base + '/variables') if value['key'] == key]
        if len(variables) != 1 or not variables[0]['protected'] or variables[0]['environment_scope'] != '*':
            raise ValueError('protected host variable differs')
        old = variables[0]
        if old['value'] != row['host']:
            api.request(base + '/variables/' + key, 'PUT', {'value': row['host']})
        current = api.request(base + '/variables/' + key)
        if current['value'] != row['host'] or any(current[field] != old[field] for field in
                ('protected', 'masked', 'raw', 'environment_scope', 'variable_type')):
            raise ValueError('host variable protections changed')
    if api.request(base)['ci_config_path'] != config or api.all(base + '/protected_branches') != before:
        raise ValueError('selector or protection readback differs')
    if api.request(base + '/repository/branches/dev')['commit']['id'] != row['source']:
        raise ValueError('source moved before launch')
    return api.request(base + '/pipeline', 'POST', {'ref': 'dev'})

