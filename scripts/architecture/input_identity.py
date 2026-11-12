"""Controller-computed identities for retaining protected CI evidence.

This is an evidence verifier, never an artifact cache. Callers authenticate the
original job and validate its complete artifacts with the original immutable
validator. A proof is only a reproducible comparison, not an authorization token.
Git objects, current database identity and expected job identities must come from
the controller, never from candidate-provided manifests or a proof's assertions.
"""
from __future__ import annotations

import ast
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


CORE = 'GetBusbar/busbar'
JOBS = {'native-qualification', 'core-build', 'core-conformance', 'external-conformance', 'security-scans'}


def requires_changed_source_checks(request):
    """Security, core-native and the certified core build rerun on any changed source."""
    return request['job'] == 'security-scans' or (
        request['repository'] == CORE and request['job'] in ('native-qualification', 'core-build'))
FIELDS = {'repository', 'source', 'policy', 'host', 'sdk', 'job'}
SCHEMA = 'busbar.protected-input-reuse/1'
REUSE_CONTROLLERS = {'scripts/architecture/input_identity.py', 'scripts/architecture/reuse_evidence.py',
                     'scripts/architecture/qualification_selection.py'}
PREPARATION_SELECTOR = 'scripts/architecture/native_sources.py'
TRIVY_METADATA_CONTRACT_IMAGE = ('mirror.gcr.io/aquasec/trivy:0.76.2@sha256:'
    '8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb')
TRIVY_METADATA_CONTRACT_SCANNER = '0860330d2bbc1b2bf47b444ea6db82fa139656fe715f8c7aee9f7543e5fc3011'
# Exact approved ASTs before/after the core-only 5563 reader repair. These are
# complete function shapes, including every default, assertion and source check.
ARTIFACT_READER_SHAPES = {
    'blob': ('164a5db69e454ec9ab910542ff05f3836b2e2c8eb9b6cd5e0168bf8f4bba6c20',
             'd0992d045ec6e53e8c0e89a2b0ec76ebca9b2902698aac8b743f21c1dd2a70ad'),
    'plan': ('5b38eab9226512ede5d32c53e71b97b4d6e41c28445f662b63b717b88aa00f93',
             '85273bcd222f9c0440fb6b4e5b7833601a3a2c61bc81959c2bbd557b1a765f50'),
}
PRODUCT_INPUT_LOAD_SHAPES = ('f848d42dd3fadae923230bba6dfea7158bdec5627deca5ad940577ef570b6bd2',
                             '8f1767e72c0c5d772cf61994317ee955cb93369de5bf19f69a3e8e87f5b2f41f')
PRODUCT_INPUT_IMPORT_SHAPES = ('6ccfb6784b3dc9524d5b7f48ea26a4f77cb2e372a5e59224ef0089e0da89ad3c',
                               'f79e8db3dff2dce838290efffbf59460b06ad2070a4e7722cfb0d962abde141c')
# Finite adapters for the two approved pure selectors, not a general Python
# evaluator. Unknown selectors (including new side effects or checks) fail closed.
LEGACY_STANDALONE_SELECTOR = '''def standalone_products(repository, evaluation_only, vector):
    if type(evaluation_only) is not bool:
        raise ValueError('standalone product selection requires the controller job mode')
    return vector['products'] if repository == 'GetBusbar/busbar' and not evaluation_only else []
'''
OIDC_STANDALONE_SELECTOR = '''def standalone_products(repository, evaluation_only, vector):
    if type(evaluation_only) is not bool:
        raise ValueError('standalone product selection requires the controller job mode')
    if repository == 'GetBusbar/busbar' and not evaluation_only:
        return vector['products']
    if repository in ('GetBusbar/busbar', 'GetBusbar/busbar-release'):
        selected = [row for row in vector['products'] if row['repo'] == 'busbar-auth-oidc']
        if len(selected) != 1:
            raise ValueError('required OIDC SDK consumer graph is absent or ambiguous')
        return selected
    return []
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def checked_request(request):
    require(isinstance(request, dict) and set(request) == FIELDS, 'invalid reuse request fields')
    require(isinstance(request['repository'], str) and re.fullmatch(
        r'(?:GetBusbar|BusbarInc)/[A-Za-z0-9_.-]+', request['repository']), 'invalid repository')
    require(request['job'] in JOBS, 'unsupported reusable job')
    for name in ('source', 'policy', 'host', 'sdk'):
        require(isinstance(request[name], str) and re.fullmatch('[0-9a-f]{40}', request[name]),
                'immutable ' + name + ' revision required')
    return dict(request)


class GitObjects:
    """Read exact immutable objects; no checkout, hooks, filters or candidate code.

    The controller resolves these local stores from canonical repositories. A
    candidate cannot supply a store, a path selection or an exclusion list.
    """

    def __init__(self, repositories):
        self.repositories = {name: Path(path).resolve() for name, path in repositories.items()}
        self._trees = {}
        self._blobs = {}

    def git(self, repository, *args):
        require(repository in self.repositories, 'missing canonical object store: ' + repository)
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.fsmonitor=false', '-C', str(self.repositories[repository]), *args])

    def tree(self, repository, revision):
        if (repository, revision) in self._trees:
            return self._trees[repository, revision]
        require(re.fullmatch('[0-9a-f]{40}', revision), 'immutable Git object required')
        require(self.git(repository, 'rev-parse', revision + '^{commit}').decode().strip() == revision,
                'revision is not the requested commit')
        records = self.git(repository, 'ls-tree', '-rz', revision).split(b'\0')
        rows = {}
        for record in records:
            if not record:
                continue
            header, raw_path = record.split(b'\t', 1)
            mode, kind, oid = header.decode().split()
            path = raw_path.decode('utf-8')
            require(kind == 'blob' and mode in ('100644', '100755', '120000'),
                    'submodules or unsupported source object require fresh qualification')
            require(not path.startswith('/') and '..' not in path.split('/'), 'invalid Git path')
            rows[path] = {'mode': mode, 'blob': oid}
        require(rows, 'empty immutable source tree')
        self._trees[repository, revision] = rows
        return rows

    def blob(self, repository, revision, path):
        # Paths below are selected by this controller, never by proof fields.
        key = repository, revision, path
        if key not in self._blobs:
            self._blobs[key] = self.git(repository, 'show', revision + ':' + path)
        return self._blobs[key]


def database_identity(database, tools, now):
    require(isinstance(database, dict) and set(database) ==
            {'updated_at', 'sha256', 'metadata_sha256'}, 'missing current advisory identity')
    for key in ('sha256', 'metadata_sha256'):
        require(isinstance(database[key], str) and re.fullmatch('[0-9a-f]{64}', database[key]),
                'invalid advisory digest')
    require(now.tzinfo is not None, 'reuse verification needs an aware clock')
    updated = dt.datetime.fromisoformat(database['updated_at'].replace('Z', '+00:00'))
    maximum = tools.get('database_max_age_hours')
    require(type(maximum) is int and maximum > 0, 'invalid advisory freshness policy')
    require(updated.tzinfo is not None and dt.timedelta() <= now - updated <= dt.timedelta(hours=maximum),
            'advisory database is stale or future-dated')
    return dict(database)


def semantic_database_identity(database, tools, now, *, scanner_sha256):
    """Actual scanned content/freshness under the one verified scanner contract.

    Original metadata_sha256 remains mandatory authenticated receipt provenance;
    this does NOT assert equality of unavailable original metadata JSON fields.
    Trivy v0.76.2 pkg/db/db.go NeedsUpdate(skip=true) validates that metadata.Version
    equals its compiled schema, then returns BEFORE NextUpdate/DownloadedAt
    scheduling. The exact wrapper below always passes --skip-db-update and checks
    UpdatedAt freshness. Both successful authenticated scans must use that same
    image/policy. Thus content SHA + UpdatedAt + this pinned schema-check contract
    identify the scanning inputs, while per-download metadata bytes do not.
    Source: https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.2/pkg/db/db.go
    """
    original = database_identity(database, tools, now)
    require(tools.get('trivy') == TRIVY_METADATA_CONTRACT_IMAGE
            and scanner_sha256 == TRIVY_METADATA_CONTRACT_SCANNER,
            'unknown scanner metadata consumption contract; fresh scan required')
    return {'sha256': original['sha256'], 'updated_at': original['updated_at'],
            'scanner_image': tools['trivy'], 'schema_validation': 'trivy-0.76.2--skip-db-update'}


def security_database_identity(request, objects, database, now):
    tools = json.loads(objects.blob(CORE, request['policy'], 'ci/security/tools.json'))
    scanner = sha(objects.blob(CORE, request['policy'], 'scripts/security/scan.py'))
    return semantic_database_identity(database, tools, now, scanner_sha256=scanner)


def compute_identity(request, objects, *, database=None, now=None):
    """Compute actual inputs, keeping revision-observable execution conservative.

    Security's exporter reads every blob but exports no Git metadata and executes
    no candidate code: identical trees across commits are equivalent. Native
    execution exposes source history, host revision and complete trusted/host
    trees. Its revision identities cannot be discarded based on source heuristics
    (build.rs, env! and runtime code can observe them). A different aggregate
    assembly may retain this evidence under its ORIGINAL execution context, but
    cannot call that proof execution against a new host.
    """
    request = checked_request(request)
    source = objects.tree(request['repository'], request['source'])
    policy = objects.tree(CORE, request['policy'])
    result = {'schema': 'busbar.protected-input-identity/1', 'repository': request['repository'],
              'job': request['job'], 'source_tree_sha256': sha(encoded(source))}
    if request['job'] == 'security-scans':
        # These are all trusted executable/configuration inputs of the dedicated
        # scanner and bootstrap. Entire directories include newly added inputs.
        paths = {name: row for name, row in policy.items() if name.startswith(
            ('scripts/security/', 'ci/security/')) or name == 'ci/architecture-pipeline.yml'}
        require('scripts/security/scan.py' in paths and 'ci/security/tools.json' in paths
                and 'ci/architecture-pipeline.yml' in paths, 'incomplete security controller')
        result['policy_inputs_sha256'] = sha(encoded(paths))
        result['database'] = security_database_identity(request, objects, database,
                                                        now or dt.datetime.now(dt.timezone.utc))
    else:
        result.update(source_revision=request['source'], policy_revision=request['policy'],
            policy_tree_sha256=sha(encoded(policy)), host_revision=request['host'],
            host_tree_sha256=sha(encoded(objects.tree(CORE, request['host']))),
            sdk_revision=request['sdk'], sdk_tree_sha256=sha(encoded(objects.tree(CORE, request['sdk']))))
        vector = json.loads(objects.blob(CORE, request['host'], 'scripts/ci-product-pins.json'))
        require(vector.get('sdk') == request['sdk'], 'host and SDK identity differ')
        # Exact immutable vector covers dynamically loaded products too, including
        # locks/features encoded in each dependency's commit. No graph pruning.
        result['dependency_vector_sha256'] = sha(encoded(vector))
    return result


def receipt_request(receipt, job, *, host=None, sdk=None):
    """Project unmodified receipt provenance; security has no host dependency."""
    return checked_request({'repository': receipt.get('repository'), 'source': receipt.get('source'),
        'policy': receipt.get('policy_revision'), 'host': receipt.get('host_revision', host),
        'sdk': receipt.get('sdk_revision', sdk), 'job': job})


def core_regression_only(path):
    """Fixed controller-owned selection; no candidate/caller exclusions."""
    value = Path(path)
    return (value.parent.as_posix() == 'scripts/architecture'
            and value.name.startswith('test_') and value.suffix == '.py')


def ast_shape(node):
    """Version-stable shape for Python 3.11+; positions/comments are not code."""
    if isinstance(node, ast.AST):
        shape = {'node': type(node).__name__, **{name: ast_shape(getattr(node, name))
                for name in node._fields if not (name == 'type_params' and not getattr(node, name))}}
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # Before Python 3.15 imports were always eager. Preserve the 3.15
            # approved hashes without discarding a nonzero lazy-import flag.
            shape.setdefault('is_lazy', 0)
        return shape
    if isinstance(node, list):
        return [ast_shape(value) for value in node]
    return node


def parsed_source(payload):
    require(isinstance(payload, bytes), 'immutable controller source bytes required')
    try:
        text = payload.decode('utf-8')
        return text, ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise ValueError('unrecognized controller source') from error


def common_source_identity(text, replacements):
    lines = text.splitlines(keepends=True)
    for node, label in sorted(replacements, key=lambda row: row[0].lineno, reverse=True):
        lines[node.lineno - 1:node.end_lineno] = ['<approved-controller-projection:' + label + '>\n']
    return sha(''.join(lines).encode())


def default_artifact_reader_identity(payload):
    """Prove default plan/blob behavior across the exact approved 5563 repair.

    The new keyword-only git_reader defaults to the unchanged generic git. Only
    core-native load_product_inputs opts into canonical_git; all other production
    callers use the default. Complete old/new function ASTs are pinned, so path,
    revision, type, size, hash and ownership checks cannot be dropped or changed.
    Every byte outside plan/blob (including generic git) remains significant.
    This is not permission to project an arbitrary custom-reader call.
    """
    text, module = parsed_source(payload)
    replacements, functions, versions = [], {}, []
    for name, approved in ARTIFACT_READER_SHAPES.items():
        nodes = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == name]
        require(len(nodes) == 1, 'missing or ambiguous artifact reader function')
        shape = sha(encoded(ast_shape(nodes[0])))
        require(shape in approved,
                'unknown artifact reader default or source checks')
        versions.append(approved.index(shape))
        replacements.append((nodes[0], name))
        functions[name] = approved[0]
    require(len(set(versions)) == 1, 'mixed artifact reader versions are not an approved contract')
    return {'schema': 'busbar.default-artifact-reader/1',
            'common_source_sha256': common_source_identity(text, replacements), 'functions': functions}


def product_input_source_identity(payload, repository, job):
    """Keep the shared ProductInputs class; isolate only approved core readback."""
    require(job in JOBS and job != 'security-scans', 'invalid product input caller')
    text, module = parsed_source(payload)
    loads = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == 'load_product_inputs']
    imports = [node for node in module.body if isinstance(node, ast.ImportFrom)
               and node.module == 'product_artifacts']
    require(len(loads) == len(imports) == 1, 'missing or ambiguous product input reader')
    load = sha(encoded(ast_shape(loads[0])))
    imported = sha(encoded(ast_shape(imports[0])))
    require(load in PRODUCT_INPUT_LOAD_SHAPES and imported in PRODUCT_INPUT_IMPORT_SHAPES
            and PRODUCT_INPUT_LOAD_SHAPES.index(load) == PRODUCT_INPUT_IMPORT_SHAPES.index(imported),
            'unknown product input readback or import contract')
    return {'schema': 'busbar.product-input-reader/1',
            'common_source_sha256': common_source_identity(text, [(loads[0], 'core-readback'),
                                                                    (imports[0], 'artifact-imports')]),
            'load_contract': load if repository == CORE and job == 'native-qualification'
                                 else 'not-invoked-by-this-protected-job'}


def preparation_source_identity(payload, repository, job, vector):
    """Hash the exact common preparation code plus its selected immutable rows.

    Only the approved pure standalone_products function is projected. Its AST
    must match one of the complete templates above after removing a docstring;
    no module/function is executed. Every byte outside that function remains
    significant. Selected product rows retain commit, SDK and exact lock hash;
    native_seed.py, its manifest processing, Git closure and collector controls
    remain hashed in full by the caller. This supports historical unchanged-work
    qualification, never strict execution equivalence at another Git revision.
    """
    require(isinstance(payload, bytes), 'immutable preparation source bytes required')
    try:
        text = payload.decode('utf-8')
        module = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise ValueError('unrecognized preparation source') from error
    functions = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == 'standalone_products']
    require(len(functions) == 1, 'missing or ambiguous preparation selector')
    function = functions[0]
    shape = copy.deepcopy(function)
    if (shape.body and isinstance(shape.body[0], ast.Expr)
            and isinstance(shape.body[0].value, ast.Constant)
            and isinstance(shape.body[0].value.value, str)):
        shape.body.pop(0)
    actual = ast.dump(shape, include_attributes=False)
    legacy = ast.dump(ast.parse(LEGACY_STANDALONE_SELECTOR).body[0], include_attributes=False)
    oidc = ast.dump(ast.parse(OIDC_STANDALONE_SELECTOR).body[0], include_attributes=False)
    require(actual in (legacy, oidc), 'unapproved or impure preparation selector')
    require(job in JOBS and job != 'security-scans', 'invalid preparation job')
    require(isinstance(vector, dict) and isinstance(vector.get('products'), list),
            'preparation requires the actual immutable product vector')
    evaluation_only = job != 'native-qualification'
    if repository == CORE and not evaluation_only:
        selected = vector['products']
    elif actual == oidc and repository in (CORE, 'GetBusbar/busbar-release'):
        selected = [row for row in vector['products'] if row['repo'] == 'busbar-auth-oidc']
        require(len(selected) == 1, 'required OIDC SDK consumer graph is absent or ambiguous')
    else:
        selected = []
    lines = text.splitlines(keepends=True)
    # Keep decorators, imports, other functions, assertions and comments outside
    # this exact span byte-identical. Decorated selectors already fail AST match.
    common = (''.join(lines[:function.lineno - 1]) + '<approved-pure-preparation-selector>\n'
              + ''.join(lines[function.end_lineno:])).encode()
    return {'common_source_sha256': sha(common), 'selected_products': selected}


def prepared_core_tree(objects, revision, request):
    """Project one known pure selector; never omit an entire preparation file."""
    tree = dict(objects.tree(CORE, revision))
    if PREPARATION_SELECTOR in tree:
        vector = json.loads(objects.blob(CORE, request['host'], 'scripts/ci-product-pins.json'))
        projected = preparation_source_identity(objects.blob(CORE, revision, PREPARATION_SELECTOR),
                                                request['repository'], request['job'], vector)
        tree[PREPARATION_SELECTOR] = {'mode': tree[PREPARATION_SELECTOR]['mode'],
                                     'preparation_sha256': sha(encoded(projected))}
    artifact = 'scripts/architecture/product_artifacts.py'
    inputs = 'scripts/architecture/native_product_inputs.py'
    # Core-native uses the newly opted-in reader and must remain fresh. All other
    # protected jobs keep the original reader; their native.py/caller source and
    # every other policy input remain hashed, so a new opt-in cannot be hidden.
    if not (request['repository'] == CORE and request['job'] == 'native-qualification'):
        if artifact in tree:
            projected = default_artifact_reader_identity(objects.blob(CORE, revision, artifact))
            tree[artifact] = {'mode': tree[artifact]['mode'], 'default_reader_sha256': sha(encoded(projected))}
        if inputs in tree:
            projected = product_input_source_identity(objects.blob(CORE, revision, inputs),
                                                       request['repository'], request['job'])
            tree[inputs] = {'mode': tree[inputs]['mode'], 'caller_inputs_sha256': sha(encoded(projected))}
    return tree


def retained_check_identity(request, objects):
    """Retain the original check when its executed inputs remain unchanged.

    These immediate test modules execute through native.core_regressions(), only
    in core-native. The separate isolation diagnostic is not a reusable job.
    Core conformance's release/security engineering tests are outside this set.
    A recognized pure preparation selector may also change only if its selected
    immutable rows are identical; its remaining module bytes stay significant.
    Every other path, including all executed assertions, runtime fixtures, full
    dynamic host/product graph and locks remains significant. Git observations
    remain historical: this is an unchanged-workload qualification, not a claim
    of execution at the new commit or byte-equivalent produced artifacts.
    """
    request = checked_request(request)
    require(not requires_changed_source_checks(request),
            'core-native, core-build and security require their actual changed source checks')

    def core_tree(revision):
        return {name: row for name, row in prepared_core_tree(objects, revision, request).items()
                if not core_regression_only(name) and name not in REUSE_CONTROLLERS}

    if request['repository'] == CORE:
        require(request['source'] == request['host'], 'core source and execution host differ')
        source = core_tree(request['source'])
    else:
        source = objects.tree(request['repository'], request['source'])
    vector = json.loads(objects.blob(CORE, request['host'], 'scripts/ci-product-pins.json'))
    require(vector.get('sdk') == request['sdk'], 'host and SDK identity differ')
    result = {'schema': 'busbar.retained-check-inputs/1', 'repository': request['repository'],
              'job': request['job'], 'source_tree_sha256': sha(encoded(source)),
              'policy_tree_sha256': sha(encoded(core_tree(request['policy']))),
              'host_tree_sha256': sha(encoded(core_tree(request['host']))),
              'sdk_revision': request['sdk'],
              'sdk_tree_sha256': sha(encoded(objects.tree(CORE, request['sdk'])))}
    if request['repository'] != CORE:
        result['source_revision'] = request['source']
    return result


def runtime_contract(objects, revision, request):
    """Core runtime inputs, independent of the separately qualified distribution.

    Cargo explicitly marks unused patches as outside the resolved package graph.
    Remove only those matching manifest patches, retaining all resolved packages,
    features, profile settings, build scripts, tests and toolchain configuration.
    No candidate pattern or caller exclusion list can change this selection.
    """
    tree = prepared_core_tree(objects, revision, request)
    paths = {name: row for name, row in tree.items()
             if (name.startswith(('crates/', '.cargo/', 'scripts/', 'ci/', 'testing/'))
                 or name in {'rust-toolchain.toml', 'build.rs', 'deny.toml', 'rustfmt.toml'})
             and name != 'scripts/ci-product-pins.json' and name not in REUSE_CONTROLLERS
             and not core_regression_only(name)
             and not name.startswith('testing/evidence-conformance/')}
    manifest = tomllib.loads(objects.blob(CORE, revision, 'Cargo.toml').decode())
    lock = tomllib.loads(objects.blob(CORE, revision, 'Cargo.lock').decode())
    patches = manifest.get('patch', {}).get('crates-io', {})
    used = {row['name'] for row in lock.get('package', [])}
    unused = lock.get('patch', {}).get('unused', [])
    for row in unused:
        name = row['name']
        patch = patches.get(name)
        if (name not in used and isinstance(patch, dict) and set(patch) == {'git', 'rev'}
                and row.get('source') == 'git+' + patch['git'] + '?rev=' + patch['rev'] + '#' + patch['rev']):
            del patches[name]
    # An unknown patch format is conservatively retained in the manifest. The
    # actual resolved graph and registry checksums are never normalized away.
    if 'patch' in lock:
        lock['patch'].pop('unused', None)
    return {'paths': paths, 'manifest': manifest, 'lock': lock}


def component_identity(request, objects):
    """Requirements for retaining a component, NOT execution on a newer host.

    The original candidate could inspect its entire execution tree. Its tested
    context is therefore retained, not replaced by a content-equivalence claim.
    The assembled product/vector must be qualified afresh. Owner source/SDK and
    required check, fixture, image, confinement and core runtime contracts must
    still agree. Source revision stays significant because build/test code can
    observe Git. This deliberately does not permit conformance-job retention.
    """
    request = checked_request(request)
    require(request['job'] == 'native-qualification' and request['repository'] != CORE,
            'component retention is only for non-core native qualification')
    source = objects.tree(request['repository'], request['source'])
    policy = prepared_core_tree(objects, request['policy'], request)
    policy_data = tomllib.loads(objects.blob(CORE, request['policy'], 'ci/architecture.toml').decode())
    # native.main dispatches the generator explicitly; architecture.toml lists
    # plugin owners only. The dispatch and generator implementation are hashed.
    require(request['repository'] in policy_data['repositories']
            or request['repository'] == 'GetBusbar/busbar-release',
            'component is absent from approved policy')
    if request['repository'] != 'GetBusbar/busbar-release':
        pin = objects.blob(request['repository'], request['source'], '.busbar-ref').decode().split()
        require(pin and pin[0] == request['sdk'], 'component source and SDK pin differ')
    vector = json.loads(objects.blob(CORE, request['host'], 'scripts/ci-product-pins.json'))
    require(vector.get('sdk') == request['sdk'], 'current assembly and component SDK differ')
    # The reuse verifier itself is not an executed qualification input. Its tests
    # execute in core's fresh regressions. Other controller additions invalidate.
    omitted = {'scripts/ci-product-pins.json'} | REUSE_CONTROLLERS
    paths = {name: row for name, row in policy.items()
             if (name.startswith(('scripts/', 'ci/', 'testing/'))
                 or name in {'plugins.yaml', 'conformance/registry.toml',
                             'crates/busbar-contract/tests/architecture_surface.rs'})
             and name not in omitted
             and not core_regression_only(name)
             and not name.startswith('testing/evidence-conformance/')}
    # The core-only evidence rig is never invoked by a component native job.
    # Coverage metadata for unrelated owners changes whenever an assembly repins;
    # retain every field of this owner's rows, including its source/script hashes.
    coverage = json.loads(objects.blob(CORE, request['policy'], 'conformance/ci-coverage.json'))
    require(coverage.get('schema') == 'busbar.conformance.ci-coverage/1', 'unknown coverage schema')
    owner_coverage = {name: row for name, row in coverage['suites'].items()
                      if row.get('repo') == request['repository']}
    return {'schema': 'busbar.retained-component-inputs/1', 'repository': request['repository'],
        'job': request['job'], 'source_revision': request['source'],
        'source_tree_sha256': sha(encoded(source)), 'sdk_revision': request['sdk'],
        'sdk_tree_sha256': sha(encoded(objects.tree(CORE, request['sdk']))),
        'policy_inputs_sha256': sha(encoded(paths)), 'owner_coverage': owner_coverage,
        'policy_compiler_manifest': tomllib.loads(objects.blob(CORE, request['policy'], 'Cargo.toml').decode())
            ['workspace']['dependencies'],
        'runtime_contract_sha256': sha(encoded(runtime_contract(objects, request['host'], request)))}


def verify_reuse(proof, expected, objects, *, receipt_bytes, artifact_bytes,
                 authenticate_original, validate_original, database=None, now=None):
    """Recompute the proof and authenticate original evidence on EVERY consumption.

    authenticate_original(original_request, receipt, artifact_sha256) must verify
    authoritative successful mandatory job/pipeline/source/config/runner and
    artifact provenance and return True. validate_original(...) must invoke the
    original immutable complete artifact validator, returning True. Neither may
    be selected by proof data. Their exceptions fail closed. Authenticating a
    copied success flag or digest is insufficient.
    """
    expected = checked_request(expected)
    require(isinstance(proof, dict) and set(proof) == {'schema', 'scope', 'original', 'requested',
            'receipt_sha256', 'artifact_sha256', 'identity', 'identity_sha256'}, 'invalid reuse proof')
    require(proof['schema'] == SCHEMA and proof['requested'] == expected, 'proof requested context differs')
    require(proof['scope'] in ('execution-equivalent', 'retained-component', 'retained-check'), 'unknown reuse scope')
    checked_request(proof['original'])
    require(isinstance(receipt_bytes, bytes) and isinstance(artifact_bytes, bytes), 'original bytes required')
    require(sha(receipt_bytes) == proof['receipt_sha256'] and sha(artifact_bytes) == proof['artifact_sha256'],
            'retained evidence bytes differ')
    receipt = json.loads(receipt_bytes)
    require(isinstance(receipt, dict), 'invalid original receipt')
    original = receipt_request(receipt, expected['job'], host=proof['original'].get('host'),
                               sdk=proof['original'].get('sdk'))
    require(original == proof['original'], 'original receipt identity differs')
    require(receipt.get('status') == 'pass', 'original receipt did not pass')
    require(original['repository'] == expected['repository'], 'wrong original repository')
    require(authenticate_original(original, receipt, proof['artifact_sha256']) is True,
            'original job/artifact provenance was not authenticated')
    require(validate_original(original, receipt_bytes, artifact_bytes) is True,
            'original immutable receipt validation did not pass')
    if expected['job'] == 'security-scans':
        clock = now or dt.datetime.now(dt.timezone.utc)
        require(security_database_identity(original, objects, receipt.get('database'), clock)
                == security_database_identity(expected, objects, database, clock),
                'advisory database changed; rescan required')
    if proof['scope'] == 'retained-check':
        before = retained_check_identity(original, objects)
        after = retained_check_identity(expected, objects)
    elif proof['scope'] == 'retained-component':
        before = component_identity(original, objects)
        after = component_identity(expected, objects)
    else:
        before = compute_identity(original, objects, database=database, now=now)
        after = compute_identity(expected, objects, database=database, now=now)
    require(before == after, 'qualification inputs changed; fresh execution required')
    require(proof['identity'] == after and proof['identity_sha256'] == sha(encoded(after)),
            'claimed identity differs from controller-computed inputs')
    return {'schema': SCHEMA, 'original': original, 'requested': expected,
            'receipt_sha256': proof['receipt_sha256'], 'artifact_sha256': proof['artifact_sha256'],
            'identity_sha256': proof['identity_sha256'], 'scope': proof['scope'],
            'current_host_protocol_credit': proof['scope'] == 'execution-equivalent',
            'current_host_binary_credit': False,
            'retained_check_credit': proof['scope'] == 'retained-check',
            'requires_fresh_assembly': expected['host'] if proof['scope'] != 'execution-equivalent' else None}


def make_proof(original, requested, objects, *, receipt_bytes, artifact_bytes,
               authenticate_original, validate_original, database=None, now=None,
               scope='execution-equivalent'):
    """Build only a proof the same consumer verifier actually accepts."""
    identity = (component_identity(requested, objects) if scope == 'retained-component' else
                retained_check_identity(requested, objects) if scope == 'retained-check' else
                compute_identity(requested, objects, database=database, now=now))
    proof = {'schema': SCHEMA, 'scope': scope, 'original': checked_request(original),
             'requested': checked_request(requested), 'receipt_sha256': sha(receipt_bytes),
             'artifact_sha256': sha(artifact_bytes), 'identity': identity,
             'identity_sha256': sha(encoded(identity))}
    verify_reuse(proof, requested, objects, receipt_bytes=receipt_bytes, artifact_bytes=artifact_bytes,
        authenticate_original=authenticate_original, validate_original=validate_original,
        database=database, now=now)
    return proof


def plan_reuse(original, requested, objects, *, database=None, now=None):
    """Read-only per-job planning. Every reuse remains pending evidence verification.

    A matching hash never authorizes skipping a job. The selector must call
    make_proof/verify_reuse with authenticated original artifacts before using
    either proposed reuse action. Missing evidence is a fresh run, not a pass.
    """
    original, requested = checked_request(original), checked_request(requested)
    require(original['repository'] == requested['repository'] and original['job'] == requested['job'],
            'planner cannot compare different owners or job kinds')
    result = {'repository': requested['repository'], 'job': requested['job'],
              'action': 'run', 'requires_evidence_verification': True,
              'requires_fresh_assembly': None}
    try:
        before = compute_identity(original, objects, database=database, now=now)
        after = compute_identity(requested, objects, database=database, now=now)
        if before == after:
            result.update(action='verify-execution-reuse', reason='execution inputs equal')
        elif (not requires_changed_source_checks(requested)
              and retained_check_identity(original, objects) == retained_check_identity(requested, objects)):
            result.update(action='verify-retained-check', reason='executed inputs and selected preparation unchanged; original check retained',
                          requires_fresh_assembly=requested['host'])
        elif (requested['job'] == 'native-qualification' and requested['repository'] != CORE
              and component_identity(original, objects) == component_identity(requested, objects)):
            result.update(action='verify-component-retention', reason='component contract equal; original context retained',
                          requires_fresh_assembly=requested['host'])
        else:
            result['reason'] = 'required inputs differ'
    except (ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        result['reason'] = 'unproven inputs: ' + str(error)
    return result
