"""Create local producer overlays and per-build CodeBuild requests; never calls AWS.

The generated runner is a separate, explicit CodeBuild entry point. It builds and
pushes new image tags only, leaving Lambda, SFN, API and IAM changes to the caller.
"""
import argparse
import ast
import base64
from copy import deepcopy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '998301375101'
REGION = 'ap-northeast-2'
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
PROJECT = 'team5-itg-build-20260914'
REPOSITORY = 'team5-itg-20260914'
RESULT_PREFIX = 'evaluation/failure-causality-20260914/aws-integration-v1/build'
# Observed by the main implementer's actual StartBuild rejection on 2026-10-03.
OBSERVED_BUILDSPEC_MAX_CHARACTERS = 25600
ROLES = ('l0', 'l1', 'l23')
SCOPES = {
    'l0': [('L0_SCANNER/src/l0', 'l0')],
    'l1': [('L1/src', 'src')],
    'l23': [('L2_SCANNER/l2_scanner', 'l2_scanner'), ('L3_SCANNER', 'L3_SCANNER'),
            ('url_collector', 'url_collector'), ('unified_scanner', 'unified_scanner')],
}
REQUIREMENT_FILES = {
    'l0': ['L0_SCANNER/requirements.txt'],
    'l1': ['L1/requirements.txt'],
    'l23': ['L2_SCANNER/requirements.txt', 'L3_SCANNER/requirements.txt'],
}
REQUIRED_DATA = {
    'l0': ['l0/data/shorteners.json'],
    'l1': ['src/psl_supplement.json', 'src/infra/rdap_bootstrap.json', 'src/infra/rdap_supplement.json'],
    'l23': ['L3_SCANNER/policies/operational.v1.json'],
}
EXCLUDED = {'__pycache__', '.git', '.pytest_cache', '.mypy_cache', '.ruff_cache',
            '.test-cache', '.venv', 'venv', 'node_modules', 'tests', 'build', 'dist'}
ALLOWED_SUFFIXES = {'.py', '.json', '.txt', '.md', '.csv', '.dat', '.pem', '.toml'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def source_files(directory):
    for folder, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith('.') and not d.endswith('.egg-info'))
        for name in sorted(files):
            path = Path(folder) / name
            if name.startswith('.') or path.suffix not in ALLOWED_SUFFIXES:
                continue
            if path.is_symlink():
                raise ValueError(f'source_symlink_not_supported:{path.name}')
            yield path


def copy_sources(source_root, relative, target):
    source = source_root / relative
    if not source.is_dir():
        raise ValueError(f'missing_source_directory:{relative}')
    rows = {}
    for path in source_files(source):
        rel = path.relative_to(source)
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = path.read_bytes()
        if path.suffix == '.py':
            ast.parse(data, filename=path.name)
        destination.write_bytes(data)
        rows[rel.as_posix()] = {'source': path.relative_to(source_root).as_posix(), 'sha256': sha(data), 'bytes': len(data)}
    return rows


def requirements(source_root, role):
    result = {'dnspython': '2.8.0', 'boto3': None, 'botocore': None}
    for name in REQUIREMENT_FILES[role]:
        for line in (source_root / name).read_text(encoding='utf-8').splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or ('sys_platform == "win32"' in line):
                continue
            package = line.split(';', 1)[0].strip()
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)', package)
            if not match:
                raise ValueError(f'unhandled_dependency_declaration:{name}:{package}')
            if match[1] == 'pytest':
                continue
            if match[1] in result and result[match[1]] not in (None, match[2]):
                raise ValueError(f'conflicting_dependency:{match[1]}')
            result[match[1]] = match[2]
    if role == 'l23':
        result['httpcore'] = '1.0.9'
    return result


def frozen_sources(source_zip, target, requirements_root):
    """Recreate exactly the native/common sources of a reviewed earlier bundle."""
    target.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(source_zip) as archive:
        configs = {role: json.loads(archive.read('role-configs/' + role + '.json')) for role in ROLES}
        for role, config in configs.items():
            for package_path, row in config['source_files'].items():
                relative = Path(row['source'])
                if relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('invalid_frozen_source_path')
                prefix = 'sources/common/' if package_path.startswith('evidence_pipeline/') else 'sources/roles/' + role + '/'
                data = archive.read(prefix + package_path)
                if sha(data) != row['sha256']:
                    raise ValueError('frozen_source_digest_mismatch:' + row['source'])
                path = target / relative
                if path.exists() and path.read_bytes() != data:
                    raise ValueError('frozen_source_collision')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
    for name in set(name for names in REQUIREMENT_FILES.values() for name in names):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((requirements_root / name).read_bytes())
    for role, config in configs.items():
        if requirements(target, role) != config['dependencies']:
            raise ValueError('requirements_changed_since_frozen_bundle:' + role)
    return target


def l1_wrapper_compatibility(path):
    """Remove two obsolete AAAA references; add no query, constant or record."""
    data = Path(path).read_bytes()
    before = sha(data)
    if before != '7d87a4d14ebbb3fd8f8c4e3dd1c3467669f0b15589bd36c65d0ab8dfbd2e678b':
        raise ValueError('unreviewed_l1_legacy_wrapper')
    replacements = ((b'INFRA_STATUS_RECEIVED, NAME_DNS_A, NAME_DNS_AAAA, OVERALL_COMPLETED',
                     b'INFRA_STATUS_RECEIVED, NAME_DNS_A, OVERALL_COMPLETED'),
                    (b'(NAME_DNS_A, NAME_DNS_AAAA)', b'(NAME_DNS_A,)'))
    for old, new in replacements:
        if data.count(old) != 1:
            raise ValueError('l1_wrapper_patch_does_not_match')
        data = data.replace(old, new, 1)
    ast.parse(data)
    return data, {'legacy_handler': {'before_sha256': before, 'after_sha256': sha(data),
                  'source_file': 'sources/roles/l1/legacy_handler.py',
                  'change': 'Remove obsolete NAME_DNS_AAAA import and gate tuple member; current DNS A producer unchanged'}}


def lazy_fragment_adapter(path, role):
    """Retain inherited storage semantics; share the runtime's lazy SDK client."""
    data = Path(path).read_bytes()
    before = sha(data)
    if before != 'f213435e5a36d1327b8aef15e48d6e4551ae03a493b9f79155432a96d09335a8':
        raise ValueError('unreviewed_legacy_fragment')
    old = b's3 = boto3.client("s3")'
    if data.count(old) != 1:
        raise ValueError('legacy_fragment_client_patch_does_not_match')
    data = data.replace(old, b'from evidence_pipeline.aws_clients import LazyS3\ns3 = LazyS3()', 1)
    ast.parse(data)
    return data, {'fragment': {'before_sha256': before, 'after_sha256': sha(data),
                  'source_file': f'sources/roles/{role}/fragment.py',
                  'change': 'Replace eager unused S3 client with shared lazy client; storage operations unchanged'}}


CONTAINER_PROBE = r'''import hashlib, importlib, importlib.metadata, json, platform, sys
from pathlib import Path

role, phase = sys.argv[1:3]
root = Path('/var/task')
sys.path.insert(0, str(root))
adapters = {}
for name in ('legacy_handler', 'adapter', 'keys', 'fragment', 'sink'):
    module = importlib.import_module(name)
    path = Path(module.__file__).resolve()
    assert path.parent == root, (name, str(path))
    adapters[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
legacy = importlib.import_module('legacy_handler')
report = {'role': role, 'phase': phase, 'python': platform.python_version(),
          'architecture': platform.machine(), 'adapters': adapters}
if phase == 'candidate':
    config = json.loads(Path('/opt/fast-final/role.json').read_text())
    for name, row in config['source_files'].items():
        path = root / name
        assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], name
    modules = ['evidence_pipeline.aws_runtime'] + {
        'l0': ['l0.registry'], 'l1': ['src.handler', 'src.domain_units'],
        'l23': ['l2_scanner', 'L3_SCANNER', 'L3_SCANNER.policies', 'url_collector', 'unified_scanner']}[role]
    loaded = {}
    for name in modules:
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        rel = path.relative_to(root).as_posix()
        assert rel in config['source_files'], (name, str(path))
        loaded[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    aliases = {'ada-url': 'ada_url', 'beautifulsoup4': 'bs4', 'dnspython': 'dns',
               'python-magic': 'magic'}
    dependencies = {}
    for name, required in config['dependencies'].items():
        module = importlib.import_module(aliases.get(name, name.replace('-', '_')))
        try:
            version = importlib.metadata.version(name)
            origin = 'distribution_metadata'
        except importlib.metadata.PackageNotFoundError:
            version = getattr(module, '__version__', None)
            origin = 'module_version' if version else 'version_unrecorded'
        dependencies[name] = {'required_version': required, 'actual_version': version,
                              'version_source': origin, 'path': getattr(module, '__file__', None),
                              'matches': (version == required) if required and version else None}
    for name in config['required_data']:
        json.loads((root / name).read_text(encoding='utf-8'))
    from evidence_pipeline.records import build_record
    if role == 'l0':
        assert legacy.analyze.__module__ == 'l0.registry'
        native = legacy.jsonable(legacy.analyze('https://community.example.org/login'))
        record = build_record('l0', native, request_id='offline-build', attempt='1', raw=native['raw_evidence'])
        assert native['producer_contract'] == 'url-observations-3'
        assert record['record_contract_version'] == 'l0-observations-1'
        smoke = {'producer_contract': native['producer_contract'], 'record_contract_version': record['record_contract_version']}
    elif role == 'l1':
        assert legacy.run.__module__ == 'src.handler'
        from src.domain_units import compute_domain_units
        units = compute_domain_units('community.example.org')
        assert units.registrable_unit == 'example.org'
        from src.common import INFRA_STATUS_RECEIVED, NAME_DNS_A, OVERALL_COMPLETED
        from src.records import KEY_DOMAIN_UNITS, KEY_INFRA_RECORDS, KEY_OVERALL
        native = {KEY_DOMAIN_UNITS: {}, KEY_OVERALL: OVERALL_COMPLETED,
                  KEY_INFRA_RECORDS: [{'name': NAME_DNS_A, 'status': INFRA_STATUS_RECEIVED,
                                       'result': {'records': ['93.184.216.34']}}]}
        gate = legacy.derive_gate(native, 'community.example.org')
        assert not gate.gate_block and gate.resolved_ips == ('93.184.216.34',)
        native[KEY_INFRA_RECORDS][0]['result']['records'] = ['127.0.0.1']
        assert legacy.derive_gate(native, 'community.example.org').gate_block
        smoke = {'entrypoint': legacy.run.__module__, 'registrable_unit': units.registrable_unit,
                 'current_dns_a_gate_public_allowed_private_blocked': True}
    else:
        from L3_SCANNER import scan_content
        from L3_SCANNER.policies import operational_detection_policy
        policy = legacy.l3_policy()
        native = scan_content({'original_url': 'https://community.example.org/login',
            'document_url': 'https://community.example.org/login',
            'html': {'content': '<title>Member login</title><form action="/session" method="post"><input name="user"><input name="password" type="password"></form>', 'truncated': False}}, policy=policy)
        record = build_record('l3', native, request_id='offline-build', attempt='1', raw=native['raw'])
        from evidence_pipeline.l3_html_text import build_html_text_context
        document = build_html_text_context(record, native['raw'], native=native)
        assert document.body and native['signals']
        smoke = {'signal_count': len(native['signals']), 'builder_bytes': len(document.body.encode()),
                 'policy_name': policy.policy_name}
        report['brand_cache_present'] = (root / 'L3_SCANNER/brands/data/wikidata-brands.json').is_file()
    report.update(modules=loaded, dependencies=dependencies, smoke=smoke,
                  source_files_verified=len(config['source_files']), required_data=config['required_data'])
print('FAST_PRODUCER_PROBE:' + json.dumps(report, ensure_ascii=False))
'''


BUILD_RUNNER = r'''"""Explicit CodeBuild image build; no Lambda/SFN/API/IAM mutation."""
import base64, hashlib, json, os, shutil, subprocess
from pathlib import Path
import boto3

ROOT = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def probe(image, role, phase):
    args = ['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python',
            '-e', 'AWS_EC2_METADATA_DISABLED=true', '-e', 'AWS_DEFAULT_REGION=ap-northeast-2',
            '-e', 'EVIDENCE_SINK=local', '-e', 'BUCKET_NAME=' + manifest['bucket'],
            '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'TLDEXTRACT_CACHE=/tmp/tldextract',
            image, '-c', (ROOT / 'container-probe.py').read_text(), role, phase]
    completed = subprocess.run(args, capture_output=True, text=True, timeout=150)
    if completed.returncode:
        raise RuntimeError('container_probe_failed:' + role + ':' + phase + '\n' + completed.stderr[-6000:])
    return json.loads(next(line.split(':', 1)[1] for line in completed.stdout.splitlines()
                           if line.startswith('FAST_PRODUCER_PROBE:')))

if not os.environ.get('CODEBUILD_BUILD_ID'):
    raise RuntimeError('explicit_codebuild_execution_required')
manifest = json.loads((ROOT / 'bundle-manifest.json').read_text())
if digest(ROOT / 'bundle-manifest.json') != os.environ['FAST_PRODUCER_MANIFEST_SHA256']:
    raise RuntimeError('manifest_digest_mismatch')
if boto3.client('sts').get_caller_identity()['Account'] != manifest['account']:
    raise RuntimeError('wrong_account')
if os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION')) != manifest['region']:
    raise RuntimeError('wrong_region')
for name, row in manifest['bundle_files'].items():
    if digest(ROOT / name) != row['sha256']:
        raise RuntimeError('source_digest_mismatch:' + name)
ecr = boto3.client('ecr', region_name=manifest['region'])
s3 = boto3.client('s3', region_name=manifest['region'])
auth = ecr.get_authorization_token(registryIds=[manifest['account']])['authorizationData'][0]
username, password = base64.b64decode(auth['authorizationToken']).decode().split(':', 1)
run(['docker', 'login', '--username', username, '--password-stdin', auth['proxyEndpoint']], input=password.encode())
build_id = os.environ['CODEBUILD_BUILD_ID']
run_id = build_id.rsplit(':', 1)[-1]
result = {'status': 'building', 'codebuild_build_id': build_id, 'release_id': manifest['release_id'],
          'manifest_sha256': digest(ROOT / 'bundle-manifest.json'), 'images': {},
          'lambda_changes': 0, 'state_machine_changes': 0, 'api_changes': 0, 'iam_changes': 0}
result_key = manifest['result_prefix'] + '/' + run_id + '/build-result.json'
try:
    for role, item in manifest['roles'].items():
        tag = item['candidate_tag']
        try:
            existing = ecr.describe_images(repositoryName=manifest['repository'], imageIds=[{'imageTag': tag}])
        except ecr.exceptions.ImageNotFoundException:
            existing = None
        if existing and existing.get('imageDetails'):
            raise RuntimeError('candidate_tag_already_exists_use_new_release:' + tag)
        run(['docker', 'pull', item['base_image']])
        before = probe(item['base_image'], role, 'baseline')
        if before['architecture'] not in ('x86_64', 'AMD64'):
            raise RuntimeError('baseline_image_architecture_is_not_amd64:' + role)
        overrides = item.get('adapter_overrides', {})
        for name, expected in overrides.items():
            if before['adapters'][name]['sha256'] != expected['before_sha256']:
                raise RuntimeError('reviewed_baseline_adapter_digest_mismatch:' + role + ':' + name)
        result['images'][role] = {'base_image': item['base_image'], 'tag': tag,
                                  'baseline_probe': before, 'adapter_overrides': overrides,
                                  'source_sha256': item['source_sha256'], 'pushed': False}
        folder = ROOT / 'work' / role
        payload = folder / 'payload'
        payload.mkdir(parents=True, exist_ok=False)
        shutil.copytree(ROOT / 'sources/common', payload, dirs_exist_ok=True)
        shutil.copytree(ROOT / ('sources/roles/' + role), payload, dirs_exist_ok=True)
        shutil.copyfile(ROOT / ('role-configs/' + role + '.json'), folder / 'role.json')
        shutil.copyfile(ROOT / 'container-probe.py', folder / 'probe.py')
        shutil.copyfile(ROOT / ('dockerfiles/' + role + '.Dockerfile'), folder / 'Dockerfile')
        uri = manifest['registry'] + '/' + manifest['repository'] + ':' + tag
        run(['docker', 'build', '--platform', 'linux/amd64', '--network', 'none', '-t', uri, str(folder)])
        after = probe(uri, role, 'candidate')
        for name, previous in before['adapters'].items():
            actual = after['adapters'][name]
            if name in overrides:
                if actual['path'] != previous['path'] or actual['sha256'] != overrides[name]['after_sha256']:
                    raise RuntimeError('explicit_adapter_override_mismatch:' + role + ':' + name)
            elif actual != previous:
                raise RuntimeError('inherited_adapter_changed:' + role + ':' + name)
        result['images'][role]['candidate_probe'] = after
        run(['docker', 'push', uri])
        image = ecr.describe_images(repositoryName=manifest['repository'], imageIds=[{'imageTag': tag}])['imageDetails'][0]
        result['images'][role].update(uri=manifest['registry'] + '/' + manifest['repository'] + '@' + image['imageDigest'],
                                     digest=image['imageDigest'], pushed=True)
        print(json.dumps({'role': role, 'status': 'built_imports_verified', 'image_digest': image['imageDigest']}))
    result['status'] = 'built_imports_verified'
except Exception as exc:
    result.update(status='failed', error_type=type(exc).__name__, error=str(exc)[-6000:])
    raise
finally:
    (ROOT / 'build-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    s3.put_object(Bucket=manifest['bucket'], Key=result_key, Body=(ROOT / 'build-result.json').read_bytes(),
                  ContentType='application/json', IfNoneMatch='*')
    print(json.dumps({'build_result_bucket': manifest['bucket'], 'build_result_key': result_key,
                      'status': result['status'], 'lambda_changes': 0}))
'''


def subset_files(source, selected):
    value = json.loads((source / 'bundle-manifest.json').read_bytes())
    value['roles'] = {role: value['roles'][role] for role in selected}
    rows = {}
    for path in sorted(source.rglob('*')):
        if not path.is_file() or path.name == 'bundle-manifest.json':
            continue
        name = path.relative_to(source).as_posix()
        if name.startswith('sources/roles/') and name.split('/')[2] not in selected:
            continue
        if name.startswith('role-configs/') and path.stem not in selected:
            continue
        if name.startswith('dockerfiles/') and path.stem not in selected:
            continue
        rows[name] = path.read_bytes()
    value['bundle_files'] = {name: {'sha256': sha(data), 'bytes': len(data)} for name, data in rows.items()}
    rows['bundle-manifest.json'] = json_bytes(value)
    return rows


def archive_bytes(rows, kind):
    output = io.BytesIO()
    if kind == 'zip':
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(rows.items()):
                item = zipfile.ZipInfo(name, (2026, 10, 3, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(item, data, compresslevel=9)
        return output.getvalue()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, data in sorted(rows.items()):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o644
            archive.addfile(item, io.BytesIO(data))
    return lzma.compress(output.getvalue(), preset=6)


def verify_archive(data, rows, kind):
    if kind == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            actual = {name: archive.read(name) for name in archive.namelist()}
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
            actual = {item.name: archive.extractfile(item).read() for item in archive.getmembers() if item.isfile()}
    if actual != rows:
        raise ValueError('local_archive_roundtrip_mismatch')


def inline_request(rows, *, release_id, label, project, budget, timeout_minutes=45):
    archive = archive_bytes(rows, 'xz')
    verify_archive(archive, rows, 'xz')
    encoded = base64.b64encode(archive).decode('ascii')
    folder = 'fast-final-' + release_id + '-' + label
    commands = ['test ! -e ' + shlex.quote(folder), 'mkdir ' + shlex.quote(folder)]
    # Each shell command stays below the Linux per-argument size ceiling.
    for start in range(0, len(encoded), 16000):
        commands.append("printf '%s' " + shlex.quote(encoded[start:start + 16000]) +
                        (' > ' if start == 0 else ' >> ') + shlex.quote(folder + '/bundle.b64'))
    unpack = (
        'import base64,hashlib,io,tarfile;from pathlib import Path;'
        f'p=Path({folder!r});b=base64.b64decode((p/"bundle.b64").read_bytes());'
        f'assert hashlib.sha256(b).hexdigest()=={sha(archive)!r};'
        't=tarfile.open(fileobj=io.BytesIO(b),mode="r:xz");'
        '\nfor m in t.getmembers():\n'
        ' q=(p/m.name).resolve();assert m.isfile() and q.is_relative_to(p.resolve());'
        'q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(t.extractfile(m).read())')
    commands.append('python -c ' + shlex.quote(unpack))
    commands.append('python ' + shlex.quote(folder + '/build_images.py'))
    buildspec = json.dumps({'version': 0.2, 'phases': {'build': {'commands': commands}}}, separators=(',', ':'))
    request = {'projectName': project, 'sourceTypeOverride': 'NO_SOURCE', 'buildspecOverride': buildspec,
               'artifactsOverride': {'type': 'NO_ARTIFACTS'}, 'cacheOverride': {'type': 'NO_CACHE'},
               'privilegedModeOverride': True, 'timeoutInMinutesOverride': timeout_minutes,
               'environmentVariablesOverride': [{'name': 'FAST_PRODUCER_MANIFEST_SHA256',
                    'value': sha(rows['bundle-manifest.json']), 'type': 'PLAINTEXT'}]}
    size = {'archive_bytes': len(archive), 'base64_bytes': len(encoded),
            'buildspec_utf8_bytes': len(buildspec.encode()), 'start_build_json_bytes': len(json_bytes(request)),
            'largest_command_utf8_bytes': max(len(v.encode()) for v in commands),
            'operator_inline_budget_bytes': budget,
            'within_operator_budget': len(buildspec.encode()) <= budget if budget else None,
            'buildspec_characters': len(buildspec),
            'observed_api_buildspec_max_characters': OBSERVED_BUILDSPEC_MAX_CHARACTERS,
            'within_observed_api_limit': len(buildspec) <= OBSERVED_BUILDSPEC_MAX_CHARACTERS,
            'execution_status': ('not_executable_buildspec_limit'
                                 if len(buildspec) > OBSERVED_BUILDSPEC_MAX_CHARACTERS else 'api_acceptance_unverified'),
            'live_api_acceptance_verified': False}
    return request, archive, size


def build(*, baseline, configurations, output, release_id, source_root=ROOT,
          project=PROJECT, repository=REPOSITORY, result_prefix=RESULT_PREFIX, inline_budget_bytes=None,
          build_timeout_minutes=45, skip_inline=False, frozen_source_zip=None, l1_legacy_wrapper=None,
          legacy_fragment=None, precompile=False):
    baseline, configurations, output, source_root = map(Path, (baseline, configurations, output, source_root))
    if not re.fullmatch(r'fastfinal-[a-z0-9][a-z0-9-]{4,45}', release_id):
        raise ValueError('release_id_must_start_fastfinal_and_use_lowercase_slug')
    if project != PROJECT or repository != REPOSITORY:
        raise ValueError('only_the_reviewed_existing_build_project_and_repository_are_supported')
    if not result_prefix.startswith(RESULT_PREFIX + '/') and result_prefix != RESULT_PREFIX:
        raise ValueError('result_prefix_must_remain_in_reviewed_build_output_scope')
    if '..' in result_prefix.split('/') or inline_budget_bytes is not None and inline_budget_bytes <= 0:
        raise ValueError('invalid_output_prefix_or_inline_budget')
    if not isinstance(build_timeout_minutes, int) or isinstance(build_timeout_minutes, bool) or build_timeout_minutes <= 0:
        raise ValueError('build_timeout_minutes_must_be_a_positive_integer')
    observed = json.loads(baseline.read_bytes())
    settings = json.loads(configurations.read_bytes())
    pinned = {}
    for role in ROLES:
        name = f'team5-itg-{role}-20260914'
        value, config = observed[name], settings[name]
        image = value['image']['ResolvedImageUri']
        pattern = re.escape(f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}@sha256:') + '[a-f0-9]{64}'
        if not re.fullmatch(pattern, image) or value['CodeSha256'] != image.rsplit(':', 1)[1]:
            raise ValueError('baseline_image_must_be_resolved_digest_for_reviewed_function:' + role)
        if config['CodeSha256'] != value['CodeSha256'] or config['settings']['EVIDENCE_ROLE'] != role:
            raise ValueError('saved_baseline_configuration_disagrees:' + role)
        pinned[role] = {'function_name': name, 'image_uri': image, 'configuration': deepcopy(config)}
    output.mkdir(parents=True, exist_ok=False)
    frozen_zip_sha256 = None
    if frozen_source_zip:
        frozen_zip_sha256 = sha(Path(frozen_source_zip).read_bytes())
        source_root = frozen_sources(Path(frozen_source_zip), output / 'frozen-input', source_root)
    source = output / 'source'
    common = copy_sources(source_root, 'evidence_pipeline', source / 'sources/common/evidence_pipeline')
    roles = {}
    for role in ROLES:
        overrides = {}
        if role == 'l1' and l1_legacy_wrapper:
            wrapper, overrides = l1_wrapper_compatibility(l1_legacy_wrapper)
            wrapper_path = source / 'sources/roles/l1/legacy_handler.py'
            wrapper_path.parent.mkdir(parents=True, exist_ok=True)
            wrapper_path.write_bytes(wrapper)
        if legacy_fragment:
            fragment, fragment_overrides = lazy_fragment_adapter(legacy_fragment, role)
            fragment_path = source / f'sources/roles/{role}/fragment.py'
            fragment_path.parent.mkdir(parents=True, exist_ok=True)
            fragment_path.write_bytes(fragment)
            overrides.update(fragment_overrides)
        files = {'evidence_pipeline/' + name: row for name, row in common.items()}
        for relative, destination in SCOPES[role]:
            copied = copy_sources(source_root, relative, source / ('sources/roles/' + role + '/' + destination))
            files.update({destination + '/' + name: row for name, row in copied.items()})
        for name in REQUIRED_DATA[role]:
            if name not in files:
                raise ValueError('required_runtime_data_missing:' + name)
        digest_input = {'source_files': files, 'adapter_overrides': overrides} if overrides else files
        source_digest = sha(json.dumps(digest_input, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())
        roles[role] = {'base_image': pinned[role]['image_uri'], 'function_name': pinned[role]['function_name'],
                       'source_sha256': source_digest, 'candidate_tag': release_id + '-' + role + '-' + source_digest[:12],
                       'adapter_overrides': overrides}
        write_json(source / ('role-configs/' + role + '.json'), {'role': role, 'source_files': files,
                   'dependencies': requirements(source_root, role), 'required_data': REQUIRED_DATA[role],
                   'adapter_overrides': overrides})
        folders = ['evidence_pipeline'] + [destination for _, destination in SCOPES[role]]
        dockerfile = ('FROM ' + pinned[role]['image_uri'] + '\n'
                      'RUN rm -rf ' + ' '.join('/var/task/' + name for name in folders) + '\n'
                      'COPY payload/ /var/task/\n'
                      'COPY role.json probe.py /opt/fast-final/\n'
                      + ('RUN python -m compileall -q ' + ' '.join('/var/task/' + name for name in folders) + '\n' if precompile else '')
                      + f'ENV EVIDENCE_ROLE={role} PYTHONDONTWRITEBYTECODE=1 TLDEXTRACT_CACHE=/tmp/tldextract\n'
                      'CMD ["evidence_pipeline.aws_runtime.handler"]\n')
        path = source / ('dockerfiles/' + role + '.Dockerfile')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dockerfile, encoding='utf-8', newline='\n')
    (source / 'build_images.py').write_text(BUILD_RUNNER, encoding='utf-8', newline='\n')
    (source / 'container-probe.py').write_text(CONTAINER_PROBE, encoding='utf-8', newline='\n')
    ast.parse(BUILD_RUNNER)
    ast.parse(CONTAINER_PROBE)
    rollback = {'source': 'saved_live_metadata; re-read current revision before any later restoration',
                'baseline_file_sha256': sha(baseline.read_bytes()),
                'configuration_file_sha256': sha(configurations.read_bytes()), 'roles': pinned,
                'automatic_restoration': False,
                'not_in_saved_configuration': ['Architectures', 'ImageConfigResponse; preserve actual Lambda command override']}
    write_json(output / 'rollback-metadata.json', rollback)
    manifest = {'schema_version': 'fast-final-producer-bundle-1', 'release_id': release_id,
                'account': ACCOUNT, 'region': REGION, 'bucket': BUCKET, 'project': project,
                'repository': repository, 'registry': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com',
                'result_prefix': result_prefix + '/' + release_id, 'roles': roles,
                'baseline_file_sha256': sha(baseline.read_bytes()),
                'configuration_file_sha256': sha(configurations.read_bytes()),
                'generator_sha256': sha(Path(__file__).read_bytes()), 'aws_actions_by_generator': 0,
                'frozen_source_zip_sha256': frozen_zip_sha256,
                'precompile_python': precompile,
                'dependency_strategy': 'inherit pinned Linux image; import and report actual versions; no package install',
                'inherited_adapters': ['legacy_handler.py', 'adapter.py', 'keys.py', 'fragment.py', 'sink.py'],
                'explicit_adapter_overrides': {role: item['adapter_overrides'] for role, item in roles.items() if item['adapter_overrides']}}
    write_json(source / 'bundle-manifest.json', manifest)
    rows = subset_files(source, ROLES)
    (source / 'bundle-manifest.json').write_bytes(rows['bundle-manifest.json'])
    archive = archive_bytes(rows, 'zip')
    verify_archive(archive, rows, 'zip')
    (output / 'source.zip').write_bytes(archive)
    source_key = result_prefix + '/' + release_id + '/source-' + sha(archive)[:16] + '.zip'
    simple_buildspec = json.dumps({'version': 0.2, 'phases': {'build': {'commands': ['python build_images.py']}}})
    s3_request = {'projectName': project, 'sourceTypeOverride': 'S3',
                  'sourceLocationOverride': BUCKET + '/' + source_key, 'buildspecOverride': simple_buildspec,
                  'artifactsOverride': {'type': 'NO_ARTIFACTS'}, 'cacheOverride': {'type': 'NO_CACHE'},
                  'privilegedModeOverride': True, 'timeoutInMinutesOverride': build_timeout_minutes,
                  'environmentVariablesOverride': [{'name': 'FAST_PRODUCER_MANIFEST_SHA256',
                       'value': sha(rows['bundle-manifest.json']), 'type': 'PLAINTEXT'}]}
    write_json(output / 'start-build-s3.json', s3_request)
    variants = {}
    for label, selected in ([] if skip_inline else [('all', ROLES), *((role, (role,)) for role in ROLES)]):
        selected_rows = subset_files(source, selected)
        request, compressed, sizes = inline_request(selected_rows, release_id=release_id, label=label,
                                                    project=project, budget=inline_budget_bytes,
                                                    timeout_minutes=build_timeout_minutes)
        filename = 'start-build-inline-' + label + '.json'
        write_json(output / filename, request)
        (output / ('inline-' + label + '.tar.xz')).write_bytes(compressed)
        variants[label] = {**sizes, 'request': filename, 'request_sha256': sha((output / filename).read_bytes()),
                           'roles': list(selected), 'manifest_sha256': sha(selected_rows['bundle-manifest.json'])}
    proof = {'status': 'local_bundle_verified', 'source_zip_sha256': sha(archive), 'source_zip_bytes': len(archive),
             'source_key': source_key, 'generator_aws_calls': 0, 'docker_executed': False,
             'container_imports_verified': False, 'archive_roundtrip_verified': True, 'inline_variants': variants,
             'source_files': sum(1 for name in rows if name.startswith('sources/')),
             'frozen_source_zip_sha256': frozen_zip_sha256,
             'explicit_adapter_overrides': manifest['explicit_adapter_overrides'],
             's3_mode_requires_new_source_getobject_permission': True,
             'inline_candidates_generated': not skip_inline,
             'observed_api_buildspec_max_characters': OBSERVED_BUILDSPEC_MAX_CHARACTERS,
             'inline_api_size_limit': 'Main implementer observed StartBuild InvalidInputException: Max buildspec length is 25600 on 2026-10-03; r2 all four inline variants are not executable',
             's3_buildspec_characters': len(simple_buildspec),
             'build_timeout_minutes': build_timeout_minutes,
             's3_candidate_status': 'prepared_additional_exact_object_read_permission_not_approved',
             'producer_deployment_status': 'incomplete', 'live_producer_validation_status': 'incomplete'}
    write_json(output / 'local-verification.json', proof)
    readme = f'''# Fast final producer bundle — {release_id}

This is a local candidate. No AWS or Docker command was executed by the generator.

## Source and image boundary

- L0: current `L0_SCANNER/src/l0` including shorteners JSON.
- L1: current `L1/src` including PSL and RDAP JSON.
- L23: current `l2_scanner`, `L3_SCANNER`, `url_collector`, `unified_scanner`; operational policy JSON included.
- All roles: current `evidence_pipeline`, including prompts/data. `.git`, tests, caches and bytecode excluded.
- Each FROM uses the exact resolved image digest in `rollback-metadata.json`.
- Original adapter, keys, fragment and sink are inherited. The manifest explicitly identifies any reviewed legacy_handler compatibility override; actual before/after hashes must match that exact exception, and all other adapter hashes must agree.
- Frozen native/common source input, when requested: `{frozen_zip_sha256}`. No query or record is added by the optional L1 wrapper compatibility patch.
- Native Linux libraries and Python dependencies are inherited. Container probes record actual versions and declared requirements. No pip/OS package installation is generated. Version mismatch or unrecorded version is visible in the result; inspect it before deployment.
- Current source contains no Wikidata cache JSON. No brand cache or reference domains are invented.

## CodeBuild invocation (S3 candidate, approval pending)

The main implementer observed `InvalidInputException: Max buildspec length is 25600` from actual StartBuild on 2026-10-03. That r2 inline attempt created no Build ID and pushed no image. All four r2 inline variants exceed this limit. Do not retry them or create smaller inline variants. This bundle generated inline candidates: {not skip_inline}. Their presence, if explicitly requested, does not establish service acceptance.

`start-build-s3.json` uses the exact new source key below, a {len(simple_buildspec)}-character buildspec and a {build_timeout_minutes}-minute timeout. The fresh source object's `s3:GetObject` permission is a separate, unapproved scope. No upload, policy change or build invocation is performed by this generator. Producer deployment and live validation are incomplete.

After approval of that exact object, upload with a condition that preserves any existing key, then use the frozen request:

```bash
aws s3api put-object --region {REGION} --bucket {BUCKET} --key {source_key} --body source.zip --if-none-match '*' --checksum-algorithm SHA256 --checksum-sha256 {base64.b64encode(hashlib.sha256(archive).digest()).decode('ascii')} --expected-bucket-owner {ACCOUNT}
aws codebuild start-build --region {REGION} --cli-input-json file://start-build-s3.json
```

Overrides affect this build only. The existing project, roles, function settings, other analysis paths and old source keys are not updated. The runner pulls pinned images, imports the inherited adapter with networking disabled, verifies copied source hashes/data/imports and a bounded offline producer check, then pushes only new `{release_id}-...` tags. It never invokes a Lambda or updates Lambda/SFN/API/IAM.

Build results go below `{result_prefix}/{release_id}/<build-id>/build-result.json`, inside the separately observed allowed build-output prefix. ECR, result PutObject and CodeBuild project privileges must still match the live role. The runner records resolved output digests; use those digests for any later qualified Lambda version.

## Restoration

The generator does not change functions. `rollback-metadata.json` preserves each original image URI, function RevisionId, timeout, memory, role, VPC and known environment values from the saved baseline. Re-read the current function revision before any later restore. Published Lambda versions and other SFN definitions are not changed by this bundle.

## Evidence still required

Local source hashes, archive round trips and Python parsing are checked. Linux container builds/imports, actual dependency compatibility and AWS route execution remain unverified until the generated CodeBuild runner and the separate integration check execute successfully. Probe success is a package/contract check, not model verdict quality.

References: [StartBuild](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_StartBuild.html), [CodeBuild quotas](https://docs.aws.amazon.com/codebuild/latest/userguide/limits.html), [official SDK model](https://github.com/boto/botocore/blob/develop/botocore/data/codebuild/2016-10-06/service-2.json).
'''
    (output / 'README.md').write_text(readme, encoding='utf-8', newline='\n')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'configurations', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--project', default=PROJECT)
    parser.add_argument('--repository', default=REPOSITORY)
    parser.add_argument('--result-prefix', default=RESULT_PREFIX)
    parser.add_argument('--inline-budget-bytes', type=int)
    parser.add_argument('--build-timeout-minutes', type=int, default=45)
    parser.add_argument('--skip-inline', action='store_true')
    parser.add_argument('--frozen-source-zip', type=Path)
    parser.add_argument('--l1-legacy-wrapper', type=Path)
    parser.add_argument('--legacy-fragment', type=Path)
    parser.add_argument('--precompile', action='store_true')
    result = build(**vars(parser.parse_args()))
    print(json.dumps({'status': result['status'], 'source_zip_bytes': result['source_zip_bytes'],
                      'source_zip_sha256': result['source_zip_sha256'], 'aws_actions': 0,
                      'inline_variants': result['inline_variants']}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
