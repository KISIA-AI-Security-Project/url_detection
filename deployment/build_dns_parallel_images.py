"""CodeBuild entry point for the isolated DNS-parallel image overlays."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

import boto3


ROOT = Path.cwd()
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
RESULT_KEY = 'evaluation/dns-inactivity-20260916/build-result-v3.json'
REPOSITORY = 'team5-itg-20260914'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        for name in source.namelist():
            target = (destination / name).resolve()
            assert target.is_relative_to(destination.resolve()), name
            if name.endswith('/'):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read(name)
            if target.exists():
                assert target.read_bytes() == data, f'existing_file_drift:{target}'
            else:
                target.write_bytes(data)


def main():
    assert boto3.client('sts').get_caller_identity()['Account'] == '998301375101'
    archive = ROOT / 'isolated-candidate-v3.zip'
    assert digest(archive) == os.environ['PACKET_SHA256']
    packet = ROOT / 'packet'
    unpack(archive, packet)
    manifest = json.loads((packet / 'package-manifest.json').read_text())
    ecr = boto3.client('ecr', region_name='ap-northeast-2')
    s3 = boto3.client('s3', region_name='ap-northeast-2')
    auth = ecr.get_authorization_token()['authorizationData'][0]
    username, password = base64.b64decode(auth['authorizationToken']).decode().split(':', 1)
    subprocess.run(['docker', 'login', '--username', username, '--password-stdin',
                    auth['proxyEndpoint']], input=password.encode(), check=True)
    result_path = ROOT / 'build-result.json'
    result = json.loads(result_path.read_text()) if result_path.exists() else {
        'packet_sha256': digest(archive), 'images': {}, 'imports': {}, 'status': 'building'}
    assert result['packet_sha256'] == digest(archive)
    result['status'] = 'building'
    result.pop('error_type', None)
    result.pop('error', None)

    def save():
        body = json.dumps(result, indent=2).encode()
        (ROOT / 'build-result.json').write_bytes(body)
        s3.put_object(Bucket=BUCKET, Key=RESULT_KEY, Body=body)

    save()
    try:
        for role in ('l0', 'l1', 'l23'):
            item = manifest['packages'][role]
            if role in result['images']:
                image = result['images'][role]
                assert image['source_sha256'] == item['sha256']
                actual = ecr.describe_images(repositoryName=REPOSITORY,
                                             imageIds=[{'imageTag': image['tag']}])['imageDetails'][0]
                assert image['uri'].endswith('@' + actual['imageDigest'])
                assert result['imports'][role]['returncode'] == 0
                continue
            overlay = packet / item['context_zip']
            assert digest(overlay) == item['sha256']
            destination = ROOT / role
            unpack(overlay, destination)
            tag = f'dnsp-{role}-{item["sha256"][:16]}'
            uri = f'998301375101.dkr.ecr.ap-northeast-2.amazonaws.com/{REPOSITORY}:{tag}'
            subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', uri,
                            str(destination)], check=True)
            modules = ['evidence_pipeline.aws_runtime', 'legacy_handler'] + {
                'l0': ['l0.registry'], 'l1': ['src.handler'],
                'l23': ['l2_scanner', 'L3_SCANNER', 'L3_SCANNER.policies']}[role]
            smoke = ('import importlib,json,hashlib; names=' + repr(modules) +
                     '; rows=[]\nfor n in names:\n m=importlib.import_module(n);'
                     ' p=m.__file__; assert p and p.startswith("/var/task/"),(n,p);'
                     ' rows.append({"module":n,"path":p,"sha256":hashlib.sha256(open(p,"rb").read()).hexdigest()})'
                     '\nprint("MODULES_JSON:"+json.dumps(rows))')
            run = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                                  '--entrypoint', 'python', '-e', 'AWS_EC2_METADATA_DISABLED=true',
                                  '-e', 'AWS_DEFAULT_REGION=ap-northeast-2',
                                  '-e', 'BUCKET_NAME=' + BUCKET, uri,
                                  '-c', smoke], capture_output=True, text=True)
            result['imports'][role] = {'returncode': run.returncode,
                                       'stdout': run.stdout[-12000:], 'stderr': run.stderr[-12000:]}
            save()
            assert run.returncode == 0, result['imports'][role]
            rows = json.loads(next(line.split('MODULES_JSON:', 1)[1] for line in run.stdout.splitlines()
                                   if line.startswith('MODULES_JSON:')))
            for row in rows:
                source = destination / 'payload' / row['path'].removeprefix('/var/task/')
                assert source.exists() and digest(source) == row['sha256'], row
            subprocess.run(['docker', 'push', uri], check=True)
            image = ecr.describe_images(repositoryName=REPOSITORY,
                                        imageIds=[{'imageTag': tag}])['imageDetails'][0]
            result['images'][role] = {'uri': uri.split(':dnsp-')[0] + '@' + image['imageDigest'],
                                      'tag': tag, 'source_sha256': item['sha256']}
            save()
            subprocess.run(['docker', 'image', 'rm', uri], check=True)
            subprocess.run(['docker', 'builder', 'prune', '--force'], check=True)
        result['status'] = 'built_imports_verified'
        save()
    except Exception as exc:
        result.update(status='failed', error_type=type(exc).__name__, error=str(exc)[-12000:])
        save()
        raise


if __name__ == '__main__':
    main()
