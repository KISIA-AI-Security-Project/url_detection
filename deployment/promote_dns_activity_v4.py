"""Promote the reviewed context-only patch to the existing isolated AWS lane."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import time

import boto3


ROOT = Path('/home/cloudshell-user')
PACKET = Path('/tmp/dnsp-build-v4/packet')
MANIFEST = ROOT / 'patch-manifest.json'
PATCH_ZIP = ROOT / 'context-v4.zip'
DEFINITION = ROOT / 'definition-v4.json'
RECEIPT = Path('/tmp/dnsp-deployment-receipt-v4.json')
ACCOUNT = '998301375101'
REGION = 'ap-northeast-2'
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
NAME = 'team5-itg-context-20260914'
NEW_SFN = f'arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:team5-itg-dns-parallel-20260916'
OLD_SFN = f'arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:team5-itg-orchestrator-20260914'
OLD_REVISION = 'eba7b921-5564-4e50-97be-fd469cd29c82'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT}:role/team5-itg-dnsp-sfn-20260916'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def code_sha(path):
    return base64.b64encode(hashlib.sha256(path.read_bytes()).digest()).decode()


def save(receipt):
    RECEIPT.write_text(json.dumps(receipt, indent=2, default=str))
    boto3.client('s3', region_name=REGION).put_object(
        Bucket=BUCKET, Key='evaluation/dns-inactivity-20260916/deployment-receipt-v4.json',
        Body=RECEIPT.read_bytes())


def main():
    assert boto3.client('sts').get_caller_identity()['Account'] == ACCOUNT
    manifest = json.loads(MANIFEST.read_text())
    assert sha(PATCH_ZIP) == manifest['patched_package_sha256']
    assert sha(PACKET / 'context.zip') == manifest['source_package_sha256']
    assert sha(DEFINITION) == manifest['new_definition_sha256']
    assert sha(PACKET / 'definition.json') == manifest['old_definition_sha256']
    old_definition = json.loads((PACKET / 'definition.json').read_text())
    new_definition = json.loads(DEFINITION.read_text())
    assert manifest['old_function'].endswith(':2')
    assert manifest['new_function'].endswith(':3')
    for state in ('ActivityTask', 'ContextTask'):
        assert old_definition['States'][state]['Parameters']['FunctionName'] == manifest['old_function']
        assert new_definition['States'][state]['Parameters']['FunctionName'] == manifest['new_function']
    assert json.loads(json.dumps(new_definition).replace(manifest['new_function'],
                                                         manifest['old_function'])) == old_definition
    lam = boto3.client('lambda', region_name=REGION)
    sf = boto3.client('stepfunctions', region_name=REGION)
    old = sf.describe_state_machine(stateMachineArn=OLD_SFN)
    assert old['revisionId'] == OLD_REVISION
    target = sf.describe_state_machine(stateMachineArn=NEW_SFN)
    assert target['status'] == 'ACTIVE' and target['roleArn'] == ROLE_ARN
    assert target['type'] == 'STANDARD'
    target_definition = json.loads(target['definition'])
    assert target_definition in (old_definition, new_definition), 'isolated_sfn_definition_drift'
    versions = [int(value['Version']) for value in lam.list_versions_by_function(
        FunctionName=NAME)['Versions'] if value['Version'].isdigit()]
    assert max(versions) in (2, 3)
    previous = lam.get_function(FunctionName=NAME, Qualifier='2')
    assert previous['Configuration']['FunctionArn'] == manifest['old_function']
    assert previous['Configuration']['CodeSha256'] == code_sha(PACKET / 'context.zip')
    current = lam.get_function_configuration(FunctionName=NAME)
    assert current['State'] == 'Active' and current['LastUpdateStatus'] == 'Successful'
    assert current['Environment']['Variables'] == previous['Configuration']['Environment']['Variables']
    assert current['CodeSha256'] in (code_sha(PACKET / 'context.zip'), code_sha(PATCH_ZIP))
    assert not lam.list_aliases(FunctionName=NAME)['Aliases']
    assert not lam.list_event_source_mappings(FunctionName=NAME)['EventSourceMappings']
    assert not lam.list_function_url_configs(FunctionName=NAME)['FunctionUrlConfigs']
    if max(versions) == 3:
        assert current['CodeSha256'] == code_sha(PATCH_ZIP)
        published = lam.get_function(FunctionName=NAME, Qualifier='3')
        assert published['Configuration']['FunctionArn'] == manifest['new_function']
        assert published['Configuration']['CodeSha256'] == code_sha(PATCH_ZIP)
        assert published['Configuration']['Environment']['Variables'] == current['Environment']['Variables']
    validation = sf.validate_state_machine_definition(definition=DEFINITION.read_text(), type='STANDARD')
    assert validation['result'] == 'OK', validation
    if '--preflight-only' in sys.argv:
        print(json.dumps({'status': 'preflight_ok', 'published_context3': max(versions) == 3,
                          'sfn_updated': target_definition == new_definition,
                          'old_sfn_revision': old['revisionId'],
                          'asl_diagnostics': validation['diagnostics']}))
        return
    receipt = {'phase': 'preflight_complete', 'patch_manifest': manifest,
               'old_sfn_revision': old['revisionId'], 'asl_validation': validation['result']}
    save(receipt)
    if max(versions) == 2:
        if current['CodeSha256'] != code_sha(PATCH_ZIP):
            lam.update_function_code(FunctionName=NAME, ZipFile=PATCH_ZIP.read_bytes())
            lam.get_waiter('function_updated_v2').wait(FunctionName=NAME)
        published = lam.publish_version(FunctionName=NAME,
                                        Description='Isolated DNS NS-SOA activity amendment 2026-09-16')
        assert published['Version'] == '3'
        assert published['FunctionArn'] == manifest['new_function']
        assert published['CodeSha256'] == code_sha(PATCH_ZIP)
    receipt['context_version_arn'] = manifest['new_function']
    receipt['context_code_sha256'] = code_sha(PATCH_ZIP)
    receipt['phase'] = 'context3_published'
    save(receipt)
    if target_definition == old_definition:
        sf.update_state_machine(stateMachineArn=NEW_SFN, definition=DEFINITION.read_text())
    for _ in range(12):
        target = sf.describe_state_machine(stateMachineArn=NEW_SFN)
        if json.loads(target['definition']) == new_definition and target['status'] == 'ACTIVE':
            break
        time.sleep(5)
    else:
        raise RuntimeError('isolated_sfn_update_not_visible')
    assert target['roleArn'] == ROLE_ARN and target['type'] == 'STANDARD'
    assert sf.describe_state_machine(stateMachineArn=OLD_SFN)['revisionId'] == OLD_REVISION
    receipt['phase'] = 'deployed_not_executed'
    receipt['new_sfn_definition_sha256'] = hashlib.sha256(target['definition'].encode()).hexdigest()
    receipt['new_sfn_revision'] = target.get('revisionId')
    save(receipt)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
