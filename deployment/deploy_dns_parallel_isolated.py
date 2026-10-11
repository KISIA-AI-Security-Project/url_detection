"""Publish an isolated DNS-parallel candidate with resumable AWS reconciliation.

Run only after scoped Step Functions role creation has been confirmed.
"""
import base64
import hashlib
import json
from pathlib import Path
import sys
import time

import boto3


ROOT = Path('/tmp/dnsp-build-v4/packet')
BUILD = Path('/tmp/dnsp-build-v4/build-result.json')
RECEIPT = Path('/tmp/dnsp-deployment-receipt-v3.json')
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
ACCOUNT = '998301375101'
REGION = 'ap-northeast-2'
OLD_SFN = f'arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:team5-itg-orchestrator-20260914'
NEW_NAME = 'team5-itg-dns-parallel-20260916'
NEW_SFN = f'arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:{NEW_NAME}'
ROLE = 'team5-itg-dnsp-sfn-20260916'
ROLE_SOURCE = 'team5-itg-sfn-20260914'
EXPECTED_OLD_REVISION = 'eba7b921-5564-4e50-97be-fd469cd29c82'
EXPECTED_PREVIOUS = {'l0': 2, 'l1': 2, 'l23': 2, 'context': 1, 'judgment': 10}
EXPECTED_OLD_PINS = {'l0': 1, 'l1': 1, 'l23': 1, 'context': 1, 'judgment': 4}
FUNCTIONS = {role: f'team5-itg-{role}-20260914' for role in EXPECTED_PREVIOUS}
EXPECTED_POLICY = {'Version': '2012-10-17', 'Statement': [
    {'Effect': 'Allow', 'Action': 'lambda:InvokeFunction',
     'Resource': [f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTIONS[role]}:*'
                  for role in ('l0', 'l1', 'l23', 'context', 'judgment')]},
    {'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:PutItem',
                                  'dynamodb:UpdateItem'],
     'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/Team5-firstDB',
     'Condition': {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': ['a50914*']}}}]}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(receipt):
    RECEIPT.write_text(json.dumps(receipt, indent=2, default=str))
    boto3.client('s3', region_name=REGION).put_object(
        Bucket=BUCKET, Key='evaluation/dns-inactivity-20260916/deployment-receipt-v3.json',
        Body=RECEIPT.read_bytes())


def main():
    assert boto3.client('sts').get_caller_identity()['Account'] == ACCOUNT
    manifest = json.loads((ROOT / 'package-manifest.json').read_text())
    contract = json.loads((ROOT / 'deployment-contract.json').read_text())
    built = json.loads(BUILD.read_text())
    assert built['status'] == 'built_imports_verified'
    assert built['packet_sha256'] == sha(Path('/tmp/dnsp-build-v4/isolated-candidate-v3.zip'))
    assert set(manifest['packages']) == {'l0', 'l1', 'l23', 'context', 'judgment', 'result'}
    for role, item in manifest['packages'].items():
        assert sha(ROOT / item.get('context_zip', item.get('package'))) == item['sha256']
    assert sha(ROOT / 'definition.json') == manifest['candidate_definition_sha256']
    assert all(manifest['functions'][role] == manifest['functions']['context']
               for role in ('activity', 'context'))
    ecr = boto3.client('ecr', region_name=REGION)
    for role in ('l0', 'l1', 'l23'):
        image = built['images'][role]
        assert image['source_sha256'] == manifest['packages'][role]['sha256']
        actual = ecr.describe_images(repositoryName='team5-itg-20260914',
                                     imageIds=[{'imageTag': image['tag']}])['imageDetails'][0]
        assert image['uri'].endswith('@' + actual['imageDigest'])
    lam = boto3.client('lambda', region_name=REGION)
    sf = boto3.client('stepfunctions', region_name=REGION)
    iam = boto3.client('iam')
    old = sf.describe_state_machine(stateMachineArn=OLD_SFN)
    assert old['revisionId'] == EXPECTED_OLD_REVISION and old['status'] == 'ACTIVE'
    assert all(f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTIONS[role]}:'
               f'{pin}' in old['definition'] for role, pin in EXPECTED_OLD_PINS.items())
    source_policy = iam.get_role_policy(RoleName=ROLE_SOURCE,
                                        PolicyName='integration-validation')['PolicyDocument']
    assert source_policy == EXPECTED_POLICY, 'source_role_policy_drift'
    definition = (ROOT / 'definition.json').read_text()
    trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'states.amazonaws.com'},
        'Action': 'sts:AssumeRole', 'Condition': {
            'StringEquals': {'aws:SourceAccount': ACCOUNT},
            'ArnEquals': {'aws:SourceArn': NEW_SFN}}}]}
    try:
        existing_sfn = sf.describe_state_machine(stateMachineArn=NEW_SFN)
    except sf.exceptions.StateMachineDoesNotExist:
        existing_sfn = None
    if existing_sfn:
        assert existing_sfn['definition'] == definition, 'target_definition_drift'
        assert existing_sfn['roleArn'] == f'arn:aws:iam::{ACCOUNT}:role/{ROLE}'
        assert existing_sfn['type'] == 'STANDARD'
    try:
        existing_role = iam.get_role(RoleName=ROLE)['Role']
    except iam.exceptions.NoSuchEntityException:
        existing_role = None
    if existing_role:
        assert existing_role['AssumeRolePolicyDocument'] == trust, 'target_role_trust_drift'
        try:
            target_policy = iam.get_role_policy(RoleName=ROLE,
                                                PolicyName='integration-validation')['PolicyDocument']
        except iam.exceptions.NoSuchEntityException:
            target_policy = None
        if target_policy is not None:
            assert target_policy == EXPECTED_POLICY, 'target_role_policy_drift'
    else:
        target_policy = None
    complete = {}
    for role, previous in EXPECTED_PREVIOUS.items():
        versions = [int(item['Version']) for item in lam.list_versions_by_function(
            FunctionName=FUNCTIONS[role])['Versions'] if item['Version'].isdigit()]
        assert max(versions) in (previous, previous + 1), (role, versions)
        config = lam.get_function_configuration(FunctionName=FUNCTIONS[role])
        assert config['LastUpdateStatus'] == 'Successful'
        assert config['State'] == 'Active'
        assert not lam.list_aliases(FunctionName=FUNCTIONS[role])['Aliases']
        assert not lam.list_event_source_mappings(FunctionName=FUNCTIONS[role])['EventSourceMappings']
        assert not lam.list_function_url_configs(FunctionName=FUNCTIONS[role])['FunctionUrlConfigs']
        if role == 'judgment':
            for key, value in contract['judgment'].items():
                assert config.get('Environment', {}).get('Variables', {}).get(key) == value, (role, key)
        if max(versions) == previous + 1:
            published = lam.get_function(FunctionName=FUNCTIONS[role],
                                         Qualifier=str(previous + 1))
            assert published['Configuration']['FunctionArn'] == manifest['functions'][role]
            environment = published['Configuration']['Environment']['Variables']
            assert environment['EVIDENCE_ROLE'] == role
            for key, value in contract['environment_common'].items():
                assert environment[key] == value, (role, key)
            if role == 'context':
                for key, value in contract['context'].items():
                    assert environment[key] == value, (role, key)
            if role == 'judgment':
                for key, value in contract['judgment'].items():
                    assert environment[key] == value, (role, key)
            item = manifest['packages'][role]
            if role in built['images']:
                assert published['Code']['ResolvedImageUri'] == built['images'][role]['uri']
            else:
                expected_zip_sha = base64.b64encode(hashlib.sha256(
                    (ROOT / item['package']).read_bytes()).digest()).decode()
                assert published['Configuration']['CodeSha256'] == expected_zip_sha
            complete[role] = {'arn': published['Configuration']['FunctionArn'],
                              'code_sha256': published['Configuration']['CodeSha256']}
    receipt = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {
        'phase': 'preflight_complete', 'candidate_sha256': built['packet_sha256'],
        'old_state_machine_revision': old['revisionId'], 'functions': {},
        'new_state_machine': NEW_SFN, 'role': ROLE}
    assert receipt['candidate_sha256'] == built['packet_sha256']
    assert receipt['old_state_machine_revision'] == EXPECTED_OLD_REVISION
    receipt['functions'].update(complete)
    if '--preflight-only' in sys.argv:
        print(json.dumps({'status': 'preflight_ok', 'candidate_sha256': built['packet_sha256'],
                          'old_state_machine_revision': old['revisionId'],
                          'new_state_machine': NEW_SFN, 'new_role': ROLE,
                          'fixed_policy': EXPECTED_POLICY, 'published': sorted(complete),
                          'role_exists': bool(existing_role),
                          'state_machine_exists': bool(existing_sfn)}, indent=2))
        return
    save(receipt)
    for role, previous in EXPECTED_PREVIOUS.items():
        if role in complete:
            continue
        name = FUNCTIONS[role]
        item = manifest['packages'][role]
        if role in built['images']:
            image = built['images'][role]
            assert image['source_sha256'] == item['sha256']
            lam.update_function_code(FunctionName=name, ImageUri=image['uri'])
        else:
            lam.update_function_code(FunctionName=name,
                                     ZipFile=(ROOT / item['package']).read_bytes())
        lam.get_waiter('function_updated_v2').wait(FunctionName=name)
        config = lam.get_function_configuration(FunctionName=name)
        variables = dict(config.get('Environment', {}).get('Variables', {}))
        variables.update(contract['environment_common'])
        variables['EVIDENCE_ROLE'] = role
        if role == 'context':
            variables.update(contract['context'])
        lam.update_function_configuration(FunctionName=name,
                                          Environment={'Variables': variables})
        lam.get_waiter('function_updated_v2').wait(FunctionName=name)
        published = lam.publish_version(FunctionName=name,
                                        Description='Isolated DNS parallel candidate 2026-09-16')
        assert int(published['Version']) == previous + 1, (role, published['Version'])
        assert published['FunctionArn'] == manifest['functions'][role]
        receipt['functions'][role] = {'arn': published['FunctionArn'],
                                      'code_sha256': published['CodeSha256']}
        receipt['phase'] = 'functions_publishing'
        save(receipt)
    if existing_role is None:
        existing_role = iam.create_role(
            RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{'Key': 'Project', 'Value': 'team5-url-detection'},
                  {'Key': 'Purpose', 'Value': 'isolated-dns-parallel'}])['Role']
        receipt['role_arn'] = existing_role['Arn']
        receipt['phase'] = 'role_created_policy_pending'
        save(receipt)
    if target_policy is None:
        iam.put_role_policy(RoleName=ROLE, PolicyName='integration-validation',
                            PolicyDocument=json.dumps(EXPECTED_POLICY))
    receipt['role_arn'] = existing_role['Arn']
    receipt['phase'] = 'role_created'
    save(receipt)
    validation = sf.validate_state_machine_definition(definition=definition, type='STANDARD')
    assert validation['result'] == 'OK', validation
    receipt['asl_validation'] = {'result': validation['result'],
                                 'diagnostics': validation['diagnostics']}
    save(receipt)
    if existing_sfn is None:
        time.sleep(10)
        created = sf.create_state_machine(name=NEW_NAME, definition=definition,
                                          roleArn=existing_role['Arn'], type='STANDARD',
                                          tags=[{'key': 'Project', 'value': 'team5-url-detection'},
                                                {'key': 'Purpose', 'value': 'isolated-dns-parallel'}])
        assert created['stateMachineArn'] == NEW_SFN
    receipt['phase'] = 'deployed_not_executed'
    deployed = sf.describe_state_machine(stateMachineArn=NEW_SFN)
    assert deployed['status'] == 'ACTIVE'
    assert deployed['definition'] == definition
    assert deployed['roleArn'] == existing_role['Arn']
    assert deployed['type'] == 'STANDARD'
    receipt['state_machine_revision'] = deployed.get('revisionId')
    receipt['state_machine_definition_sha256'] = hashlib.sha256(definition.encode()).hexdigest()
    receipt['state_machine_creation_date'] = deployed['creationDate'].isoformat()
    assert sf.describe_state_machine(stateMachineArn=OLD_SFN)['revisionId'] == EXPECTED_OLD_REVISION
    save(receipt)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
