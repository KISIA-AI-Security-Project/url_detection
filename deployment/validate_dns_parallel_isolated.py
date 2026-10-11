"""Run bounded isolated AWS DNS-parallel probes without a model call on direct probes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

import boto3
from boto3.dynamodb.types import TypeDeserializer


REGION = 'ap-northeast-2'
ACCOUNT = '998301375101'
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
TABLE = 'Team5-firstDB'
MACHINE = f'arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:team5-itg-dns-parallel-20260916'
ROOT = Path('/tmp/dnsp-build-v4/packet')
OUT = Path('/tmp/dnsp-validation-v3')
FUNCTIONS = {role: f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:team5-itg-{role}-20260914:{version}'
             for role, version in {'l0': 3, 'l1': 3, 'l23': 3, 'context': 3}.items()}


def save(label, result):
    OUT.mkdir(parents=True, exist_ok=True)
    body = json.dumps(result, ensure_ascii=False, indent=2, default=str).encode()
    (OUT / f'{label}.json').write_bytes(body)
    boto3.client('s3', region_name=REGION).put_object(
        Bucket=BUCKET, Key=f'evaluation/dns-inactivity-20260916/validation/{label}.json', Body=body)


def invoke(role, event):
    response = boto3.client('lambda', region_name=REGION).invoke(
        FunctionName=FUNCTIONS[role], InvocationType='RequestResponse',
        Payload=json.dumps(event).encode())
    payload = json.loads(response['Payload'].read())
    if response.get('FunctionError'):
        raise RuntimeError(f'{role}_lambda_error:{json.dumps(payload)[:1800]}')
    return payload


def object_evidence(key):
    data = boto3.client('s3', region_name=REGION).get_object(Bucket=BUCKET, Key=key)['Body'].read()
    value = json.loads(data)
    return {'key': key, 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'value': value}


def include_related(result):
    for layer in ('l0', 'l1', 'l2', 'l3'):
        record = result['artifacts'].get(layer)
        if record:
            key = record['value']['artifact_refs']['raw']
            result['artifacts'][f'{layer}_raw'] = object_evidence(key)
    final = result['artifacts'].get('final')
    if final and final['value'].get('audit_key'):
        result['artifacts']['context_audit'] = object_evidence(final['value']['audit_key'])


def collect(job, execution=None):
    ddb = boto3.client('dynamodb', region_name=REGION)
    item = ddb.get_item(TableName=TABLE, Key={'job_id': {'S': job}},
                        ConsistentRead=True).get('Item')
    decoded = {k: TypeDeserializer().deserialize(v) for k, v in item.items()} if item else None
    result = {'job_id': job, 'ddb': decoded, 'artifacts': {}, 'execution': execution}
    if decoded:
        for field in ('l0_key', 'l1_key', 'l2_key', 'l3_key', 'url_activity_key', 'final_key'):
            key = decoded.get(field)
            if key:
                name = field[:-4] if field.endswith('_key') else field
                result['artifacts'][name] = object_evidence(key)
        include_related(result)
    return result


def sf_probe(url, label):
    job = 'a50914' + uuid.uuid4().hex[:26]
    sf = boto3.client('stepfunctions', region_name=REGION)
    started = sf.start_execution(stateMachineArn=MACHINE,
                                 name=f'{label}-{job}',
                                 input=json.dumps({'job_id': job, 'url': url}))
    arn = started['executionArn']
    deadline = time.monotonic() + 780
    while time.monotonic() < deadline:
        execution = sf.describe_execution(executionArn=arn)
        if execution['status'] != 'RUNNING':
            break
        time.sleep(5)
    else:
        raise TimeoutError(f'execution_still_running:{arn}')
    events = sf.get_execution_history(executionArn=arn, maxResults=1000)['events']
    entered = [{'state': event['stateEnteredEventDetails']['name'],
                'at': event['timestamp'].isoformat()}
               for event in events if 'stateEnteredEventDetails' in event]
    failures = [{'type': event['type'], 'at': event['timestamp'].isoformat(),
                 'details': event.get('executionFailedEventDetails',
                                      event.get('taskFailedEventDetails'))}
                for event in events if event['type'] in ('ExecutionFailed', 'TaskFailed')]
    summary = {'arn': arn, 'status': execution['status'],
               'start': execution['startDate'].isoformat(),
               'stop': execution.get('stopDate').isoformat() if execution.get('stopDate') else None,
               'entered': entered, 'failures': failures,
               'judgment_entered': any(x['state'] == 'JudgmentTask' for x in entered)}
    result = collect(job, summary)
    if result['ddb']:
        os.environ['JOBS_TABLE'] = TABLE
        os.environ['EVIDENCE_BUCKET'] = BUCKET
        sys.path.insert(0, str(ROOT / 'result.zip'))
        import app
        result['consumer'] = json.loads(app.handler(
            {'pathParameters': {'scanId': job}}, None)['body'])
    result['input_url'] = url
    result['captured_at'] = datetime.now(timezone.utc).isoformat()
    save(label, result)
    print(json.dumps({'label': label, 'job_id': job, 'execution_status': summary['status'],
                      'ddb_status': (result['ddb'] or {}).get('status'),
                      'judgment_entered': summary['judgment_entered'],
                      'consumer_verdict': (result.get('consumer') or {}).get('verdict')}))


def direct_probe(url, label):
    job = 'a50914' + uuid.uuid4().hex[:26]
    event = {'job_id': job, 'attempt': 1, 'url': url}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {role: pool.submit(invoke, role, event) for role in ('l0', 'l1', 'l23')}
        layers = {role: future.result() for role, future in futures.items()}
    layer_refs = {'l0': layers['l0'], 'l1': layers['l1'],
                  'l2': layers['l23']['l2'], 'l3': layers['l23']['l3']}
    activity = invoke('context', {**event, 'operation': 'activity', 'layers': layer_refs})
    context = invoke('context', {**event, 'operation': 'context',
                                 'layers': layer_refs, 'url_activity': activity})
    keys = {role: layers[role]['s3_key'] for role in ('l0', 'l1')}
    keys.update({role: layer_refs[role]['s3_key'] for role in ('l2', 'l3')})
    keys.update(url_activity=activity['url_activity_key'], final=context['final_key'])
    result = {'job_id': job, 'input_url': url, 'layers': layers,
              'activity': activity, 'context': context,
              'artifacts': {name: object_evidence(key) for name, key in keys.items()},
              'captured_at': datetime.now(timezone.utc).isoformat(),
              'judgment_invocations': 0}
    include_related(result)
    save(label, result)
    print(json.dumps({'label': label, 'job_id': job,
                      'activity_state': activity['url_activity_state'],
                      'skip_judgment': activity['skip_judgment'],
                      'context_analysis_status': context['analysis_status']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=('sfn', 'direct'))
    parser.add_argument('label')
    parser.add_argument('url')
    args = parser.parse_args()
    assert boto3.client('sts').get_caller_identity()['Account'] == ACCOUNT
    {'sfn': sf_probe, 'direct': direct_probe}[args.kind](args.url, args.label)
