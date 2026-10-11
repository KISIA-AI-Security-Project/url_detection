"""Build a reproducible isolated Judgment v2 package and SFN definition."""
import argparse
import json
from pathlib import Path

import dns

from deployment.build_aws_parallel_package import copy_tree, zip_tree


ROOT = Path(__file__).resolve().parents[1]
VERSION = 'fact-interpretation-selection-2'


def patch_definition(value, function_arn):
    value = json.loads(json.dumps(value))
    states = value['States']
    task = states['JudgmentTask']
    task['Parameters']['FunctionName'] = function_arn
    task['Comment'] = 'Isolated Judgment v2. A rejected or failed result reaches MarkFailed without a URL verdict.'
    allocation = states['AllocAttempt']['Parameters']
    if 'judgment_status, block_reason' not in allocation['UpdateExpression']:
        raise ValueError('attempt_reset_contract_drift')
    allocation['UpdateExpression'] = allocation['UpdateExpression'].replace(
        'judgment_status, block_reason',
        'judgment_status, judgment_contract_version, block_reason')
    marked = states['MarkJudged']['Parameters']
    marked['UpdateExpression'] += ', judgment_contract_version = :jcv'
    marked['ExpressionAttributeValues'][':jcv'] = {'S': VERSION}
    return value


def build(definition_path, function_arn, output):
    if not function_arn.startswith('arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-'):
        raise ValueError('isolated_lambda_arn_required')
    output.mkdir(parents=True, exist_ok=False)
    payload = output / 'payload'
    payload.mkdir()
    copy_tree(ROOT / 'evidence_pipeline', payload / 'evidence_pipeline')
    copy_tree(Path(dns.__file__).parent, payload / 'dns')
    package = output / 'judgment-v2.zip'
    package_sha = zip_tree(payload, package)
    definition = patch_definition(json.loads(definition_path.read_text(encoding='utf-8')), function_arn)
    out_definition = output / 'definition.json'
    out_definition.write_text(json.dumps(definition, ensure_ascii=False, indent=2), encoding='utf-8')
    result_payload = output / 'result-payload'
    result_payload.mkdir()
    (result_payload / 'app.py').write_bytes((ROOT / 'deployment/result/app.py').read_bytes())
    copy_tree(ROOT / 'evidence_pipeline', result_payload / 'evidence_pipeline')
    copy_tree(Path(dns.__file__).parent, result_payload / 'dns')
    result_sha = zip_tree(result_payload, output / 'result-candidate.zip')
    manifest = {'handler': 'evidence_pipeline.aws_judgment_v2.handler',
                'judgment_package_sha256': package_sha,
                'result_candidate_sha256': result_sha,
                'function_arn': function_arn,
                'source_definition': str(definition_path),
                'judgment_contract_version': VERSION}
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--definition', type=Path, required=True)
    parser.add_argument('--function-arn', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.definition, args.function_arn, args.output), ensure_ascii=False, indent=2))
