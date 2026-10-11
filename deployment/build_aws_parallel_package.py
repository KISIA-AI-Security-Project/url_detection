"""Build local deployment artifacts against a saved live baseline. Never calls AWS."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import zipfile
import dns
import dns.version

from deployment.build_dns_parallel_candidate import patch_definition

ROOT = Path(__file__).resolve().parents[1]


def sha(data): return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def copy_tree(source, destination):
    for p in sorted(source.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and '.git' not in p.parts and p.suffix != '.pyc':
            dest = destination/p.relative_to(source)
            dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(p, dest)


def zip_tree(source, path):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(source.rglob('*')):
            if p.is_file():
                item = zipfile.ZipInfo(p.relative_to(source).as_posix(), (2026,9,14,0,0,0))
                item.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(item, p.read_bytes())
    return sha(path.read_bytes())


def previous_patch_definition(original, functions):
    value = deepcopy(original); states = value['States']
    # Preserve gate ordering and all existing collector branching and failure handling.
    for branch, role in zip(states['L0L1Parallel']['Branches'], ('l0','l1')):
        branch['States'][role.upper()+'_Invoke']['Parameters']['FunctionName'] = functions[role]
    states['L23Task']['Parameters']['FunctionName'] = functions['l23']
    states['ContextTask'] = {
        'Type':'Task','Resource':'arn:aws:states:::lambda:invoke',
        'Parameters':{'FunctionName':functions['context'],'Payload':{
            'job_id.$':'$.job_id','attempt.$':'$.alloc.attempt','url.$':'$.url',
            'layers':{'l0.$':'$.result.l0','l1.$':'$.result.l1',
                      'l2.$':'$.observe.l23.l2','l3.$':'$.observe.l23.l3'}}},
        'ResultSelector':{'ctx.$':'$.Payload'},'ResultPath':'$.context','TimeoutSeconds':60,
        'Catch':[{'ErrorEquals':['States.ALL'],'ResultPath':'$.error','Next':'MarkFailed'}],
        'Next':'MarkContext'}
    states['MarkObserved']['Parameters']['ExpressionAttributeValues'][':ff']['M'].update(
        status={'S':'PENDING'}, reason={'S':'Builder task follows collection'})
    states['MarkContext'] = {
        'Type':'Task','Resource':'arn:aws:states:::dynamodb:updateItem',
        'Parameters':{'TableName':states['MarkObserved']['Parameters']['TableName'],
          'Key':{'job_id':{'S.$':'$.job_id'}},
          'UpdateExpression':'SET final_key = :key, #fr.#fi = :fragment, updatedAt = :t',
          'ExpressionAttributeNames':{'#fr':'fragments','#fi':'final'},
          'ExpressionAttributeValues':{':key':{'S.$':'$.context.ctx.final_key'},
            ':fragment':{'M':{'key':{'S.$':'$.context.ctx.final_key'},
                             'status':{'S.$':'$.context.ctx.analysis_status'},
                             'at':{'S.$':'$$.State.EnteredTime'}}}, ':t':{'S.$':'$$.State.EnteredTime'}}},
        'ResultPath':None,'Catch':[{'ErrorEquals':['States.ALL'],'ResultPath':'$.error','Next':'MarkFailed'}],
        'Next':'JudgmentTask'}
    task = states['JudgmentTask']
    task['Parameters'] = {'FunctionName':functions['judgment'],'Payload':{
        'job_id.$':'$.job_id','attempt.$':'$.alloc.attempt','url.$':'$.url',
        'context_key.$':'$.context.ctx.final_key','context_sha256.$':'$.context.ctx.context_sha256'}}
    task['Comment'] = 'Read the explicit Builder artifact. Service/validation failure raises to MarkFailed; no UNKNOWN fallback.'
    task['Next'] = 'JudgmentSucceeded'
    states['JudgmentSucceeded'] = {'Type':'Choice','Choices':[{'And':[
        {'Variable':'$.final.judgment.judgment_status','IsPresent':True},
        {'Variable':'$.final.judgment.judgment_status','StringEquals':'completed'},
        {'Variable':'$.final.judgment.judgment_key','IsPresent':True},
        {'Variable':'$.final.judgment.verdict','IsPresent':True}], 'Next':'MarkJudged'}],
        'Default':'JudgmentInvalidReturn'}
    states['JudgmentInvalidReturn'] = {'Type':'Pass',
        'Result':{'Error':'JudgmentInvalidReturn','Cause':'No validated model judgment'},
        'ResultPath':'$.error','Next':'MarkFailed'}
    return value


def build(baseline, definition_path, deployed, output, functions):
    output.mkdir(parents=True, exist_ok=False)
    original = json.loads(definition_path.read_bytes())
    manifest = json.loads((baseline/'manifest.json').read_bytes())
    manifest = {m['name']:m for m in manifest}
    packages = {}
    for role in ('l0','l1','l23','context','judgment'):
        folder = output/role; payload = folder/'payload'; payload.mkdir(parents=True)
        copy_tree(ROOT/'evidence_pipeline', payload/'evidence_pipeline')
        copy_tree(Path(dns.__file__).parent, payload/'dns')
        if role in ('l0','l1','l23'):
            legacy = deployed/role/'payload'
            for name in ('legacy_handler.py','adapter.py','keys.py','fragment.py','sink.py'):
                shutil.copyfile(legacy/name, payload/name)
            if role=='l0':copy_tree(ROOT/'L0_SCANNER/src/l0', payload/'l0')
            if role=='l1':copy_tree(ROOT/'L1/src', payload/'src')
            if role=='l23':
                copy_tree(ROOT/'L2_SCANNER/l2_scanner', payload/'l2_scanner')
                copy_tree(ROOT/'L3_SCANNER', payload/'L3_SCANNER')
                copy_tree(ROOT/'url_collector', payload/'url_collector')
                copy_tree(ROOT/'unified_scanner', payload/'unified_scanner')
            image = manifest['team5-'+role]['image']
            # /var/task takes precedence over the installed scanner distributions.
            (folder/'Dockerfile').write_text('FROM '+image+'\nCOPY payload/ /var/task/\n'
                +'ENV EVIDENCE_ROLE='+role+'\nCMD ["evidence_pipeline.aws_runtime.handler"]\n', encoding='utf-8')
            packages[role] = {'kind':'image_overlay','base_image':image,
                              'context_zip':role+'-overlay.zip','sha256':zip_tree(folder, output/(role+'-overlay.zip'))}
        else:
            packages[role] = {'kind':'lambda_zip','package':role+'.zip','sha256':zip_tree(payload, output/(role+'.zip'))}
    result_payload = output/'result'/'payload'
    result_payload.mkdir(parents=True)
    shutil.copyfile(ROOT/'deployment/result/app.py', result_payload/'app.py')
    packages['result'] = {'kind':'lambda_zip','package':'result.zip',
                          'sha256':zip_tree(result_payload, output/'result.zip')}
    candidate = patch_definition(original, functions)
    save(output/'definition.json', candidate)
    save(output/'definition-original.json', original)
    settings = {'handler':'evidence_pipeline.aws_runtime.handler',
        'result_handler':'app.handler', 'bundled_dnspython':dns.version.version,
        'environment_common':{'OUTPUT_BUCKET':'team5-evidence-998301375101-ap-northeast-2-an',
                              'EVIDENCE_JOB_PREFIX':'a50914'},
        'roles':{role:{'EVIDENCE_ROLE':role} for role in packages if role!='result'},
        'judgment':{'ANTHROPIC_BASE_URL':'https://monogpt.kr/api/monorouter/claude-code',
          'JUDGMENT_MODEL':'claude-haiku-4.5','LLM_SECRET_ID':'team5/judgment/llm-api-key',
          'LLM_TIMEOUT_SECONDS':'50','JUDGMENT_MAX_TOKENS':'1600'},
        'context':{'CONTEXT_MAX_BYTES':'400000'},
        'iam_requirements':[
            'Producer GetObject+PutObject on its own raw/{job}/{attempt}/{layer}/ and records/{job}/{attempt}/{layer}/ paths for immutable retry verification.',
            'Context role handles operation=activity and operation=context; GetObject on L0-L3 raw and records; GetObject+PutObject on records/.../final/ including url-activity.json. No record prefix enumeration.',
            'Judgment GetObject on final.json and url-activity.json; GetObject+PutObject on judgments/{job}/{attempt}.json and judgments/{job}/{attempt}/ artifacts; existing Secrets Manager reference.',
            'Isolated result GetItem on Team5-firstDB and GetObject on the decision artifact; no public API integration in this package.',
            'State-machine invoke permission for all selected isolated functions. DynamoDB writer remains the state machine.'
        ],
        'preserve':['existing VPC/network routing and layer budgets',
                    'original image and Lambda/SFN snapshots for rollback',
                    'production Team5-result and team5-orchestrator unchanged'],
        'excluded':['GPU four-shard runners','Bedrock model invocation'],
        'limitations':['Image overlays require build/import verification on Linux against pinned base images.',
                       'ActivityTask reuses a published version of the existing isolated Context function; the Step Functions role needs no new Lambda ARN permission.',
                       'Isolated result consumer requires separate invocation/integration verification.',
                       'Code/adapter readiness is not URL-quality approval.']}
    save(output/'deployment-contract.json', settings)
    save(output/'package-manifest.json', {'packages':packages,'functions':functions,
          'bundled_dnspython':dns.version.version,
          'baseline_definition_sha256':sha(definition_path.read_bytes()),
          'candidate_definition_sha256':sha((output/'definition.json').read_bytes()),
          'builder_sha256':sha((ROOT/'deployment/build_aws_parallel_package.py').read_bytes()),
          'asl_builder_sha256':sha((ROOT/'deployment/build_dns_parallel_candidate.py').read_bytes()),
          'result_source_sha256':sha((ROOT/'deployment/result/app.py').read_bytes()),
          'source_files':{p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in sorted((ROOT/'evidence_pipeline').glob('*')) if p.is_file()},
          'aws_actions':0})
    return packages


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for option in ('baseline','definition','deployed','output','functions'):parser.add_argument('--'+option,required=True)
    args=parser.parse_args()
    print(json.dumps(build(Path(args.baseline),Path(args.definition),Path(args.deployed),Path(args.output),
                           json.loads(Path(args.functions).read_bytes())),indent=2))
