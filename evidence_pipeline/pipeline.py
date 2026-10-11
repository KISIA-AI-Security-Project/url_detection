"""계층 실행 → 불변 기록 → Context → 1회 판정과 형식 검증."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter
from uuid import uuid4
import json
import hashlib
from .records import build_record, canonical, digest
from .context import build_context
from .judgment_contract import evidence_ids
from .url_activity import assess_url_activity

VERDICTS={'MALICIOUS','LIKELY_BENIGN','SUSPICIOUS','UNKNOWN'}
SYSTEM_PROMPT=Path(__file__).with_name('judgment_prompt.txt').read_text(encoding='utf-8')
# Scope and historical-observation guidance are included in the frozen prompt.
TARGET_SCOPE_GUIDANCE=''


def render_context(context):
    """Serialize the selected evidence view without changing its frozen field order."""
    return json.dumps(context, ensure_ascii=False, separators=(',', ':'))

def validate_judgment(value, context, *, require_observations=False):
    if not isinstance(value,dict) or value.get('verdict') not in VERDICTS: raise ValueError('invalid_verdict')
    if not isinstance(value.get('summary'),str) or not value['summary'].strip(): raise ValueError('missing_summary')
    reasons=value.get('reasons')
    if not isinstance(reasons,list) or not 1<=len(reasons)<=5: raise ValueError('invalid_reasons')
    observations=value.get('observations',None if require_observations else [])
    if not isinstance(observations,list) or len(observations)>3:raise ValueError('invalid_observations')
    ids=set(evidence_ids(context))
    for reason in reasons+observations:
        if not isinstance(reason,dict) or not isinstance(reason.get('text'),str) or not reason.get('text') or not isinstance(reason.get('evidence_ids'),list) or not reason['evidence_ids'] or not all(isinstance(x,str) for x in reason['evidence_ids']): raise ValueError('missing_evidence_reference')
        if not set(reason['evidence_ids']) <= ids: raise ValueError('invalid_evidence_reference: '+', '.join(sorted(set(reason['evidence_ids'])-ids)))
    if not isinstance(value.get('limitations'),list) or not all(isinstance(x,str) for x in value['limitations']) or not isinstance(value.get('deep_analysis_needed'),bool): raise ValueError('invalid_limits')
    return value

class FastPipeline:
    def __init__(self, *, collector=None, l1_runner=None, judgment=None):
        from unified_scanner import UnifiedScanner
        self.scanner=collector or UnifiedScanner()
        self.l1_runner=l1_runner
        self.judgment=judgment

    def run(self,url,*,output_root,request_id=None,attempt='1'):
        from l0.registry import analyze
        from src.handler import run as run_l1
        request_id=request_id or 'remediation-'+uuid4().hex
        if any('/' in str(x) or '\\' in str(x) or '..' in str(x) for x in [request_id,attempt]): raise ValueError('invalid identity')
        root=Path(output_root)/request_id/str(attempt)
        root.mkdir(parents=True,exist_ok=False)
        started=perf_counter()
        l1_runner=self.l1_runner or (lambda value: run_l1(value,request_id,str(attempt)))
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures={'l0':pool.submit(analyze,url),'l1':pool.submit(l1_runner,url),'l23':pool.submit(self.scanner.scan_url,url)}
            outputs={}; failures={}
            for name,future in futures.items():
                try: outputs[name]=future.result()
                except Exception as exc: failures[name]={'code':'layer_execution_failed','error_type':type(exc).__name__,'message':str(exc)}
        l1, l1raw=outputs.get('l1',({},{}))
        for error in outputs.get('l23',{}).get('errors',[]):
            layer=str(error.get('layer','')).lower()
            if layer in {'l2','l3'}:failures[layer]={'code':'layer_execution_failed','stage':'analysis',**error}
        l23=outputs.get('l23',{}).get('layers',{})
        results={'l0':outputs.get('l0',{}),'l1':l1,'l2':l23.get('l2') or {},'l3':l23.get('l3') or {}}
        raws={name:value.get('raw',value.get('raw_evidence',{})) for name,value in results.items()}
        raws['l1']=l1raw
        for name in results:
            results[name].setdefault('target',{'original_url':url})
            failure=failures.get(name) or (failures.get('l23') if name in {'l2','l3'} else None)
            if failure: results[name]['errors']=[failure]
        records=[build_record(name,value,request_id=request_id,attempt=attempt,raw=raws[name]) for name,value in results.items()]
        url_activity=assess_url_activity(url,l1,l1raw,records,request_id=request_id,attempt=attempt)
        # This cross-layer decision is an orchestration artifact, not an L1
        # signal or a model verdict. Bind it to the exact producer artifacts.
        url_activity={**url_activity, 'request_id':request_id, 'attempt':str(attempt),
                      'source_references':[
                          {'key':'raw-l1.json','sha256':digest(l1raw)},
                          *({'key':f'record-{record["layer"]}.json','sha256':digest(record)}
                            for record in records if record['layer'] in {'l1','l2','l3'})]}
        # 구성·판정이 실패해도 이미 확보한 원문과 기록을 잃지 않는다.
        for name,raw in raws.items(): (root/f'raw-{name}.json').write_bytes(canonical(raw))
        snapshot=outputs.get('l23',{}).get('raw_snapshot')
        if snapshot is not None:(root/'raw-http-snapshot.json').write_bytes(canonical(snapshot))
        for record in records: (root/f'record-{record["layer"]}.json').write_bytes(canonical(record))
        (root/'url-activity.json').write_bytes(canonical(url_activity))
        response={'request_id':request_id,'attempt':str(attempt),'records':records,
                  'url_activity':url_activity,
                  'url_activity_reference':{'key':'url-activity.json','sha256':digest(url_activity)},
                  'pipeline_seconds_before_judgment':perf_counter()-started}
        try:
            audit={}
            context=build_context(records,raws,audit=audit)
            (root/'context-before-budget.json').write_text(render_context(context),encoding='utf-8')
            (root/'context-audit.json').write_bytes(canonical(audit))
            response.update(context=context, context_status='completed')
        except Exception as exc:
            context=None
            response.update(context_status='failed',context_error={'type':type(exc).__name__,'message':str(exc)},judgment_status='not_attempted_context_failure')
        if context is not None and self.judgment and url_activity['can_skip_judgment']:
            response['judgment_status']=(
                'not_requested_dns_name_nonexistent_at_scan'
                if url_activity['state']=='DNS_NAME_NONEXISTENT_AT_SCAN'
                else 'not_requested_url_unreachable_at_scan')
        elif context is not None and self.judgment:
            t=perf_counter()
            system_text=SYSTEM_PROMPT+TARGET_SCOPE_GUIDANCE
            context_text=render_context(context)
            try:
                prepare=getattr(type(self.judgment),'prepare_context',None)
                if callable(prepare):
                    selected=prepare(self.judgment,system_text,context)
                    if not isinstance(selected,dict):raise ValueError('invalid_prepared_context')
                    context=selected
                    response['context']=context
                    context_text=render_context(context)
                judgment_input={'system':system_text,'user':context_text}
                (root/'context-for-model.json').write_text(context_text,encoding='utf-8')
                (root/'judgment-input.json').write_bytes(canonical(judgment_input))
                response['judgment_input_sha256']=digest(judgment_input)
                value=self.judgment(system_text,context_text)
            except Exception as exc:
                response['judgment_status']='service_failed'
                response['judgment_error']={'type':type(exc).__name__,'message':str(exc),**getattr(exc,'detail',{})}
            else:
                response['judgment_unvalidated']=value
                try: response['judgment']=validate_judgment(value,context,require_observations=True);response['judgment_status']='completed'
                except ValueError as exc: response['judgment_status']='output_validation_failed';response['judgment_error']={'type':type(exc).__name__,'message':str(exc)}
            gateway_response=getattr(self.judgment,'last_response',None)
            if isinstance(gateway_response,dict):response['judgment_service_response']=gateway_response
            budget_check=getattr(self.judgment,'last_budget_check',None)
            if isinstance(budget_check,dict):
                response['judgment_budget_check']=budget_check
                (root/'judgment-budget.json').write_bytes(canonical(budget_check))
            request_body=getattr(self.judgment,'last_request_body',None)
            if isinstance(request_body,bytes):
                try:
                    json.loads(request_body.decode('utf-8'))
                except (ValueError,UnicodeError):
                    response['request_capture_error']='gateway_request_body_is_not_json'
                else:
                    (root/'judgment-request.json').write_bytes(request_body)
                    response['judgment_request_bytes_sha256']=hashlib.sha256(request_body).hexdigest()
            response['judgment_seconds']=perf_counter()-t
        elif context is not None: response['judgment_status']='not_requested'
        response['pipeline_seconds']=perf_counter()-started
        (root/'result.json').write_bytes(canonical(response))
        (root/'COMPLETE.json').write_bytes(canonical({'files':{p.name:digest(json.loads(p.read_text(encoding='utf-8'))) for p in root.glob('*.json')}}))
        return response
