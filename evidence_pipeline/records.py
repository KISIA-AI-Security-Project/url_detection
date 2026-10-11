"""확보한 사실과 미확정 원인을 분리하고 Raw 위치에 연결한다."""
from copy import deepcopy
from hashlib import sha256
import json
from .record_contract import (execution_for,acquisition_for,analysis_for,l1_observation,validate_record,
    L0_OBSERVATION_CONTRACT,SIGNAL_STATES,validate_l0_observation_result)

SCHEMA_VERSION = "3.1-experimental"

# 기존 기능명과 detected의 극성이 다른 항목은 실제 코드 조건을 명시한다.
DETECTOR_PREDICATES={
    'L2-H-05':'HTTP declared type differs from the libmagic prefix classification after configured MIME aliases',
    'L2-H-06':'filename extension or prefix MIME classification matches the configured executable-type lists; not a malware verdict',
    # 과거 C01 bool 결과에만 적용한다. 새 measurement 결과는 이 조건을 사용하지 않는다.
    'L2-C-01':'certificate age is within the configured freshness threshold',
    'L2-C-02':'certificate is expired or not yet valid at observation time',
    'L2-C-03':'certificate hostname comparison returned matched=false',
    'L2-C-04':'leaf certificate self-signature verification returned true',
    'L2-C-05':'certificate chain verification returned valid=false',
    'L2-C-06':'CT first-seen age is within the configured freshness threshold',
    'L2-C-07':'negotiated TLS version is in the configured legacy-version set',
    'L2-C-08':'a wildcard name was present in the certificate',
}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def digest(value): return sha256(canonical(value)).hexdigest()

def cause_kind(code):
    if code.endswith('_not_configured'): return 'capability_not_configured'
    if code=='brand_not_identified': return 'identification_unresolved'
    if code in {'brand_absent_from_domain_reference','brand_domain_reference_empty'}: return 'reference_coverage_gap'
    if code=='brand_resource_evaluator_abstained': return 'evaluation_abstained'
    if code=='analysis_unresolved_reason_not_recorded': return 'reason_not_recorded'
    if code.startswith('brand_') and 'invalid' in code: return 'invalid_policy_result_or_configuration'
    if "policy" in code and ("unresolved" in code or "missing" in code): return "policy_unconfigured"
    if "blocked" in code: return "collection_blocked"
    if "timeout" in code: return "collection_timeout"
    if "parse" in code or "syntax" in code: return "parse_unsupported_or_invalid"
    if "encoding" in code or "decoding" in code: return "decoding_incomplete"
    if "truncat" in code or "limit" in code or "interrupted" in code: return "partial_observation"
    if "order" in code or "selector" in code or "conditional" in code or "source_sink" in code or "callback" in code: return "relationship_unresolved"
    if "source_unavailable" in code: return "source_unavailable"
    if "unsupported_content" in code: return "content_outside_analyzer_scope"
    if "not_attempted" in code: return "not_attempted"
    if "historical" in code: return "historical_observation_limit"
    return "tool_or_collection_error"

def _build_l0_observation_record(result,raw,*,request_id,attempt,mode,source_reference):
    """Store the approved three-field records; execution/error metadata is shared."""
    errors=deepcopy(result['errors'])
    for i,error in enumerate(raw.get('query_errors',[])):
        error=deepcopy(error)
        error.setdefault('code','query_component_parse_failed')
        error.setdefault('stage','query_parsing')
        error.setdefault('impact_scope','analysis')
        error.setdefault('occurrence_id',f'l0:query:{i}')
        error.setdefault('target',{'query_error_index':i})
        errors.append(error)
    if raw.get('parse_status')!='SUCCESS':
        errors.append({'code':'url_parse_failed','stage':'url_parsing','impact_scope':'analysis',
            'occurrence_id':'l0:url_parse','target':raw.get('raw_url'),'parse_status':raw.get('parse_status')})
    analysis_state=('not_performed' if result['analysis_execution']['state']=='not_run' else
                    'partial' if errors else 'completed')
    signals=deepcopy(result['observations'])
    counts={state:len(signals) if state=='observed' else 0 for state in sorted(SIGNAL_STATES)}
    record={'schema_version':SCHEMA_VERSION,'record_contract_version':'l0-observations-1',
        'request_id':request_id,'attempt':str(attempt),'layer':'l0',
        'analysis_status':{'not_performed':'NOT_PERFORMED','partial':'PARTIAL','completed':'COMPLETED'}[analysis_state],
        'execution':{'state':'completed','reason':None,'result_counts':counts},
        'acquisition':{'state':'observed' if 'raw_url' in raw else 'unrecorded'},
        'analysis':{'state':analysis_state},
        'target':deepcopy(result.get('target') or {'original_url':raw.get('raw_url')}),
        'coverage':{'producer_contract':L0_OBSERVATION_CONTRACT,'parse_status':raw.get('parse_status'),
            'query_status':raw.get('query_status'),'analysis_execution':deepcopy(result['analysis_execution']),
            'judgment_guidance':deepcopy(result['judgment_guidance']),
            'reference_versions':deepcopy(result['reference_versions'])},
        'signals':signals,'errors':errors,'raw_ref':{'key':'raw-l0.json','sha256':digest(raw)},
        'provenance':{'mode':mode,'source_reference':deepcopy(source_reference)}}
    return validate_record(record)


def build_record(layer, result, *, request_id, attempt, raw=None, mode="current", source_reference=None):
    """기존 상태 문자열을 맹신하지 않고 실제 관측 축을 함께 기록한다."""
    layer=layer.lower()
    result=deepcopy(result or {})
    if layer=='l0' and result.get('producer_contract') not in {None,'url-evaluations-2',L0_OBSERVATION_CONTRACT}:
        raise ValueError('unsupported_l0_producer_contract')
    compact_l0=layer=='l0' and result.get('producer_contract')==L0_OBSERVATION_CONTRACT
    if compact_l0:validate_l0_observation_result(result)
    raw=deepcopy(raw if raw is not None else result.get("raw", result.get("raw_evidence", {})))
    if compact_l0 and raw!=result['raw_evidence']:raise ValueError('l0_raw_input_mismatch')
    if compact_l0:
        return _build_l0_observation_record(result,raw,request_id=request_id,attempt=attempt,
            mode=mode,source_reference=source_reference)
    raw_hash=digest(raw)
    analysis_facts=deepcopy(result.get('analysis_facts',[]))
    if layer=='l1' and isinstance(result.get('ns_registration_comparison'),dict):
        comparison=deepcopy(result['ns_registration_comparison'])
        by_name={item.get('name'):f'l1:{i}' for i,item in enumerate(result.get('인프라결과_목록',[]))}
        source_names=(comparison.get('dns_lookup'),comparison.get('rdap_lookup'))
        if all(name in by_name for name in source_names):
            analysis_facts.append({'id':'l1:ns-registration-comparison',
                'kind':'dns_rdap_nameserver_set_comparison',
                'domain':comparison.get('domain'),'same_set':comparison.get('same_set'),
                'scope':comparison.get('scope'),
                'source_evidence_ids':[by_name[name] for name in source_names],
                'source':{'pointer':'/','sha256':raw_hash}})
    for i,fact in enumerate(analysis_facts):
        # Validate the analyzer's input binding; never recompute its finding here.
        source=fact.get('source') or {}
        value=raw
        try:
            for token in ([] if source['pointer'] in ('','/') else source['pointer'].strip('/').split('/')):
                token=token.replace('~1','/').replace('~0','~')
                value=value[int(token)] if isinstance(value,list) else value[token]
        except (KeyError,IndexError,TypeError,ValueError):
            raise ValueError('analysis_fact_source_pointer_invalid') from None
        if digest(value)!=source.get('sha256'):
            raise ValueError('analysis_fact_source_hash_mismatch')
        fact['raw_reference']={'key':f'raw-{layer}.json','sha256':raw_hash,
                               'pointer':source['pointer']}
        fact['record_reference']={'key':f'record-{layer}.json','pointer':f'/analysis_facts/{i}'}
    root=f"raw-{layer}.json"
    causes=[]
    by_key={}
    def add_cause(value, pointer):
        value=deepcopy(value if isinstance(value,dict) else {"message":str(value)})
        code=value.get("code") or value.get("error_type") or "unspecified_tool_error"
        # These errors are produced by this adapter at known acquisition/analysis boundaries.
        if 'impact_scope' not in value:
            if code.startswith('infrastructure_'):value['impact_scope']='execution' if code in ('infrastructure_budget_exceeded','infrastructure_control_probe_failed','infrastructure_run_failed') else 'acquisition'
            elif code in ('url_parse_failed','query_component_parse_failed','url_pattern_analysis_unavailable','analysis_unresolved_reason_not_recorded'):value['impact_scope']='analysis'
        # Only an explicit occurrence ID establishes a shared event across record locations.
        identity={k:v for k,v in value.items() if k not in {"source_pointer","source_hint"}}
        identity['code']=code
        if value.get('occurrence_id') is None:
            identity['record_location']=pointer
        key=digest(identity)
        if key not in by_key:
            cid=f"{layer}:cause:{key[:16]}"
            by_key[key]=cid
            causes.append({"id":cid,"kind":cause_kind(str(code)),"code":code,"detail":value,
                           "record_reference":{"key":f'record-{layer}.json',"pointer":f"/causes/{len(causes)}/detail"},
                           "source_hint":pointer,"source_hints":[pointer],"raw_reference":root})
        else:
            cause=next(c for c in causes if c['id']==by_key[key])
            if pointer not in cause['source_hints']: cause['source_hints'].append(pointer)
        return by_key[key]
    errors=list(result.get("errors") or [])
    if layer=='l0' and result.get('parse_status',raw.get('parse_status')) not in {None,'SUCCESS'}:
        errors.append({'code':'url_parse_failed','stage':'url_parsing','url':raw.get('raw_url'),
            'status':result.get('parse_status',raw.get('parse_status')),'detail':raw.get('error') or raw.get('parse_error')})
    if layer=='l1' and result.get('전체상태')=='실패':
        reason=result.get('실패사유')
        errors.append({'code':'infrastructure_budget_exceeded' if reason=='관측 무효(예산 초과)' else 'infrastructure_control_probe_failed' if reason=='관측 무효(대조 무응답)' else 'infrastructure_run_failed','reason':reason})
    if layer=='l3':
        errors+=list(raw.get("html",{}).get("errors") or [])+list(raw.get("javascript",{}).get("errors") or [])
        for script in raw.get("javascript",{}).get("scripts",[]):
            for error in script.get("collection_errors",[]):
                errors.append({**error,"script_id":script.get("script_id")})
    for i,error in enumerate(errors): add_cause(error,f"/errors/{i}")
    query_cause_ids = [add_cause({'code':'query_component_parse_failed',**e},f'/query_errors/{j}')
                       for j,e in enumerate(raw.get('query_errors',[]))] if layer=='l0' else []
    if mode=='historical':
        add_cause({"code":"historical_source_not_recollected", "message":"Stored observations reused; absent original HTML/JS cannot be re-extracted or treated as current page behavior"}, "/provenance")
    signals=[]
    # Native v2 URL evaluations carry their facts/relationships directly. They
    # never pass through the legacy detected/status conversion below.
    for i,item in enumerate(result.get('evaluations',[])):
        predicate=deepcopy(item['predicate']); applicability=deepcopy(item['applicability'])
        state=('not_applicable' if applicability['state']=='not_applicable' else
               'unresolved' if predicate['result']=='unresolved' else 'relationship_record_only')
        cids=[add_cause(e,f'/evaluations/{i}/limitations/{j}') for j,e in enumerate(item.get('limitations',[]))]
        if state=='unresolved' and not cids:
            cids.append(add_cause({'code':'url_pattern_analysis_unavailable','stage':'url_evaluation',
                'impact_scope':'analysis','occurrence_id':f'l0:evaluator:{i}','analyzer':item['name'],
                'target':raw.get('raw_url'),'detail':deepcopy(item.get('facts'))},f'/evaluations/{i}'))
        signals.append({'id':f'l0:{item["name"]}','name':item['name'],'state':state,
            'assessment':{'predicate':predicate,'applicability':applicability,**deepcopy(item['interpretation'])},
            'scope':deepcopy(item['scope']),'evidence':deepcopy(item.get('facts')),
            'analysis_provenance':{'list_version':deepcopy(item.get('reference_versions',{}))},
            'cause_ids':cids,'record_reference':{'key':f'record-{layer}.json','pointer':f'/signals/{i}'}})
    for i,item in enumerate(result.get("signals",result.get("analysis_records",[]))):
        item=deepcopy(item.get("analysis_record",item))
        identifier=item.get("id") or f"{layer}:{item.get('name',i)}"
        status=item.get("status")
        detected=item.get("detected")
        measurement=layer=='l2' and item.get('result_kind')=='measurement'
        if measurement and (identifier not in {'L2-C-01','L2-C-06'} or
                item.get('measurement_state') not in {'observed','unavailable'} or 'detected' in item):
            raise ValueError('invalid_l2_measurement_result')
        if layer=='l0': detected=True if status=='확인함' else None
        cause_ids=[]
        if item.get("error"):
            error=item['error']
            detailed=error.get("causes",[]) if isinstance(error,dict) else []
            cause_ids=[add_cause(e,f"/signals/{i}/error/causes/{j}") for j,e in enumerate(detailed)] or [add_cause(error,f"/signals/{i}/error")]
        for j,limitation in enumerate(item.get('limitations') or []):
            cause_ids.append(add_cause(limitation,f'/signals/{i}/limitations/{j}'))
        if layer=='l2' and detected is None and (not measurement or item['measurement_state']=='unavailable'):
            stage='ct' if identifier=='L2-C-06' else 'tls' if str(identifier).startswith('L2-C-') else 'http'
            cause_ids += [add_cause(e,f'/errors/{j}') for j,e in enumerate(errors) if e.get('stage')==stage or e.get('analyzer')==identifier or identifier in {'L2-H-05','L2-H-06'} and str(e.get('code','')).startswith('mime_')]
        query_limited=layer=='l0' and isinstance(item.get('value'),dict) and bool(item['value'].get('query_limitations'))
        if query_limited:
            cause_ids += query_cause_ids
        if measurement: state='observed' if item['measurement_state']=='observed' else 'unresolved'
        elif detected is True: state="observed"
        elif detected is False: state="not_observed_in_analyzed_scope"
        elif layer=="l0" and status=="해당없음": state="relationship_record_only"
        elif status=='not_applicable': state="not_applicable"
        elif layer=='l3' and identifier=='L3-H-03' and not cause_ids: state="relationship_record_only"
        else: state="unresolved"
        if layer=='l0' and status=='판정실패' and not query_limited:
            cause_ids.append(add_cause({"code":"url_pattern_analysis_unavailable","analyzer":identifier,"detail":item.get('value')},f"/signals/{i}"))
        if state=='unresolved' and not cause_ids:
            cause_ids.append(add_cause({'code':'analysis_unresolved_reason_not_recorded','analyzer':identifier,
                'message':'The analyzer result does not record why this check is unresolved; do not infer a collection failure or a site property.'},f'/signals/{i}'))
        signals.append({"id":identifier,"name":item.get("name"),"state":state,"detected":detected,
                        "analysis_provenance":{k:deepcopy(item[k]) for k in ('list_version',) if k in item},
                        'detector_predicate':(item.get('technical_scope') or {}).get('predicate',DETECTOR_PREDICATES.get(identifier)),
                        "scope":"URL string only" if layer=='l0' else "static source structure; execution unobserved" if item.get('scanner') in {'html','javascript'} else "collected metadata",
                        "meaning":item.get("meaning"),"legacy_status":status if layer=="l0" else None,"evidence":item.get("evidence",item.get("value")),
                        "cause_ids":list(dict.fromkeys(cause_ids)),"record_reference":{"key":f'record-{layer}.json',"pointer":f"/signals/{i}"}})
        if measurement:
            signal=signals[-1]
            signal.pop('detected')
            signal.pop('detector_predicate')
            signal['result_kind']='measurement'
            signal['measurement_state']=item['measurement_state']
            signal['assessment']={
                'predicate':{'statement':('Whole elapsed days from collected CT timestamp to measured_at' if identifier=='L2-C-06'
                                         else 'Whole elapsed days from certificate notBefore to measured_at'),
                    'result':'relationship_only' if state=='observed' else 'unresolved'},
                'applicability':{'state':'unrecorded','reason':None},
                'certainty':'technical_observation_only','url_verdict':'not_assessed',
                'limits': ('Elapsed days from the collected CT timestamp at the recorded measurement time; no freshness threshold or URL verdict.' if identifier=='L2-C-06'
                           else 'Elapsed days from certificate validity start at the recorded measurement time; not an issuance event, domain age or URL verdict.'),
            }
    if layer=='l1':
        for i,item in enumerate(result.get('인프라결과_목록',[])):
            status=item.get('status')
            cids=[]
            observation=deepcopy(item.get('observation') or l1_observation(item))
            for j,limitation in enumerate(observation.get('limitations',[])):
                cids.append(add_cause(limitation,f'/인프라결과_목록/{i}/observation/limitations/{j}'))
            not_applicable=status=='Not Queried' and item.get('reason')=='호스트가 IP 주소라 물을 이름이 없음'
            if status in {'Timeout','도구 오류','Not Queried'} and not not_applicable and not cids:
                code={'Timeout':'infrastructure_timeout','도구 오류':'infrastructure_tool_error','Not Queried':'infrastructure_not_attempted'}[status]
                cids=[add_cause({'code':code,'name':item.get('name'),'reason':item.get('reason'),'detail':item.get('detail')},f'/인프라결과_목록/{i}')]
            signals.append({'id':f'l1:{i}','name':item.get('name'),'state':'observed' if status=='응답 수신' else 'not_applicable' if not_applicable else 'unresolved',
                            'observation':observation,
                            'scope':'Infrastructure response at the recorded lookup target; platform facts do not establish tenant trust',
                            'evidence':item,'cause_ids':cids,'record_reference':{'key':f'record-{layer}.json','pointer':f'/signals/{i}'}})
    for signal in signals:
        if 'assessment' not in signal:
            signal['assessment']={
                'predicate':{'statement':signal.get('detector_predicate'),
                    'result':'matched' if signal.get('detected') is True else 'not_matched' if signal.get('detected') is False else 'unresolved' if signal['state']=='unresolved' else 'not_evaluated' if signal['state']=='not_applicable' else 'relationship_only'},
                'applicability':{'state':'not_applicable' if signal['state']=='not_applicable' else 'unrecorded','reason':None},
                'certainty':'technical_observation_only','url_verdict':'not_assessed',
                'limits':('Infrastructure lookup does not establish platform tenant trust or site ownership.' if layer=='l1' else
                    'Static source relationships and configured policy outputs do not establish runtime execution, intent or maliciousness.' if layer=='l3' else
                    'HTTP/TLS facts and configured technical criteria do not establish content safety, brand ownership or maliciousness.' if layer=='l2' else
                    'Legacy aggregate result; applicability and full candidate coverage were not recorded by the historical producer.')}
    scan=result.get('scan') or {}
    if layer=='l3':
        html=raw.get('html',{}).get('document',{})
        js=raw.get('javascript',{}).get('analysis',{})
        coverage={'html_parsed':html.get('parse_succeeded'), 'html_source_complete':html.get('source_complete'),
                  'javascript_source_complete':js.get('source_complete'), 'javascript_parsed_count':js.get('parsed_script_count'),
                  'javascript_semantic_complete':js.get('semantic_complete'), 'browser_execution_observed':False,
                  'javascript_decoding_complete':js.get('decoding_complete'),
                  'response':scan.get('response',{})}
        has_observation=bool(html.get('parse_succeeded'))
    elif layer=='l2':
        response=raw.get('http',{}).get('final_response',{})
        body=response.get('response_body',{})
        coverage={'http_response_received':response.get('status_code') is not None, 'http_status_code':response.get('status_code'),
                  'body_complete':body.get('body_complete'), 'body_truncated':body.get('truncated'),
                  'tls_certificate_observed':bool(raw.get('tls',{}).get('leaf_certificate')),
                  'tls_target':raw.get('tls',{}).get('hostname'), 'tls_scope':'separate connection', 'file_execution_observed':False}
        has_observation=coverage['http_response_received'] or coverage['tls_certificate_observed']
    else:
        coverage={'source_available':bool(raw or signals),'query_status':raw.get('query_status'),
            'analysis_execution':deepcopy(result.get('analysis_execution'))} if layer=='l0' else {
            'domain_units':result.get('도메인단위'), 'queries':len(signals),
            'query_lifecycle':deepcopy(result.get('query_lifecycle')),
            'query_lifecycle_state':'recorded_by_collector' if 'query_lifecycle' in result else 'individual_query_lifecycle_not_recorded'}
        has_observation=bool(raw or signals)
    shared = result.get('shared_page_observation')
    if layer in {'l2','l3'} and isinstance(shared,dict):
        coverage['shared_page_observation'] = deepcopy(shared)
        coverage['response_observation'] = 'shared-page:' + shared['snapshot_id']
    incomplete=bool(causes) or scan.get('status') in {'partial','failed'}
    for cause in causes:
        detail=cause['detail'];nested=detail.get('details') or {}
        if not isinstance(nested,dict):nested={}
        target={k:deepcopy(detail.get(k,nested.get(k))) for k in ('url','document_url','hostname','script_id','target')
                if detail.get(k,nested.get(k)) is not None}
        cause['occurrence']={'layer':layer,'stage':detail.get('stage',nested.get('stage')),
            'impact_scope':detail.get('impact_scope','unrecorded'),
            'observed_target':target or None,
            'reported_in':list(dict.fromkeys('analysis_result' if p.startswith(('/signals/','/evaluations/')) else
                'query_parser' if p.startswith('/query_errors/') else 'layer_result' for p in cause['source_hints'])),
            'identity_basis':'producer_occurrence_id' if detail.get('occurrence_id') else 'distinct_record_location',
            'affected_signal_ids':[s['id'] for s in signals if cause['id'] in s['cause_ids']],
            'reason_scope':'Reported failure or limitation; a shared message does not establish a shared underlying cause.'}
    record={'schema_version':SCHEMA_VERSION,'request_id':request_id,'attempt':str(attempt),'layer':layer,
            'analysis_status':'PARTIAL' if has_observation and incomplete else 'COMPLETED' if has_observation else 'NO_OBSERVATION',
            'coverage':coverage, 'target':result.get('target') or {'original_url':raw.get('raw_url') or result.get('url')},
            'signals':signals,'causes':causes,'analysis_facts':analysis_facts,
            'raw_ref':{'key':root,'sha256':raw_hash},
            'provenance':{'mode':mode,'source_reference':source_reference,'scanner_time':{k:scan.get(k) for k in ['started_at','finished_at']}}}
    record['record_contract_version']='layer-evidence-1'
    record['execution']=execution_for(layer,result,signals,causes,coverage)
    record['acquisition']=acquisition_for(layer,result,signals,causes,coverage,raw)
    record['analysis']=analysis_for(layer,result,signals,causes)
    record['analysis_status']={'completed':'COMPLETED','partial':'PARTIAL','unavailable':'NO_OBSERVATION',
        'not_performed':'NOT_PERFORMED','unrecorded':'UNRECORDED'}[record['analysis']['state']]
    return validate_record(record)
