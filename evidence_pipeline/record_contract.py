"""Common layer-record semantics. Layer adapters normalize; the Builder only reads.

Native details remain under signal.evidence and coverage. Missing producer data
is explicitly unrecorded rather than filled with guessed collection outcomes.
"""
STATES={'completed','failed','not_performed','interrupted','unrecorded'}
ACQUISITION_STATES={'observed','partial','unavailable','not_attempted','unrecorded'}
ANALYSIS_STATES={'completed','partial','unavailable','not_performed','unrecorded'}
SIGNAL_STATES={'observed','not_observed_in_analyzed_scope','not_applicable',
                'relationship_record_only','unresolved'}
L0_OBSERVATION_CONTRACT='url-observations-3'
L0_OBSERVATION_FIELDS={'검사','관찰','판단에 쓸 점'}


def validate_l0_observation(value):
    """A positive URL observation is data, not a verdict or a negative result."""
    if not isinstance(value,dict) or set(value)!=L0_OBSERVATION_FIELDS:
        raise ValueError('invalid_l0_observation')
    for key in ('검사','판단에 쓸 점'):
        if not isinstance(value[key],str) or not value[key]:raise ValueError('invalid_l0_observation_text')
    if not isinstance(value['관찰'],dict) or not value['관찰']:raise ValueError('invalid_l0_observation_facts')
    return value


def validate_l0_observation_result(result):
    """Reject malformed declared v3 output instead of treating it as legacy."""
    required={'raw_evidence','observations','errors','analysis_execution','judgment_guidance','reference_versions'}
    if not required<=result.keys():raise ValueError('incomplete_l0_observation_result')
    if any(key in result for key in ('evaluations','signals','analysis_records')):
        raise ValueError('mixed_l0_producer_contracts')
    if not isinstance(result['raw_evidence'],dict):raise ValueError('invalid_l0_raw_evidence')
    observations=result['observations']
    if not isinstance(observations,list):raise ValueError('invalid_l0_observations')
    for value in observations:validate_l0_observation(value)
    execution=result['analysis_execution']
    if not isinstance(execution,dict) or execution.get('state') not in {'run','not_run'}:
        raise ValueError('invalid_l0_analysis_execution')
    if execution['state']=='run':
        if type(execution.get('check_count')) is not int or execution['check_count']<0:
            raise ValueError('invalid_l0_check_count')
        if type(execution.get('record_count')) is not int or execution['record_count']!=len(observations):
            raise ValueError('inconsistent_l0_record_count')
        if result['raw_evidence'].get('parse_status')!='SUCCESS':raise ValueError('inconsistent_l0_parse_execution')
    elif observations or not execution.get('reason'):
        raise ValueError('inconsistent_l0_unperformed_analysis')
    if not isinstance(result['errors'],list):raise ValueError('invalid_l0_errors')
    for error in result['errors']:
        if not isinstance(error,dict) or not {'code','stage','impact_scope','target','occurrence_id'}<=error.keys():
            raise ValueError('incomplete_l0_analysis_error')
        if error['impact_scope']!='analysis':raise ValueError('invalid_l0_error_impact')
        if any(not isinstance(error[key],str) or not error[key] for key in ('code','stage','occurrence_id')):
            raise ValueError('invalid_l0_analysis_error')
    for key in ('judgment_guidance','reference_versions'):
        if not isinstance(result[key],dict):raise ValueError('invalid_l0_'+key)
        if any(not isinstance(k,str) or not isinstance(v,str) or not v for k,v in result[key].items()):
            raise ValueError('invalid_l0_'+key)
    return result


def l1_observation(record):
    """Adapter for historical L1 rows lacking the current producer observation field."""
    status=record.get('status');detail=record.get('detail') or {}
    state=('not_attempted' if status=='Not Queried' else 'unavailable' if status in ('Timeout','도구 오류') else
           'partial' if isinstance(detail,dict) and (detail.get('dropped') or detail.get('failure_occurrences')) else 'observed' if status is not None else 'unrecorded')
    return {'state':state,'scope':'This lookup result, including any per-target failures in detail.',
            'partial_detail_field':'dropped' if isinstance(detail,dict) and detail.get('dropped') else None,
            'limitations':([*detail['failure_occurrences']] if isinstance(detail,dict) and isinstance(detail.get('failure_occurrences'),list) else [{'occurrence_id':f'l1:{record.get("name")}:dropped:{i}',
                'code':'infrastructure_partial_observation','stage':'infrastructure_lookup','impact_scope':'acquisition',
                'target':target,'reason':reason} for i,(target,reason) in enumerate(detail.get('dropped',{}).items())]
                if isinstance(detail,dict) and isinstance(detail.get('dropped'),dict) else [])}


def execution_for(layer,result,signals,causes,coverage):
    """Normalize only producer-stated completion and observed result availability."""
    supplied=result.get('analysis_execution') or {}
    scan=result.get('scan') or {}
    reason=None
    if (result.get('producer_execution') or {}).get('state') == 'not_performed' and \
            (result.get('preflight') or {}).get('state') == 'blocked_before_layer_network':
        state='not_performed';reason='l23_preflight_blocked'
    elif layer=='l1' and result.get('실패사유') in ('관측 무효(예산 초과)','관측 무효(대조 무응답)'):
        state='interrupted';reason=result['실패사유']
    elif any(c['code']=='layer_execution_failed' for c in causes):
        state='failed';reason='layer_execution_failed'
    elif not scan.get('status') and not supplied and not result.get('전체상태'):
        state='unrecorded';reason='producer_execution_status_not_recorded'
    else:
        state='completed'
    return {'state':state,'reason':reason,
        'result_counts':{name:sum(s['state']==name for s in signals) for name in sorted(SIGNAL_STATES)},
        'unperformed_or_interrupted_parts':result.get('query_lifecycle') if layer=='l1' and 'query_lifecycle' in result else None,
        'parts_scope':'producer_recorded_query_lifecycle' if layer=='l1' and 'query_lifecycle' in result else 'individual_execution_parts_not_recorded',
        'completion_scope':'completed means the producer reported finishing its run, even if collection or analysis failed. Acquisition and analysis outcomes are separate. No producer completion field means unrecorded.'}


def acquisition_for(layer,result,signals,causes,coverage,raw):
    shared_observation=result.get('shared_page_observation') or {}
    redirect_observed=bool(shared_observation.get('redirect_chain') or
                           (raw.get('http') or {}).get('redirect_chain'))
    redirect_without_final=redirect_observed and shared_observation.get('response_received') is False
    if (result.get('producer_execution') or {}).get('reason') == 'shared_page_analysis_failed':
        # The final page or an intermediate redirect may survive analyzer failure.
        state = 'partial' if shared_observation.get('response_received') or redirect_observed else 'unavailable'
    elif (result.get('producer_execution') or {}).get('state') == 'not_performed' and \
            (result.get('preflight') or {}).get('state') == 'blocked_before_layer_network':
        state='not_attempted'
    elif layer=='l0':
        state='observed' if 'raw_url' in raw else 'unrecorded'
    elif layer=='l1':
        states=[(s.get('observation') or {}).get('state','unrecorded') for s in signals]
        if any(x in ('observed','partial') for x in states):
            state='partial' if any(x!='observed' for x in states) else 'observed'
        elif states and all(x=='not_attempted' for x in states):state='not_attempted'
        elif any(x=='unavailable' for x in states) or causes:state='unavailable'
        else:state='unrecorded'
        if result.get('실패사유') and state=='observed':state='partial'
    elif layer=='l2':
        final_response_observed=coverage.get('http_response_received')
        observed=final_response_observed or coverage.get('tls_certificate_observed') or redirect_observed
        collection_limits=[c for c in causes if c['occurrence'].get('impact_scope')=='acquisition']
        partial=collection_limits or coverage.get('body_complete') is False or (redirect_observed and not final_response_observed)
        state=('partial' if partial else 'observed') if observed else 'unavailable' if collection_limits else 'unrecorded'
    else:
        html=raw.get('html') or {};js=raw.get('javascript') or {}
        observed=html.get('source') is not None or html.get('document',{}).get('parse_succeeded') or any(s.get('source') is not None for s in js.get('scripts',[])) or redirect_without_final
        partial=coverage.get('html_source_complete') is False or coverage.get('javascript_source_complete') is False or redirect_without_final
        state=('partial' if partial else 'observed') if observed else 'unavailable' if causes else 'unrecorded'
    return {'state':state,'scope':'Only supplied inputs or lookup responses; detailed coverage and native evidence remain authoritative.',
            'limitation_ids':[c['id'] for c in causes if c['occurrence'].get('impact_scope')=='acquisition']}


def analysis_for(layer,result,signals,causes):
    if (result.get('producer_execution') or {}).get('reason') == 'shared_page_analysis_failed':state='unavailable'
    elif (result.get('producer_execution') or {}).get('state') == 'not_performed' and \
            (result.get('preflight') or {}).get('state') == 'blocked_before_layer_network':state='not_performed'
    elif layer=='l0' and (result.get('analysis_execution') or {}).get('state')=='not_run':state='not_performed'
    elif not signals:state='unrecorded'
    else:
        usable=any(s['state'] in {'observed','not_observed_in_analyzed_scope','relationship_record_only'} for s in signals)
        unresolved=any(s['state']=='unresolved' for s in signals) or any(c['occurrence'].get('impact_scope')=='analysis' for c in causes)
        state='partial' if usable and unresolved else 'unavailable' if unresolved else 'completed'
    return {'state':state,'scope':'Availability of supplied technical findings; separate from task completion and URL verdict.'}


def _object(value, required, error):
    if not isinstance(value,dict) or not set(required)<=value.keys():raise ValueError(error)
    return value


def _text(value,error,nullable=False):
    if value is None and nullable:return
    if not isinstance(value,str) or not value:raise ValueError(error)


def _refs(value,allowed,error):
    if not isinstance(value,list) or any(not isinstance(x,str) or not x for x in value):raise ValueError(error)
    if len(value)!=len(set(value)) or not set(value)<=allowed:raise ValueError(error)
    return set(value)


def validate_l0_observation_record(record):
    """L0 compact storage is separate from the older per-signal assessment model."""
    required={'record_contract_version','layer','request_id','attempt','analysis_status','execution',
              'acquisition','analysis','target','coverage','signals','errors','raw_ref'}
    _object(record,required,'incomplete_l0_record')
    if record['layer']!='l0':raise ValueError('invalid_l0_record_layer')
    _text(record['request_id'],'invalid_l0_request_id')
    _text(record['attempt'],'invalid_l0_attempt')
    if not isinstance(record['signals'],list):raise ValueError('invalid_l0_observations')
    for item in record['signals']:validate_l0_observation(item)
    coverage=_object(record['coverage'],{'producer_contract','analysis_execution','judgment_guidance',
        'reference_versions','parse_status'},'incomplete_l0_coverage')
    if coverage['producer_contract']!=L0_OBSERVATION_CONTRACT:raise ValueError('invalid_l0_record_producer_contract')
    validate_l0_observation_result({'raw_evidence':{'parse_status':coverage['parse_status']},
        'observations':record['signals'],'errors':record['errors'],
        'analysis_execution':coverage['analysis_execution'],
        'judgment_guidance':coverage['judgment_guidance'],'reference_versions':coverage['reference_versions']})
    execution=_object(record['execution'],{'state','reason','result_counts'},'invalid_l0_record_execution')
    if not isinstance(execution['state'],str) or execution['state'] not in STATES:raise ValueError('invalid_l0_record_execution_state')
    _text(execution['reason'],'invalid_l0_record_execution_reason',nullable=True)
    counts=_object(execution['result_counts'],SIGNAL_STATES,'incomplete_record_result_counts')
    for state in SIGNAL_STATES:
        expected=len(record['signals']) if state=='observed' else 0
        if type(counts[state]) is not int or counts[state]!=expected:raise ValueError('inconsistent_record_result_counts')
    acquisition=_object(record['acquisition'],{'state'},'invalid_l0_record_acquisition')
    if not isinstance(acquisition['state'],str) or acquisition['state'] not in {'observed','unrecorded'}:raise ValueError('invalid_l0_record_acquisition_state')
    analysis=_object(record['analysis'],{'state'},'invalid_l0_record_analysis')
    expected=('not_performed' if coverage['analysis_execution']['state']=='not_run' else
              'partial' if record['errors'] else 'completed')
    if analysis['state']!=expected:raise ValueError('inconsistent_l0_record_analysis')
    if record['analysis_status']!={'not_performed':'NOT_PERFORMED','partial':'PARTIAL','completed':'COMPLETED'}[expected]:
        raise ValueError('inconsistent_l0_record_analysis_status')
    if not isinstance(record['target'],dict):raise ValueError('invalid_l0_record_target')
    raw_ref=_object(record['raw_ref'],{'key','sha256'},'invalid_l0_raw_reference')
    if raw_ref['key']!='raw-l0.json' or not isinstance(raw_ref['sha256'],str) or len(raw_ref['sha256'])!=64:
        raise ValueError('invalid_l0_raw_reference')
    return record


def validate_record(record):
    if isinstance(record,dict) and record.get('record_contract_version')=='l0-observations-1':
        return validate_l0_observation_record(record)
    _object(record,{'record_contract_version','layer','execution','acquisition','analysis','target','coverage','signals','causes'},'incomplete_record_contract')
    if record['record_contract_version']!='layer-evidence-1':raise ValueError('unsupported_record_contract_version')
    if record['layer'] not in {'l0','l1','l2','l3'}:raise ValueError('invalid_record_layer')
    execution=_object(record['execution'],{'state','reason','result_counts','unperformed_or_interrupted_parts','parts_scope','completion_scope'},'invalid_record_execution')
    acquisition=_object(record['acquisition'],{'state','scope','limitation_ids'},'invalid_record_acquisition')
    analysis=_object(record['analysis'],{'state','scope'},'invalid_record_analysis')
    for value,states,name in [(execution,STATES,'execution'),(acquisition,ACQUISITION_STATES,'acquisition'),(analysis,ANALYSIS_STATES,'analysis')]:
        if not isinstance(value['state'],str) or value['state'] not in states:raise ValueError('invalid_record_'+name+'_state')
    for value in (acquisition,analysis):_text(value['scope'],'invalid_record_scope')
    _text(execution['reason'],'invalid_record_execution_reason',nullable=True)
    _text(execution['parts_scope'],'invalid_record_parts_scope')
    _text(execution['completion_scope'],'invalid_record_completion_scope')
    parts=execution['unperformed_or_interrupted_parts']
    if parts is not None:
        if not isinstance(parts,list):raise ValueError('invalid_record_execution_parts')
        for part in parts:
            _object(part,{'name','state','run_stop_reason','raw_response_recorded','result_status'},'incomplete_record_execution_part')
            _text(part['name'],'invalid_record_execution_part_name')
            if not isinstance(part['state'],str) or part['state'] not in {'result_recorded','not_started','cancelled_before_start','completed_result_not_consumed','running_at_stop'}:raise ValueError('invalid_record_execution_part_state')
            if type(part['raw_response_recorded']) is not bool:raise ValueError('invalid_record_execution_part_response')
            _text(part['run_stop_reason'],'invalid_record_part_reason',nullable=True)
            _text(part['result_status'],'invalid_record_part_result_status',nullable=True)
    if not isinstance(record['target'],dict) or not isinstance(record['coverage'],dict):raise ValueError('invalid_record_scope')
    signals=record['signals'];causes=record['causes']
    if not isinstance(signals,list) or not isinstance(causes,list):raise ValueError('invalid_record_collections')
    signal_ids=[];cause_ids=[]
    for rows,ids in ((signals,signal_ids),(causes,cause_ids)):
        for row in rows:
            _object(row,{'id'},'invalid_record_item');_text(row['id'],'invalid_record_identity');ids.append(row['id'])
        if len(ids)!=len(set(ids)):raise ValueError('duplicate_record_identity')
    allowed_causes=set(cause_ids);allowed_signals=set(signal_ids)
    for signal in signals:
        _object(signal,{'state','assessment','scope','evidence','cause_ids'},'incomplete_record_signal')
        if not isinstance(signal['state'],str) or signal['state'] not in SIGNAL_STATES:raise ValueError('invalid_record_signal_state')
        if not isinstance(signal['scope'],(str,dict)) or not signal['scope']:raise ValueError('invalid_record_signal_scope')
        assessment=_object(signal['assessment'],{'predicate','applicability','certainty','url_verdict','limits'},'incomplete_record_assessment')
        if assessment['url_verdict']!='not_assessed' or assessment['certainty']!='technical_observation_only':raise ValueError('invalid_bounded_assessment')
        _text(assessment['limits'],'invalid_assessment_limits')
        predicate=_object(assessment['predicate'],{'statement','result'},'incomplete_record_predicate')
        _text(predicate['statement'],'invalid_predicate_statement',nullable=True)
        if not isinstance(predicate['result'],str) or predicate['result'] not in {'matched','not_matched','not_evaluated','unresolved','relationship_only','unrecorded'}:raise ValueError('invalid_record_predicate_result')
        applicability=_object(assessment['applicability'],{'state','reason'},'incomplete_record_applicability')
        if not isinstance(applicability['state'],str) or applicability['state'] not in {'applicable','not_applicable','unrecorded'}:raise ValueError('invalid_record_applicability')
        _text(applicability['reason'],'invalid_applicability_reason',nullable=True)
        state=signal['state'];result=predicate['result'];applicable=applicability['state']
        if (state=='not_applicable')!=(applicable=='not_applicable') or (state=='not_applicable')!=(result=='not_evaluated'):
            raise ValueError('inconsistent_record_applicability')
        permitted={'observed':{'matched','relationship_only'},'not_observed_in_analyzed_scope':{'not_matched'},
            'not_applicable':{'not_evaluated'},'relationship_record_only':{'matched','not_matched','relationship_only','unrecorded'},'unresolved':{'unresolved'}}
        if result not in permitted[state]:raise ValueError('inconsistent_record_predicate')
        if signal.get('result_kind')=='measurement':
            measurement_field = 'first_seen' if signal['id']=='L2-C-06' else 'not_before'
            measurement_statement = ('Whole elapsed days from collected CT timestamp to measured_at' if signal['id']=='L2-C-06'
                                     else 'Whole elapsed days from certificate notBefore to measured_at')
            if (record['layer']!='l2' or signal['id'] not in {'L2-C-01','L2-C-06'} or
                    'detected' in signal or signal.get('detector_predicate') is not None or
                    predicate['statement']!=measurement_statement):
                raise ValueError('invalid_measurement_record')
            measured=signal.get('measurement_state')
            if (measured not in {'observed','unavailable'} or
                    (state,result)!=({'observed':('observed','relationship_only'),
                                     'unavailable':('unresolved','unresolved')}[measured])):
                raise ValueError('inconsistent_measurement_record')
            evidence=signal['evidence']
            if not isinstance(evidence,dict) or 'fresh' in evidence:
                raise ValueError('invalid_measurement_evidence')
            if measured=='observed':
                if (type(evidence.get('age_days')) is not int or
                        any(not isinstance(evidence.get(k),str) or not evidence[k]
                            for k in (measurement_field,'measured_at'))):
                    raise ValueError('incomplete_certificate_age_measurement')
                if signal['id']=='L2-C-06' and ('source' not in evidence or
                        evidence['source'] is not None and (not isinstance(evidence['source'],str) or not evidence['source'])):
                    raise ValueError('invalid_ct_measurement_source')
            elif evidence.get('age_days') is not None:
                raise ValueError('inconsistent_measurement_record')
        refs=_refs(signal['cause_ids'],allowed_causes,'dangling_record_cause')
        if state=='unresolved' and not refs:raise ValueError('unresolved_record_without_cause')
    counts=_object(execution['result_counts'],SIGNAL_STATES,'incomplete_record_result_counts')
    for state in SIGNAL_STATES:
        if type(counts[state]) is not int or counts[state]!=sum(s['state']==state for s in signals):raise ValueError('inconsistent_record_result_counts')
    for cause in causes:
        _object(cause,{'code','kind','detail','occurrence'},'incomplete_record_cause')
        _text(cause['code'],'invalid_record_cause_code');_text(cause['kind'],'invalid_record_cause_kind')
        if not isinstance(cause['detail'],dict):raise ValueError('invalid_record_cause_detail')
        occurrence=_object(cause['occurrence'],{'layer','stage','impact_scope','observed_target','reported_in','identity_basis','affected_signal_ids','reason_scope'},'incomplete_record_occurrence_contract')
        if occurrence['layer']!=record['layer']:raise ValueError('invalid_record_occurrence_layer')
        _text(occurrence['stage'],'invalid_record_occurrence_stage',nullable=True)
        _text(occurrence['reason_scope'],'invalid_record_occurrence_scope')
        if not isinstance(occurrence['impact_scope'],str) or occurrence['impact_scope'] not in {'execution','acquisition','analysis','unrecorded'}:raise ValueError('invalid_record_occurrence_impact')
        if occurrence['observed_target'] is not None and not isinstance(occurrence['observed_target'],dict):raise ValueError('invalid_record_occurrence_target')
        _refs(occurrence['reported_in'],{'analysis_result','query_parser','layer_result'},'invalid_record_occurrence_locations')
        if not isinstance(occurrence['identity_basis'],str) or occurrence['identity_basis'] not in {'producer_occurrence_id','distinct_record_location'}:raise ValueError('invalid_record_occurrence_identity')
        refs=_refs(occurrence['affected_signal_ids'],allowed_signals,'dangling_record_affected_signal')
        actual={s['id'] for s in signals if cause['id'] in s['cause_ids']}
        if refs!=actual:raise ValueError('inconsistent_record_affected_signals')
    acquisition_refs=_refs(acquisition['limitation_ids'],allowed_causes,'dangling_record_acquisition_cause')
    if acquisition_refs!={c['id'] for c in causes if c['occurrence']['impact_scope']=='acquisition'}:raise ValueError('inconsistent_record_acquisition_causes')
    return record
