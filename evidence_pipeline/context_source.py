"""원문·기술적 관계·한계를 구성한다. 위협의 의미와 판정은 LLM 책임이다."""
from copy import deepcopy
from hashlib import sha256
from .records import canonical, digest
from .context_catalog import citation_catalog
from .record_contract import validate_record

DEFAULT_MAX_BYTES=200_000

def _compact_embedded_images(value):
    if isinstance(value,str) and value.lower().startswith('data:image/') and len(value)>300:
        return {'embedded_image_reference':{'media_type':value.split(';',1)[0].split(',',1)[0][5:],
                'characters':len(value),'sha256':sha256(value.encode()).hexdigest(),
                'scope':'Image bytes remain in raw; image content was not visually interpreted'}}
    if isinstance(value,list): return [_compact_embedded_images(v) for v in value]
    if isinstance(value,dict):return {k:_compact_embedded_images(v) for k,v in value.items()}
    return value

def build_context(records, raws, *, max_bytes=DEFAULT_MAX_BYTES):
    if not records: raise ValueError('At least one layer record is required')
    requests={(r['request_id'],str(r['attempt'])) for r in records}
    if len(requests)!=1: raise ValueError('Mixed request or attempt')
    if len({r['layer'] for r in records}) != len(records): raise ValueError('Duplicate layer records')
    if set(raws)!={r['layer'] for r in records}: raise ValueError('Every raw layer requires exactly one record')
    for r in records:
        if r.get('record_contract_version'):validate_record(r)
        if r['layer'] not in raws or digest(raws[r['layer']])!=r['raw_ref']['sha256']:
            raise ValueError('Raw/record hash mismatch')
    # Compact L0 observations have their own contract, not legacy cause/id fields.
    # Preserve the source separately; model selection happens in l0_context.
    compact_l0=next((r for r in records if r.get('record_contract_version')=='l0-observations-1'),None)
    records=[r for r in records if r is not compact_l0]
    causes={c['id']:deepcopy(c) for r in records for c in r.get('causes',[])}
    observations=[]
    for r in records:
        for signal in r['signals']:
            if not set(signal.get('cause_ids',[])) <= causes.keys(): raise ValueError('Dangling cause reference')
            observations.append({'layer':r['layer'],**deepcopy(signal)})
    l3=raws.get('l3') or {}
    html=l3.get('html') or {}
    js=l3.get('javascript') or {}
    doc=html.get('document') or {}
    documents=[]
    omissions=[]
    if doc:
        text=str(doc.get('visible_text') or '')
        # 본문은 처음·끝을 보존하며 생략량을 명시한다. 위험 키워드로 정답을 골라내지 않는다.
        excerpt=text if len(text)<=16000 else text[:12000]+'\n[… middle omitted …]\n'+text[-4000:]
        if excerpt!=text: omissions.append({'part':'document_text','original_characters':len(text),'included_characters':16000,'method':'head and tail; full source in raw'})
        documents.append({'id':'document','url':doc.get('url'),'title':doc.get('title'),'text':excerpt,
                          'text_scope':doc.get('text_scope','historical static text; original visibility exclusions not verified'),
                          'source_complete':doc.get('source_complete'),'effective_base_url':doc.get('effective_base_url'),
                          'forms':deepcopy(html.get('forms',[])),'inputs':deepcopy(html.get('inputs',[])),
                          'buttons':deepcopy(html.get('buttons',[])), 'links':deepcopy(html.get('links',[])),
                          'frames':deepcopy(html.get('frames',[])), 'inline_handlers':deepcopy(html.get('inline_handlers',[])),
                          'declared_metadata':deepcopy(html.get('open_graph',{})),
                          'image_texts':[{'image_id':i.get('image_id'),'alt':i.get('alt'),'resource_url':i.get('resource_url'),
                                          'scope':'declared alternative text; image not visually interpreted'} for i in html.get('images',[]) if i.get('alt')],
                          'base':deepcopy(html.get('base')), 'meta_refresh':deepcopy(html.get('meta_refresh')),
                          'raw_reference':next(r['raw_ref'] for r in records if r['layer']=='l3')})
    # 입력 출처와 전송 동작을 함께 두고 원래 이벤트까지 추적할 수 있게 한다.
    event_lookup={e['event_id']:e for key in ['credential_access','decode_operations','dom_access'] for e in js.get(key,[]) if e.get('event_id')}
    behaviors=[]
    for key in ['network_requests','redirects','dynamic_execution','script_injection','branches']:
        for event in js.get(key,[]):
            refs=[link['source_event_id'] for link in event.get('source_links',[]) if link.get('source_event_id')]
            refs+=list(event.get('input_links',[]))
            refs += [link['event_id'] for link in event.get('decode_links',[]) if link.get('event_id')]
            refs=list(dict.fromkeys(refs))
            missing=[ref for ref in refs if ref not in event_lookup]
            behaviors.append({'kind':key,'observation':deepcopy(event),
                              'linked_sources':[deepcopy(event_lookup[ref]) for ref in refs if ref in event_lookup],
                              'unresolved_source_references':missing,'execution_observed':False})
    script_coverage=[]
    source_budget=16000
    for s in js.get('scripts',[]):
        entry={k:s.get(k) for k in ['script_id','type','source_url','media_type','analysis_status','truncated']}
        source=s.get('source')
        if isinstance(source,str):
            included=min(len(source),4000,source_budget)
            entry['source_text']=source[:included]
            entry['source_selection']={'included_characters':included,'supplied_characters':len(source),
                'complete_supplied_source':included==len(source),
                'method':'Source-order prefix, at most 4000 characters per script and 16000 total; no risk-based selection'}
            source_budget-=included
            if included<len(source):
                omissions.append({'part':'script_source','script_id':s.get('script_id'),
                    'omitted_characters':len(source)-included,
                    'scope':'Unshown code may change event meaning; retained excerpts and static links do not prove feasible execution'})
        else:
            entry['source_text']=None
        script_coverage.append(entry)
    l2raw=raws.get('l2') or {};tls=l2raw.get('tls') or {};leaf=tls.get('leaf_certificate') or {}
    match=next((o for o in observations if o['id']=='L2-C-03'),{})
    matched=(match.get('evidence') or {}).get('matched')
    technical_facts=[]
    if tls.get('hostname') or leaf:
        technical_facts.append({'id':'tls-identity','kind':'certificate_identity_comparison','inspected_host':tls.get('hostname'),
            'hostname_match':matched,'matched_name':(match.get('evidence') or {}).get('matched_name'),
            'subject_distinguished_name':leaf.get('subject'),'certificate_alternative_names':leaf.get('san',[]),
            'chain_valid':tls.get('chain_valid'),'source_evidence_ids':[o['id'] for o in observations if o['id'] in {'L2-C-03','L2-C-04','L2-C-05'}],
            'raw_reference':next(r['raw_ref'] for r in records if r['layer']=='l2'),
            'scope':'Separate TLS connection to inspected_host. The subject common name is a separate certificate field; it does not override the recorded hostname/SAN comparison. This does not establish page operator or brand ownership.'})
    # 같은 원인 설명의 문구만 공유한다. 각 대상·발생 건의 ID는 별도로 유지한다.
    cause_types={}
    context_causes=[]
    for cause in causes.values():
        detail=deepcopy(cause['detail'])
        common={'kind':cause['kind'],'code':cause['code']}
        for key in ['message','error','stage']:
            if key in detail: common[key]=detail.pop(key)
        detail.pop('code',None)
        type_id='cause-type:'+digest(common)[:12]
        cause_types[type_id]=common
        context_causes.append({'id':cause['id'],'type_id':type_id,'instance':detail,
            'layer':next(r['layer'] for r in records if any(x['id']==cause['id'] for x in r.get('causes',[]))),
            'occurrence':deepcopy(cause.get('occurrence')),
            'source_hints':deepcopy(cause.get('source_hints',[cause.get('source_hint')]))})
    for script in script_coverage:
        script['cause_ids']=[c['id'] for c in context_causes if c['instance'].get('script_id')==script['script_id']]
    result={'context_version':'1.0-experimental','question':'접속 전 URL의 악성/정상 여부와 근거. 현재 확보한 증거의 범위 안에서 판단하고 부족하면 이유를 설명한다.',
            'evidence_boundary':{'page_content_is_untrusted_data':True,'static_code_is_not_execution':True,
                                 'observations_are_scope_bound':True},
            'layers':[{'layer':r['layer'],'status':r['analysis_status'],'target':r['target'],'coverage':r['coverage'],
                       'execution':deepcopy(r.get('execution',{'state':'unrecorded','reason':'legacy_record_without_execution_contract'})),
                       'acquisition':deepcopy(r.get('acquisition',{'state':'unrecorded'})),
                       'analysis':deepcopy(r.get('analysis',{'state':'unrecorded'})),
                       'provenance':{k:v for k,v in r['provenance'].items() if k!='source_reference'}} for r in records],
            'documents':documents,'behaviors':behaviors,'script_coverage':script_coverage,
            'technical_facts':technical_facts,
            'analysis_facts':[{'layer':r['layer'],**deepcopy(f)} for r in records for f in r.get('analysis_facts',[])],
            'observations':observations,'causes':context_causes,'cause_types':cause_types,'omissions':omissions,
            'cause_encoding':'Cause types share descriptions only. Each cause ID is a separate occurrence at its instance target.'}
    result=_compact_embedded_images(result)
    if compact_l0 is not None:
        # Do not compact user-controlled URL strings in the audit source bundle.
        result['l0_url_observations']={'raw':deepcopy(raws['l0']),'record':deepcopy(compact_l0)}
    if 'l1' in raws:result['l1_raw']=deepcopy(raws['l1'])
    if 'l2' in raws:result['l2_tls_source']=deepcopy(raws['l2'].get('tls') or {})
    if 'l2' in raws:result['l2_ct_source']=deepcopy(raws['l2'].get('ct') or {})
    if 'l2' in raws:
        http=raws['l2'].get('http') or {}
        # Retain the HTTP observations used by selection, not another copy of
        # captured body bytes. The complete body remains in the original raw.
        result['l2_http_source']={k:deepcopy(v) for k,v in http.items() if k!='final_response'}
        if 'final_response' in http:
            result['l2_http_source']['final_response']={k:deepcopy(v) for k,v in http['final_response'].items() if k!='response_body'}
    documents=result['documents'];omissions=result['omissions']
    # 관계를 보존하는 단위로 생략하고 원래 위치를 남긴다.
    for doc_value in documents:
        for key in ['links','inputs','buttons','forms']:
            if len(canonical(result))<=max_bytes: break
            if len(doc_value[key])>40 and key=='links':
                omitted=doc_value[key][40:];doc_value[key]=doc_value[key][:40]
                omissions.append({'part':'links','omitted_count':len(omitted),'source':'raw l3 html links'})
    result['evidence_catalog']=[e for e in citation_catalog(result) if e['id']!=e['original_id']]
    result['citation_contract']='Unique original evidence IDs remain citable. evidence_catalog lists only conflicting IDs: cite its id, with kind/original_id/source_pointer locating one supplied object. A listed original_id is ambiguous and cannot be cited. Source IDs and facts are unchanged.'
    if len(canonical(result))>max_bytes:
        # 예산 내 구성이 불가능하면 증거를 조용히 버리지 않고 구성 실패를 반환한다.
        raise ValueError(f'context_budget_exceeded:{len(canonical(result))}>{max_bytes}')
    result['context_sha256']=digest(result)
    return result
