"""Put the service question and factual relationships before detector inventory.

The code does not classify page purpose, warnings, harm, or a URL verdict. It
joins recorded IDs only and explicitly states when a payload link is absent.
All source fields are retained, without aliases or risk-based selection.
"""
from copy import deepcopy
import json

ORDER=['question','documents','analysis_facts','behaviors','layers','causes','cause_types','cause_encoding',
       'technical_facts','script_coverage','observations','evidence_boundary','omissions','context_version','context_sha256']


def build_internal_context(records,raws,**kwargs):
    """Inspectable internal legacy view; not the public model-input projection."""
    from .context_source import build_context
    return present(build_context(records,raws,**kwargs))

def present(source):
    c=deepcopy(source)
    if any(k in c for k in ('judgment_subject','recorded_relationships','request_observation_focus')):
        raise ValueError('reserved relation view field')
    original_urls=[]
    for layer in c.get('layers',[]):
        value=(layer.get('target') or {}).get('original_url')
        if value and value not in original_urls:original_urls.append(value)
    subject={
        'requested_urls_recorded':original_urls,
        'request_identity':'consistent_recorded_url' if len(original_urls)==1 else 'missing_or_multiple_recorded_urls',
        'documents_recorded':[{'document_id':d['id'],'url':d.get('url'),'title':d.get('title')} for d in c.get('documents',[])],
        'relationship_boundary':'Matching URLs or IDs establish only the recorded association, not shared ownership, contemporaneous execution, or truth of page claims.'}
    forms=[]
    for d in c.get('documents',[]):
        all_forms=d.get('forms',[])
        for f in all_forms:
            fid=f.get('form_id')
            if not fid:continue
            unique=sum(item.get('form_id')==fid for item in all_forms)==1
            row={'document_id':d['id'],'form_id':fid,
                 'association':'recorded_form_id' if unique else 'ambiguous_duplicate_form_id',
                 'declared_submission':{'target_url':f.get('action_url'),'method':f.get('method')},
                 'execution_observed':False}
            if unique:
                row['recorded_fields']=[]
                for i in d.get('inputs',[]):
                    if i.get('form_id')!=fid:continue
                    item={k:i[k] for k in ['field_id','type','name','disabled','checked'] if k in i}
                    # Only join established L3 findings. Missing analysis stays missing.
                    matches=[{'analysis_id':fact['id'],'source_pointer':field.get('source_pointer')}
                        for fact in c.get('analysis_facts',[])
                        if fact.get('kind')=='native_form_submission' and fact.get('layer')=='l3'
                        for field in fact.get('fields',[])
                        if field.get('field_id')==i.get('field_id') and field.get('form_id')==fid]
                    item['native_analysis_recorded']=matches
                    row['recorded_fields'].append(item)
                row['recorded_submit_controls']=[{k:b.get(k) for k in ['button_id','type','text','disabled','effective_action_url','effective_method']} for b in d.get('buttons',[]) if b.get('form_id')==fid and b.get('type') in ['submit','image']]
            forms.append(row)
    networks=[]
    for b in c.get('behaviors',[]):
        o=b.get('observation') or {}
        if b.get('kind')!='network_requests':continue
        links=o.get('source_links') or []
        sources=b.get('linked_sources') or []
        unresolved=b.get('unresolved_source_references') or []
        networks.append({'event_id':o.get('event_id'),'script_id':o.get('script_id'),
            'destination_url_recorded':o.get('destination_url'),
            'source_excerpt_recorded':o.get('source_excerpt'),
            'source_event_ids_recorded':[x.get('event_id') for x in sources],
            'source_field_ids_recorded':sorted({x['field_id'] for x in links+sources if x.get('field_id')}),
            'unresolved_source_references':unresolved,
            'payload_relationship':('unresolved_source_references' if unresolved else
                                    'linked_source_evidence_recorded' if sources else
                                    'source_references_only' if links else 'no_payload_source_link_recorded'),
            'execution_observed':b.get('execution_observed',False)})
    relationships={'form_paths':forms,'network_paths':networks,
        'interpretation_boundary':'These are joins of supplied records, not extra observations. A network destination with no payload source link recorded does not establish which input, if any, is sent. Read any provided source excerpt. No execution, event timing or ownership is inferred.'}
    result={'judgment_subject':subject}
    for key in ORDER:
        if key in c:result[key]=c.pop(key)
        if key=='documents':result['recorded_relationships']=relationships
    result.update(c)
    # A factual scope index remains adjacent to the requested judgment even for
    # a long document/inventory. No status-to-verdict or keyword rule is used.
    result['request_observation_focus']={
        'requested_urls_recorded':original_urls,
        'retrievals':[{'layer':l.get('layer'),'target':deepcopy(l.get('target')),
            'response_observations':{k:v for k,v in (l.get('coverage') or {}).items()
                if k in ('http_response_received','http_status_code','body_complete','body_truncated','response')},
            'recorded_time':deepcopy((l.get('provenance') or {}).get('scanner_time'))}
            for l in source.get('layers',[]) if l.get('layer') in ('l2','l3')],
        'documents_recorded':deepcopy(subject['documents_recorded'])}
    return result

def restore(view):
    c=deepcopy(view);c.pop('judgment_subject',None);c.pop('recorded_relationships',None);c.pop('request_observation_focus',None);return c

def render(view):
    # The deliberate context order is preserved; source field values stay exact.
    return json.dumps(view,ensure_ascii=False,separators=(',',':')).encode()
