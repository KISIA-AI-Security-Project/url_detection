"""Assign unambiguous citation names without changing original evidence IDs or facts."""
from collections import Counter


def citation_catalog(context):
    from .context_view import unpack_rows
    definitions=[]
    events={}
    def add(value, key, kind, pointer):
        identifier=value.get(key)
        if not isinstance(identifier,str) or not identifier: return
        if kind=='event':
            identity=(value.get('script_id'),identifier)
            if identity in events:
                if events[identity]!=value: raise ValueError('conflicting_event_definition')
                return
            events[identity]=value
        definitions.append({'kind':kind,'original_id':identifier,'source_pointer':pointer,'id_field':key})
    for name in ('causes','documents','technical_facts','analysis_facts','document_interactions'):
        for i,value in enumerate(context.get(name,[])):
            add(value,'id',name,f'/{name}/{i}')
    observations=context.get('observations',context.get('observed_findings',[])+sum(context.get('analysis_outcomes',{}).values(),[]))
    for i,value in enumerate(observations): add(value,'id','observation',f'/observations/{i}')
    for i,value in enumerate(context.get('script_coverage',[])): add(value,'script_id','script',f'/script_coverage/{i}')
    for i,behavior in enumerate(context.get('behaviors',[])):
        add(behavior.get('observation',{}),'event_id','event',f'/behaviors/{i}/observation')
        for j,value in enumerate(behavior.get('linked_sources',[])):
            add(value,'event_id','event',f'/behaviors/{i}/linked_sources/{j}')
    fields={'forms':'form_id','inputs':'field_id','buttons':'button_id','links':'link_id','frames':'frame_id','image_texts':'image_id'}
    for i,document in enumerate(context.get('documents',[])):
        for name,key in fields.items():
            for j,value in enumerate(unpack_rows(document.get(name,[]))):
                add(value,key,name,f'/documents/{i}/{name}/{j}')
    counts=Counter(value['original_id'] for value in definitions)
    reserved=set(counts)
    counter=0
    for value in definitions:
        citation=value['original_id']
        if counts[citation]>1:
            while True:
                counter+=1
                candidate=f'citation:{counter}'
                if candidate not in reserved:
                    citation=candidate
                    reserved.add(citation)
                    break
        value['id']=citation
    return definitions
