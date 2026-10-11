"""Output shape and supplied-reference constraints, without choosing a verdict.

This contract does not establish semantic entailment.
The active server's own OpenAPI contract confirms json_schema support.
"""
from .context_view import unpack_rows

def evidence_ids(context):
    from .context_inventory import restore
    from .context_catalog import citation_catalog
    c=restore(context)
    if c.get('model_context_version'):
        from .model_context import validate_model_context
        return validate_model_context(c)
    expected=citation_catalog(c)
    aliases=[x for x in expected if x['id']!=x['original_id']]
    if 'evidence_catalog' in c:
        if c['evidence_catalog']!=aliases: raise ValueError('invalid_evidence_catalog')
    elif aliases:
        raise ValueError('ambiguous_evidence_id_without_catalog')
    return sorted(x['id'] for x in expected)

def response_format(context):
    ids=evidence_ids(context)
    if not ids:raise ValueError('context_has_no_citable_evidence')
    text={'type':'string','minLength':1}
    claim={'type':'object','additionalProperties':False,'required':['text','evidence_ids'],
           'properties':{'text':text,'evidence_ids':{'type':'array','minItems':1,'items':{'$ref':'#/$defs/evidence_id'}}}}
    schema={'type':'object','additionalProperties':False,
      '$defs':{'evidence_id':{'type':'string','enum':ids},'claim':claim},
      'required':['verdict','summary','observations','reasons','limitations','deep_analysis_needed'],
      'properties':{'verdict':{'type':'string','enum':['MALICIOUS','LIKELY_BENIGN','SUSPICIOUS','UNKNOWN']},'summary':text,
        'observations':{'type':'array','maxItems':3,'items':{'$ref':'#/$defs/claim'}},
        'reasons':{'type':'array','minItems':1,'maxItems':5,'items':{'$ref':'#/$defs/claim'}},
        'limitations':{'type':'array','items':text},'deep_analysis_needed':{'type':'boolean'}}}
    return {'type':'json_schema','json_schema':{'name':'grounded_url_judgment','strict':True,'schema':schema}}
