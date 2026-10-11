"""One scoped, per-field credential classification shared by HTML and JS.

A policy exception belongs to that field. It does not erase preceding results,
skip later fields, or stop unrelated parsing. A cached result is supplied only
by the scanner after parsing its current document.
"""
def classify_credential_fields(raw, policy):
    if raw.get('document',{}).get('parse_succeeded') is False:
        return {'state':'not_performed','fields':[],'errors':[],'scope':'No parsed HTML document; field classification was not performed.'}
    classifier=getattr(policy,'credential_classifier',None)
    observations=[];errors=[]
    for index,field in enumerate(raw.get('inputs',[])):
        target={'field_id':field.get('field_id'),'form_id':field.get('form_id'),'field_index':index}
        value=field.get('credential_type')
        state='evaluated' if value is not None else 'not_performed'
        if value is None and classifier is not None:
            try:
                value=classifier(field)
                if value is not None and not isinstance(value,str):
                    raise TypeError('credential classifier must return a string or None')
                state='evaluated'
            except Exception as exc:
                state='unresolved';value=None
                errors.append({'code':'credential_classification_failed',
                    'occurrence_id':f'l3:credential-classification:{index}',
                    'stage':'credential_classification','impact_scope':'analysis','target':target,
                    'message':str(exc),'exception':type(exc).__name__})
        observations.append({**target,'state':state,'credential_type':value})
    completed=sum(x['state']=='evaluated' for x in observations)
    return {'state':'partial' if errors and completed else 'unavailable' if errors else 'completed' if classifier is not None else 'not_performed',
        'fields':observations,'errors':errors,
        'scope':'Configured field-label policy only; input values, runtime use, intent and maliciousness are not assessed.'}


def classification_result(raw,policy):
    return raw.get('credential_classification') or classify_credential_fields(raw,policy)
