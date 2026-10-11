"""Judgment v2 input view with complete, inference-free evidence accounting.

Preserve every producer evidence row, Builder boundary, and URL activity
observation in the isolated gateway input.
"""
from copy import deepcopy

from .context_inventory import restore
from .model_context import validate_model_context, VERSION as MODEL_CONTEXT_VERSION, H09_VERSIONS, C01_VERSIONS, C02_VERSIONS, C03_VERSIONS, C04_VERSIONS, C05_VERSIONS, C06_VERSIONS, C07_VERSIONS
from .l2_http_context import validate_http_selection
from .l2_certificate_context import validate_c04_selection
from .l2_chain_context import validate_c05_selection
from .l2_ct_context import validate_c06_selection
from .l2_tls_version_context import validate_c07_selection
from .l2_wildcard_context import validate_c08_selection
from .records import digest
from .l0_context import validate_l0_selection
from .l1_context import validate_l1_selection
from .l2_context import validate_h09_selection, validate_c01_selection, validate_c02_selection, validate_c03_selection


VERSION = 'fact-boundary-view-2-static-activity'


def _evidence_refs(value):
    refs=[]
    if isinstance(value,dict):
        if set(value)=={'evidence_ref'} and isinstance(value['evidence_ref'],str):
            refs.append(value['evidence_ref'])
        else:
            for item in value.values():
                refs.extend(_evidence_refs(item))
    elif isinstance(value,list):
        for item in value:
            refs.extend(_evidence_refs(item))
    return refs


def _coverage_fact_ids_by_layer(facts):
    result={}
    for row in facts:
        if row.get('kind')!='coverage':
            continue
        layer=row.get('facts',{}).get('layer')
        if not isinstance(layer,str) or not layer:
            raise ValueError('judgment_view_v2_coverage_without_layer')
        result.setdefault(layer,[]).append(row['id'])
    return result


def _source_boundaries(source):
    """Copy existing boundary records without inferring new layer semantics."""
    result = {
        'model_context_version':source.get('model_context_version'),
        'reading_guide':deepcopy(source.get('reading_guide')),
        'evidence_groups':deepcopy(source.get('evidence_groups',[])),
        'content_observations':deepcopy(source.get('content_observations',[])),
        'observation_omissions':deepcopy(source.get('observation_omissions',[])),
        'coverage_fact_ids_by_layer':_coverage_fact_ids_by_layer(source['evidence']),
    }
    if source.get('layer_subjects'):
        result['layer_subjects']=deepcopy(source['layer_subjects'])
    return result


def build_judgment_view_v2(context):
    """Build the v2 view with every source evidence row included."""
    validate_model_context(context)
    source=restore(context)
    facts=deepcopy(source['evidence'])
    ids=[row['id'] for row in facts]
    view={
        'judgment_view_version':VERSION,
        'question':source['question'],
        'requested_urls':deepcopy(source['requested_urls']),
        'url_activity_observation':deepcopy(source.get('url_activity_observation')),
        'layer_boundaries':_source_boundaries(source),
        'fact_units':facts,
        'omitted_evidence':[],
        'source_accounting':{
            'source_evidence_count':len(ids),
            'fact_unit_count':len(ids),
            'omitted_evidence_count':0,
            'source_evidence_ids':ids,
            'source_evidence_sha256':digest(source['evidence']),
            'source_activity_sha256':digest(source['url_activity_observation'])
                if isinstance(source.get('url_activity_observation'),dict) else None,
        },
    }
    validate_judgment_view_v2(view,source_context=context)
    return view


def validate_judgment_view_v2(view, *, source_context=None):
    expected_keys={'judgment_view_version','question','requested_urls','url_activity_observation','layer_boundaries',
                   'fact_units','omitted_evidence','source_accounting'}
    if not isinstance(view,dict) or set(view)!=expected_keys:
        raise ValueError('invalid_judgment_view_v2_shape')
    if view['judgment_view_version']!=VERSION:
        raise ValueError('invalid_judgment_view_v2_version')
    if not isinstance(view['question'],str) or not isinstance(view['requested_urls'],list) or not view['requested_urls']:
        raise ValueError('invalid_judgment_view_v2_question')
    activity=view['url_activity_observation']
    if activity is not None and not isinstance(activity,dict):
        raise ValueError('invalid_judgment_view_v2_activity')
    facts=view['fact_units'];omissions=view['omitted_evidence'];accounting=view['source_accounting']
    if not isinstance(facts,list) or not isinstance(omissions,list) or not isinstance(accounting,dict):
        raise ValueError('invalid_judgment_view_v2_accounting')
    if not all(isinstance(row,dict) and isinstance(row.get('id'),str) and
               isinstance(row.get('kind'),str) and isinstance(row.get('facts'),dict) for row in facts):
        raise ValueError('invalid_judgment_view_v2_fact')
    fact_ids=[row['id'] for row in facts]
    if len(fact_ids)!=len(set(fact_ids)):
        raise ValueError('duplicate_judgment_view_v2_fact')
    if not all(isinstance(item,dict) and set(item)=={'id','rule'} and
               isinstance(item['id'],str) and isinstance(item['rule'],str) and item['rule'] for item in omissions):
        raise ValueError('invalid_judgment_view_v2_omission')
    omitted_ids=[item['id'] for item in omissions]
    if len(omitted_ids)!=len(set(omitted_ids)) or set(fact_ids)&set(omitted_ids):
        raise ValueError('duplicate_judgment_view_v2_accounting')
    expected_accounting={
        'source_evidence_count':len(fact_ids)+len(omitted_ids),
        'fact_unit_count':len(fact_ids),
        'omitted_evidence_count':len(omitted_ids),
        'source_evidence_ids':fact_ids+omitted_ids,
        'source_evidence_sha256':digest(facts),
        'source_activity_sha256':digest(activity) if activity is not None else None,
    }
    if accounting!=expected_accounting:
        raise ValueError('invalid_judgment_view_v2_accounting')
    dangling=set(_evidence_refs({'facts':facts,'boundaries':view['layer_boundaries']}))-set(fact_ids)
    if dangling:
        raise ValueError('judgment_view_v2_dangling_evidence_ref')
    boundaries=view['layer_boundaries']
    required_boundaries={'reading_guide','evidence_groups','content_observations',
                         'observation_omissions','coverage_fact_ids_by_layer'}
    if (not isinstance(boundaries,dict) or not required_boundaries<=set(boundaries)
            or set(boundaries)-required_boundaries-{'layer_subjects','model_context_version'}):
        raise ValueError('invalid_judgment_view_v2_boundaries')
    if boundaries['coverage_fact_ids_by_layer']!=_coverage_fact_ids_by_layer(facts):
        raise ValueError('invalid_judgment_view_v2_coverage_index')
    validate_l0_selection({'evidence':facts, 'requested_urls':view['requested_urls'],
                          'reading_guide':boundaries.get('reading_guide') or {}})
    validate_l1_selection({'evidence':facts,'layer_subjects':boundaries.get('layer_subjects',{}),
                          'reading_guide':boundaries.get('reading_guide') or {}})
    if boundaries.get('model_context_version') in H09_VERSIONS:
        validate_h09_selection({'evidence':facts})
    if boundaries.get('model_context_version') in C01_VERSIONS:
        validate_c01_selection({'evidence':facts,'model_context_version':boundaries['model_context_version']})
    if boundaries.get('model_context_version') in C02_VERSIONS:
        validate_c02_selection({'evidence':facts})
    if boundaries.get('model_context_version') in C03_VERSIONS:
        validate_c03_selection({'evidence':facts,'model_context_version':boundaries['model_context_version']})
    if boundaries.get('model_context_version') in C04_VERSIONS:
        validate_http_selection({'evidence':facts})
        validate_c04_selection({'evidence':facts})
    if boundaries.get('model_context_version') in C05_VERSIONS:
        validate_c05_selection({'evidence':facts})
    if boundaries.get('model_context_version') in C06_VERSIONS:
        validate_c06_selection({'evidence':facts})
    if boundaries.get('model_context_version') in C07_VERSIONS:
        validate_c07_selection({'evidence':facts})
    if boundaries.get('model_context_version')==MODEL_CONTEXT_VERSION:
        validate_c08_selection({'evidence':facts})
    if source_context is not None:
        validate_model_context(source_context)
        source=restore(source_context);source_ids=[row['id'] for row in source['evidence']]
        if view['question']!=source['question'] or view['requested_urls']!=source['requested_urls']:
            raise ValueError('judgment_view_v2_source_question_mismatch')
        if activity!=source.get('url_activity_observation'):
            raise ValueError('judgment_view_v2_source_activity_mismatch')
        if set(fact_ids)|set(omitted_ids)!=set(source_ids) or len(fact_ids)+len(omitted_ids)!=len(source_ids):
            raise ValueError('judgment_view_v2_source_accounting_mismatch')
        if omissions:
            raise ValueError('judgment_view_v2_static_slice_forbids_omission')
        if facts!=source['evidence'] or accounting['source_evidence_ids']!=source_ids:
            raise ValueError('judgment_view_v2_source_fact_mismatch')
        if boundaries!=_source_boundaries(source):
            raise ValueError('judgment_view_v2_source_boundary_mismatch')
        if accounting['source_evidence_sha256']!=digest(source['evidence']):
            raise ValueError('judgment_view_v2_source_hash_mismatch')
    return view


def restore_v2_evidence(view):
    """Return the exact evidence rows represented by this static v2 slice."""
    validate_judgment_view_v2(view)
    if view['omitted_evidence']:
        raise ValueError('judgment_view_v2_has_omissions')
    return deepcopy(view['fact_units'])
