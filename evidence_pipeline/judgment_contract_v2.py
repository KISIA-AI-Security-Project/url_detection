"""Judgment output contract for the isolated activity-aware v2 view.

The provider selects fixed evidence slots and writes one interpretation.  The
consumer keeps producer facts and Judgment-authored meaning in separate fields.
The isolated DNS-parallel runtime uses this contract before publishing a verdict.
"""
from copy import deepcopy
import re

from .judgment_view_v2 import validate_judgment_view_v2


VERSION='fact-interpretation-selection-2'
VALIDATION_VERSION='judgment-grounding-validation-1'
REVIEW_VERSION='judgment-review-1'
PROCESSING_VERSION='judgment-processing-1'
VERDICTS=('MALICIOUS','LIKELY_BENIGN','SUSPICIOUS','UNKNOWN')
SLOT_GROUPS={
    'observed_fact_ids':('observed_fact_id_1','observed_fact_id_2'),
    'basis_fact_ids':('basis_fact_id_1','basis_fact_id_2'),
    'limitation_fact_ids':('limitation_fact_id_1','limitation_fact_id_2'),
}
REQUIRED={'verdict','interpretation_text','basis_fact_id_1'}
ALLOWED=REQUIRED|{slot for slots in SLOT_GROUPS.values() for slot in slots}

# This is a deliberately narrow post-condition for the confirmed s05 failure.
# It does not grade arbitrary prose.  It only rejects a positive credential
# transfer assertion when none of the selected basis facts records that
# relationship directly.
_CREDENTIAL_TERM=re.compile(r'(?:비밀번호|자격증명|암호|password|credential)',re.IGNORECASE)
_TRANSFER_ASSERTION=re.compile(
    r'(?:전송|유출|전달|송신|보내|흘러|'
    r'transmit(?:s|ted|ting)?|send(?:s|ing)?|sent|exfiltrat(?:e|es|ed|ing|ion)|'
    r'forward(?:s|ed|ing)?|deliver(?:s|ed|ing)?|leak(?:s|ed|ing)?)',
    re.IGNORECASE)
_PAYLOAD_ASSERTION=re.compile(
    r'(?:(?:POST\s*)?(?:body|payload|요청\s*본문|본문).{0,24}(?:담|포함|실리|contain|include)|'
    r'(?:담|포함|실리|contain|include).{0,24}(?:POST\s*)?(?:body|payload|요청\s*본문|본문))',
    re.IGNORECASE)
_NEGATED_TRANSFER=re.compile(
    r'(?:전송|유출|전달|송신|보내|흘러)(?:되|하)?지는?\s*(?:않|못)|'
    r'(?:전송|유출|전달|송신|보내|흘러)(?:한|했다는)?\s*(?:구체적\s*)?증거.{0,8}없|'
    r'(?:was|were)\s+(?:not|never)\s+(?:sent|transmitted|forwarded|delivered|leaked)|'
    r'(?:has|have|had)\s+never\s+been\s+(?:sent|transmitted|forwarded|delivered|leaked)|'
    r'never\s+(?:sent|transmitted|forwarded|delivered|leaked)|'
    r'no\s+evidence.{0,48}(?:sent|transmitted|forwarded|delivered|leaked)',re.IGNORECASE)
_STATIC_RELATION=re.compile(
    r'(?:(?:전송|유출|전달|송신|보내).{0,12}(?:하도록\s*(?:구성|설정|되어|돼)|하는\s*(?:구조|코드))|'
    r'(?:구성|설정).{0,18}(?:전송|유출|전달|송신|보내)|'
    r'configured.{0,24}(?:transmit|send|forward|deliver|leak)|'
    r'(?:transmit|send|forward|deliver|leak).{0,18}(?:configuration|configured))',re.IGNORECASE)
_OBSERVED_MODALITY=re.compile(
    r'(?:실제로|실제\s*전송|실행되어|관찰된\s*전송|전송되었다|전송됐다|전송했다|전달했다|송신했다|보냈다|유출되었다|유출됐다|'
    r'observed|actually|was\s+sent|were\s+sent|delivered)',re.IGNORECASE)


def anthropic_output_config_v2(view):
    """Return a provider-supported schema with a hard two-slot cardinality."""
    validate_judgment_view_v2(view)
    fact_ids=[row['id'] for row in view['fact_units']]
    if not fact_ids:
        raise ValueError('judgment_view_v2_has_no_facts')
    properties={
        'verdict':{'type':'string','enum':list(VERDICTS)},
        # Anthropic structured outputs do not support minLength/maxLength.  A
        # simple supported pattern prevents an empty or whitespace-only value.
        'interpretation_text':{'type':'string','pattern':'.*\\S.*'},
    }
    for slots in SLOT_GROUPS.values():
        for slot in slots:
            properties[slot]={'type':'string','enum':list(fact_ids)}
    schema={
        'type':'object',
        'additionalProperties':False,
        'required':sorted(REQUIRED),
        'properties':properties,
    }
    return {'format':{'type':'json_schema','schema':schema}}


def _selected(value,slots):
    return [value[slot] for slot in slots if slot in value]


def _asserts_credential_transfer(text):
    for clause in re.split(r'(?:[,。;；\n]|\.(?=\s|$)|하지만|그러나|있으며|이며|이고|\bbut\b|\bhowever\b)',text):
        if (_CREDENTIAL_TERM.search(clause) and
                (_TRANSFER_ASSERTION.search(clause) or _PAYLOAD_ASSERTION.search(clause)) and
                _NEGATED_TRANSFER.search(clause) is None):
            return clause
    return None


def _supports_credential_transfer(row):
    facts=row['facts']
    if facts.get('payload_relationship') in {'recorded_source_links','linked_source_evidence_recorded'}:
        return any(isinstance(link,dict) and isinstance(link.get('credential_type'),str)
                   for link in facts.get('source_links',[]))
    assessment=facts.get('assessment') or {};predicate=assessment.get('predicate') or {}
    evidence=facts.get('evidence') or {}
    return (facts.get('name')=='credential_exfiltration' and predicate.get('result')=='matched' and
            isinstance(evidence.get('source_sink_relationships'),list) and
            bool(evidence['source_sink_relationships']))


def _supports_observed_credential_transfer(row):
    return _supports_credential_transfer(row) and row['facts'].get('execution_observed') is True


def _validated_selection(value,view):
    validate_judgment_view_v2(view)
    if not isinstance(value,dict) or not REQUIRED<=set(value) or not set(value)<=ALLOWED:
        raise ValueError('invalid_judgment_v2_shape')
    if value.get('verdict') not in VERDICTS:
        raise ValueError('invalid_judgment_v2_verdict')
    text=value.get('interpretation_text')
    if not isinstance(text,str) or re.search(r'\S',text) is None:
        raise ValueError('invalid_judgment_v2_interpretation')
    by_id={row['id']:row for row in view['fact_units']}
    selected={name:_selected(value,slots) for name,slots in SLOT_GROUPS.items()}
    for name,ids in selected.items():
        if not all(isinstance(identifier,str) and identifier in by_id for identifier in ids):
            raise ValueError('invalid_judgment_v2_fact_reference')
        if len(ids)!=len(set(ids)):
            raise ValueError('duplicate_judgment_v2_fact_reference')
    basis=selected['basis_fact_ids']
    if not basis:
        raise ValueError('judgment_v2_interpretation_requires_basis')
    return text,by_id,selected


def _basis_transfer_support(identifier,row):
    facts=row['facts']
    links=facts.get('source_links')
    credential_links=[] if not isinstance(links,list) else [
        link for link in links
        if isinstance(link,dict) and isinstance(link.get('credential_type'),str)]
    execution=facts.get('execution_observed','unrecorded')
    if type(execution) is not bool:
        execution='unrecorded'
    name=facts.get('name','unrecorded')
    direct=_supports_credential_transfer(row)
    if direct:
        support_scope='records_direct_credential_to_external_payload_relationship'
    elif name=='credential_access':
        support_scope='records_credential_access_without_direct_sink_link'
    elif name=='network_destination':
        support_scope='records_network_destination_without_direct_credential_source_link'
    else:
        support_scope='does_not_record_direct_credential_transfer_relationship'
    return {
        'fact_id':identifier,
        'fact_kind':row['kind'],
        'fact_name':name,
        'support_scope':support_scope,
        'response_observation':facts.get('response_observation','unrecorded'),
        'payload_relationship':facts.get('payload_relationship','unrecorded'),
        'credential_source_link_count':len(credential_links),
        'direct_credential_transfer_relationship':direct,
        'execution_observed':execution,
    }


def judgment_validation_v2(value,view):
    """Describe grounding failures without deciding whether L4 should investigate."""
    text,by_id,selected=_validated_selection(value,view)
    basis=selected['basis_fact_ids']
    transfer_clause=_asserts_credential_transfer(text)
    findings=[]
    if transfer_clause:
        claims_observed=(_OBSERVED_MODALITY.search(transfer_clause) is not None or
                         _STATIC_RELATION.search(transfer_clause) is None)
        support=[_basis_transfer_support(identifier,by_id[identifier]) for identifier in basis]
        linked=[item['fact_id'] for item in support if item['direct_credential_transfer_relationship']]
        observed=[item['fact_id'] for item in support
                  if item['direct_credential_transfer_relationship'] and item['execution_observed'] is True]
        access=[item['fact_id'] for item in support if item['fact_name']=='credential_access']
        destinations=[item['fact_id'] for item in support if item['fact_name']=='network_destination']
        claim={
            'text':text,
            'matched_clause':transfer_clause.strip(),
            'type':'credential_transfer',
            'modality':'observed_execution' if claims_observed else 'static_relationship',
        }
        if not linked:
            findings.append({
                'code':'credential_transfer_claim_requires_linked_basis',
                'claim':claim,
                'selected_basis_fact_ids':list(basis),
                'basis_support':support,
                'required_evidence':{
                    'relationship':'credential_value_to_external_request_payload',
                    'required_in':'at_least_one_selected_basis_fact',
                    'execution_observed_required':claims_observed,
                },
                'missing_evidence':{
                    'direct_relationship_fact_ids':[],
                    'separately_recorded_fact_ids':{
                        'credential_access':access,
                        'network_destination':destinations,
                    },
                    'not_recorded_relationship':'credential_access_value_to_network_destination_request_payload',
                    'precise_gap':'No selected basis fact records the credential value as the source of an external request payload.',
                },
            })
        elif claims_observed and not observed:
            findings.append({
                'code':'observed_credential_transfer_claim_requires_observed_basis',
                'claim':claim,
                'selected_basis_fact_ids':list(basis),
                'basis_support':support,
                'required_evidence':{
                    'relationship':'credential_value_to_external_request_payload',
                    'required_in':'at_least_one_selected_basis_fact',
                    'execution_observed_required':True,
                },
                'missing_evidence':{
                    'direct_relationship_fact_ids':linked,
                    'execution_observed_fact_ids':[],
                    'precise_gap':'Selected basis records a static credential-to-payload relationship, but no selected supporting fact records execution_observed=true.',
                },
            })
    return {
        'judgment_validation_version':VALIDATION_VERSION,
        'status':'rejected' if findings else 'accepted',
        'scope':'judgment_grounding_only',
        'judgment_accepted_for_consumer':not findings,
        'findings':findings,
    }


def review_judgment_output_v2(value,view):
    """Preserve the original Judgment next to its grounding validation."""
    return {
        'judgment_review_version':REVIEW_VERSION,
        'judgment':deepcopy(value),
        'validation':deepcopy(judgment_validation_v2(value,view)),
    }


def process_judgment_output_v2(value,view):
    """Review one provider Judgment and create a consumer result only when accepted."""
    review=review_judgment_output_v2(value,view)
    findings=review['validation']['findings']
    if findings:
        return {
            'judgment_processing_version':PROCESSING_VERSION,
            'status':'rejected',
            'review':review,
            'consumer':None,
            'rejection_code':findings[0]['code'],
        }
    return {
        'judgment_processing_version':PROCESSING_VERSION,
        'status':'accepted',
        'review':review,
        'consumer':adapt_judgment_output_v2(value,view),
        'rejection_code':None,
    }


def persist_judgment_output_v2(value,view,write_artifact):
    """Persist original, review, status, and only an accepted consumer in that order."""
    if not callable(write_artifact):
        raise TypeError('judgment_artifact_writer_required')
    write_artifact('selection.json',deepcopy(value))
    try:
        processing=process_judgment_output_v2(value,view)
    except Exception as error:
        write_artifact('processing.json',{
            'judgment_processing_version':PROCESSING_VERSION,
            'status':'validation_error',
            'consumer_created':False,
            'error_code':str(error),
        })
        raise
    write_artifact('review.json',deepcopy(processing['review']))
    write_artifact('processing.json',{
        'judgment_processing_version':PROCESSING_VERSION,
        'status':processing['status'],
        'consumer_created':processing['consumer'] is not None,
        'rejection_code':processing['rejection_code'],
    })
    if processing['consumer'] is not None:
        write_artifact('consumer.json',deepcopy(processing['consumer']))
    return processing


def adapt_judgment_output_v2(value,view):
    """Validate provider slots and render a provenance-preserving consumer result."""
    text,by_id,selected=_validated_selection(value,view)
    report=judgment_validation_v2(value,view)
    if report['findings']:
        raise ValueError(report['findings'][0]['code'])
    basis=selected['basis_fact_ids']
    def facts(ids):
        return [deepcopy(by_id[identifier]) for identifier in ids]
    response_observations=[]
    for identifier in basis:
        scope=by_id[identifier]['facts'].get('response_observation')
        if isinstance(scope,str) and scope not in response_observations:
            response_observations.append(scope)
    return {
        'judgment_contract_version':VERSION,
        'verdict':value['verdict'],
        'observed_facts':facts(selected['observed_fact_ids']),
        'interpretation':{
            'text':text,
            'basis_fact_ids':basis,
            'basis_facts':facts(basis),
            'basis_response_observations':response_observations,
        },
        'limitation_support_facts':facts(selected['limitation_fact_ids']),
        'provider_selection':deepcopy(value),
    }
