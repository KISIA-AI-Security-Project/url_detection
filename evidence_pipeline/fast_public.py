"""Dependency-free, allowlisted public API contract (also packaged with Result)."""
from copy import deepcopy
from hashlib import sha256
import json

VERSION = 'fast-result-1'
STATUSES = {'not_requested', 'pending', 'accepted', 'failed', 'invalid'}
# New provider responses are validated against five labels in fast_judgment.
# Keep the stored four-label history readable without relabeling its judgments.
VERDICTS = {'BENIGN', 'LIKELY_BENIGN', 'LIKELY_MALICIOUS', 'MALICIOUS', 'UNKNOWN', 'SUSPICIOUS'}


def revision(value):
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')).hexdigest()


def make_public_result(job_id, attempt, *, context=None, status='pending', judgment=None):
    context_revision = context['context_revision'] if context else None
    result = {'schema_version': VERSION, 'job_id': job_id, 'attempt': int(attempt),
              'context_revision': context_revision, 'judgment_status': status,
              'judgment': deepcopy(judgment),
              'details': deepcopy(context['details']) if context else
                         {'context_revision': None, 'sections': [], 'facts': []},
              'deep_analysis': {'available': status == 'accepted'}}
    result['result_revision'] = revision(result)
    return validate_public_result(result, job_id=job_id, attempt=attempt)


def _keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('invalid_public_contract')


def _strings(values):
    return isinstance(values, list) and all(isinstance(v, str) for v in values)


def validate_public_result(value, *, job_id, attempt):
    """Check API shape and local IDs; never re-open raw/S3 citations."""
    _keys(value, ('schema_version', 'job_id', 'attempt', 'result_revision', 'context_revision',
                  'judgment_status', 'judgment', 'details', 'deep_analysis'))
    if (value['schema_version'] != VERSION or value['job_id'] != job_id or
            type(value['attempt']) is not int or value['attempt'] != int(attempt) or
            value['judgment_status'] not in STATUSES or not isinstance(value['result_revision'], str)):
        raise ValueError('public_identity_or_status_mismatch')
    if value['context_revision'] is not None and not isinstance(value['context_revision'], str):
        raise ValueError('invalid_context_revision')
    details = value['details']
    _keys(details, ('context_revision', 'sections', 'facts'))
    if (details['context_revision'] != value['context_revision'] or
            not isinstance(details['facts'], list) or not isinstance(details['sections'], list)):
        raise ValueError('invalid_public_details')
    ids = set()
    for fact in details['facts']:
        _keys(fact, ('fact_id', 'title', 'kind', 'text', 'basis', 'condition_fact_ids', *(['plain'] if 'plain' in fact else [])))
        if 'plain' in fact:
            _keys(fact['plain'], ('title', 'text'))
            if not all(isinstance(v, str) and v.strip() for v in fact['plain'].values()):
                raise ValueError('invalid_plain_fact')
        if (not all(isinstance(fact[k], str) and fact[k] for k in ('fact_id', 'title', 'kind', 'text')) or
                fact['fact_id'] in ids or not _strings(fact['condition_fact_ids'])):
            raise ValueError('invalid_public_fact')
        ids.add(fact['fact_id'])
        _keys(fact['basis'], ('kind', 'label'))
        if not all(isinstance(v, str) and v for v in fact['basis'].values()):
            raise ValueError('invalid_fact_basis')
    section_ids, located = set(), []
    for section in details['sections']:
        _keys(section, ('section_id', 'title', 'fact_ids'))
        if (not isinstance(section['section_id'], str) or section['section_id'] in section_ids or
                not isinstance(section['title'], str) or not _strings(section['fact_ids'])):
            raise ValueError('invalid_public_section')
        section_ids.add(section['section_id']); located.extend(section['fact_ids'])
    if set(located) != ids or len(located) != len(ids):
        raise ValueError('invalid_fact_placement')
    for fact in details['facts']:
        if not set(fact['condition_fact_ids']) <= ids:
            raise ValueError('invalid_condition_link')
    judgment = value['judgment']
    if value['judgment_status'] == 'accepted':
        _keys(judgment, ('verdict', 'summary', 'reasons'))
        if (judgment['verdict'] not in VERDICTS or not isinstance(judgment['summary'], str) or
                not judgment['summary'].strip() or not isinstance(judgment['reasons'], list) or
                (not judgment['reasons'] and judgment['verdict'] != 'UNKNOWN')):
            raise ValueError('invalid_public_judgment')
        reason_ids = set()
        for reason in judgment['reasons']:
            _keys(reason, ('reason_id', 'text', 'related_fact_ids'))
            if (not isinstance(reason['reason_id'], str) or reason['reason_id'] in reason_ids or
                    not isinstance(reason['text'], str) or not reason['text'].strip() or
                    not _strings(reason['related_fact_ids']) or not set(reason['related_fact_ids']) <= ids):
                raise ValueError('invalid_public_reason')
            reason_ids.add(reason['reason_id'])
    elif judgment is not None:
        raise ValueError('service_state_must_not_have_verdict')
    _keys(value['deep_analysis'], ('available',))
    if value['deep_analysis']['available'] is not (value['judgment_status'] == 'accepted'):
        raise ValueError('invalid_deep_availability')
    return deepcopy(value)
