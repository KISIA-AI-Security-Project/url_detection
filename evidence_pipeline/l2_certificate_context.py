"""C04 leaf self-signature selection, independent from C05 chain trust."""
from copy import deepcopy
from .l2_context import TLS_MISSING

C04 = 'L2-C-04'
SIGNATURE_LABEL = '서버 인증서 서명 검사'
SIGNATURE_TEXT = {
    True: '인증서에 들어 있는 공개키로 그 인증서 자체의 서명이 검증됨 (자체 서명).',
    False: '자체 서명 인증서가 아님. 발급자를 신뢰할 수 있는지는 별도 검사 대상임.',
}
C04_NULL = '인증서는 수집됐지만 자체 서명 여부를 검증하지 못함 (세부 원인 미기록)'
C04_UNRECORDED = '서버 인증서의 자체 서명 검사 결과와 세부 원인이 기록되지 않음'
C04_FAILED = '서버 인증서의 자체 서명 분석 실패'


def _owned(item):
    return item.get('layer') == 'l2' and (item.get('id') == C04 or item.get('name') == 'self_signed_certificate')


class C04Selection:
    def __init__(self, source):
        selected = [x for x in source.get('observations', []) if _owned(x)]
        if len(selected) > 1:
            raise ValueError('duplicate_l2_c04_observation')
        self.item = selected[0] if selected else None
        self.projected = {}
        self.limit_facts = {}
        self.absent_causes = set()
        self.additions = {}
        if self.item is None:
            return
        tls = source.get('l2_tls_source') or {}
        leaf = tls.get('leaf_certificate') or {}
        result = self.item.get('detected')
        if result is not None:
            if type(result) is not bool or not leaf or leaf.get('self_signed') is not result:
                raise ValueError('c04_raw_record_result_mismatch')
            self.additions[SIGNATURE_LABEL] = SIGNATURE_TEXT[result]
        related = [x for x in source.get('causes', []) if x['id'] in self.item.get('cause_ids', [])]
        if result is not None:
            for cause in source.get('causes', []):
                detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
                if (cause.get('instance') or {}).get('analyzer') == C04 and detail.get('code') == 'analyzer_failed':
                    raise ValueError('c04_result_conflicts_with_analysis_failure')
        self.tls_limit_recorded = any((x.get('occurrence') or {}).get('stage') == 'tls'
            and (x.get('occurrence') or {}).get('impact_scope') == 'acquisition' for x in related)
        for cause in related:
            users = [x for x in source.get('observations', []) if cause['id'] in x.get('cause_ids', [])]
            if not users or not all(_owned(x) for x in users):
                continue
            detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            if result is not None and detail.get('code') in {'analyzer_failed', 'analysis_unresolved_reason_not_recorded'}:
                raise ValueError('c04_result_conflicts_with_analysis_failure')
            if detail.get('code') == 'analyzer_failed':
                facts = {'관측 한계': C04_FAILED}
                reason = detail.get('error') or detail.get('message')
                if reason:
                    facts['이유'] = reason
                self.limit_facts[cause['id']] = facts
            elif detail.get('code') == 'analysis_unresolved_reason_not_recorded':
                if 'leaf_certificate' in tls and not leaf:
                    self.absent_causes.add(cause['id'])
                else:
                    self.limit_facts[cause['id']] = {'관측 한계': C04_NULL if leaf and 'self_signed' in leaf and leaf['self_signed'] is None else C04_UNRECORDED}

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            if self.additions:
                targets = document.lookup.get(('technical', 'tls-identity'), [])
                if not targets:
                    raise ValueError('c04_result_without_certificate_context')
                targets[0]['source_pointers'].append(pointer)
                document.lookup[('check', C04)].append(targets[0])
            document.model_omissions.append({'source': pointer, 'reason': 'c04_subject_issuer_and_wrapper_retained_in_audit'})
            return True
        if collection == 'causes' and value.get('id') in self.absent_causes:
            shared = (self.tls_limit_recorded or bool(document.c02.absent_certificate_causes)
                      or bool(document.c03.absent_certificate_causes)
                      or any(kind == 'tls_observation_limit' for kind, _ in document.c01.limit_facts.values()))
            if not shared:
                eid = document.add('tls_observation_limit', value, pointer)
                document.lookup[('limitation', value['id'])].append(document.definitions[-1])
                self.projected[eid] = {'관측 한계': TLS_MISSING}
            document.model_omissions.append({'source': pointer, 'reason': 'c04_certificate_absence_represented_as_shared_tls_limit'})
            return True
        if collection == 'causes' and value.get('id') in self.limit_facts:
            eid = document.add('certificate_signature_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            facts = deepcopy(self.limit_facts[value['id']])
            if document.lookup.get(('technical', 'tls-identity')):
                facts['certificate_ref'] = document.ref('technical', 'tls-identity')
            self.projected[eid] = facts
            return True
        return False

    def prepare_technical(self, value):
        if value.get('kind') == 'certificate_identity_comparison' and 'source_evidence_ids' in value:
            value['source_evidence_ids'] = [x for x in value['source_evidence_ids'] if x != C04]
            if not value['source_evidence_ids']:
                value.pop('source_evidence_ids')
        return value

    def finish_technical(self, facts):
        if facts.get('kind') == 'certificate_identity_comparison':
            facts.update(deepcopy(self.additions))
        return facts

    def visible_occurrence(self, occurrence):
        if self.item is not None and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C04]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def validate_c04_selection(context):
    count = 0
    for row in context.get('evidence', []):
        facts, kind = row.get('facts') or {}, row.get('kind')
        if kind == 'check' and _owned(facts):
            raise ValueError('c04_record_wrapper_leaked_to_model_context')
        if SIGNATURE_LABEL in facts:
            count += 1
            if kind != 'technical' or facts.get('kind') != 'certificate_identity_comparison' or facts[SIGNATURE_LABEL] not in SIGNATURE_TEXT.values():
                raise ValueError('invalid_c04_signature_result')
        if kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison':
            if set(facts) & {'self_signed', '자체 서명 여부', 'issuer', 'subject'}:
                raise ValueError('c04_duplicate_fields_leaked_to_model_context')
        if kind == 'certificate_signature_limit':
            if set(facts) - {'관측 한계', '이유', 'certificate_ref'} or facts.get('관측 한계') not in {C04_FAILED, C04_NULL, C04_UNRECORDED}:
                raise ValueError('invalid_c04_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c04_model_limit_reason')
            if 'certificate_ref' in facts:
                ref = facts['certificate_ref']
                target = next((r for r in context.get('evidence', []) if r.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
                if not target or set(ref) != {'evidence_ref'} or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                    raise ValueError('invalid_c04_certificate_reference')
    if count > 1:
        raise ValueError('duplicate_c04_signature_result')
