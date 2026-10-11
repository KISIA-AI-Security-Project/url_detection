"""Select the recorded C05 TLS verification result; never revalidate a certificate."""
from copy import deepcopy

C05 = 'L2-C-05'
VERIFY_LABEL = '서버 인증서 검증'
VERIFY_PASSED = '스캐너가 신뢰하도록 설정한 인증서를 기준으로, 서버 인증서부터 발급기관으로 이어지는 서명 관계와 TLS 인증서 유효성 검사를 통과함.'
VERIFY_FAILED = '실패'
REASON_LABEL = '서버 인증서 검증 실패 사유'
REASON_MISSING = '실패 사유 미기록'
SCOPE_LABEL = '서버 인증서 검증 범위'
FAILED_SCOPE = '검증을 켠 첫 TLS 접속에서 관측한 실패다. 이후 인증서 수집용 재접속에서 인증서를 얻더라도 첫 접속의 인증서와 동일하다고 보장하지 않는다.'
C05_UNRECORDED = '서버 인증서 검증 결과와 세부 원인이 기록되지 않음'
C05_ANALYSIS_FAILED = '서버 인증서 검증 결과를 정리하는 분석에서 실패함'
KINDS = {'certificate_verification', 'certificate_verification_limit'}


def _owned(item):
    return item.get('layer') == 'l2' and (item.get('id') == C05 or item.get('name') == 'certificate_chain')


class C05Selection:
    def __init__(self, source):
        items = [(i, item) for i, item in enumerate(source.get('observations', [])) if _owned(item)]
        if len(items) > 1:
            raise ValueError('duplicate_l2_c05_observation')
        self.item = items[0][1] if items else None
        self.projected = {}
        self.additions = {}
        self.limits = {}
        self.omitted_causes = set()
        self.fallback_limit = False
        if self.item is None:
            return
        evidence = self.item.get('evidence') or {}
        tls = source.get('l2_tls_source') or {}
        valid = evidence.get('valid')
        if valid is not None and type(valid) is not bool:
            raise ValueError('invalid_c05_recorded_result')
        if valid is None and self.item.get('detected') is not None:
            raise ValueError('c05_detected_result_mismatch')
        if 'valid' in evidence and 'chain_valid' in tls and valid is not tls['chain_valid']:
            raise ValueError('c05_raw_record_result_mismatch')
        if valid is not None:
            if self.item.get('detected') is not (valid is False):
                raise ValueError('c05_detected_result_mismatch')
            error = evidence.get('error')
            if error is not None and (not isinstance(error, str) or not error.strip()):
                raise ValueError('invalid_c05_recorded_error')
            if 'chain_error' in tls and error != tls['chain_error']:
                raise ValueError('c05_raw_record_error_mismatch')
            if valid and error is not None:
                raise ValueError('c05_success_with_verification_error')
            self.additions[VERIFY_LABEL] = VERIFY_PASSED if valid else VERIFY_FAILED
            if not valid:
                self.additions[REASON_LABEL] = error if error is not None else REASON_MISSING
                self.additions[SCOPE_LABEL] = FAILED_SCOPE

        causes = source.get('causes', [])
        types = source.get('cause_types', {})
        related = [c for c in causes if c['id'] in self.item.get('cause_ids', [])]
        for cause in causes:
            detail = types.get(cause.get('type_id'), {})
            if (cause.get('instance') or {}).get('analyzer') == C05 and detail.get('code') == 'analyzer_failed' and valid is not None:
                raise ValueError('c05_result_conflicts_with_analysis_failure')
        # A certificate export/parsing failure does not explain an absent handshake
        # verification result. Keep that distinct from connection failure/non-attempt.
        shared_tls_limit = any((c.get('occurrence') or {}).get('stage') == 'tls'
            and (c.get('occurrence') or {}).get('impact_scope') == 'acquisition'
            and types.get(c.get('type_id'), {}).get('code') not in {'tls_chain_export_unavailable', 'certificate_parse_failed'}
            for c in related)
        for cause in related:
            users = [o for o in source.get('observations', []) if cause['id'] in o.get('cause_ids', [])]
            if not users or not all(_owned(o) for o in users):
                continue
            detail = types.get(cause.get('type_id'), {})
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            code = detail.get('code')
            if valid is not None and code in {'analyzer_failed', 'analysis_unresolved_reason_not_recorded'}:
                raise ValueError('c05_result_conflicts_with_analysis_failure')
            if code == 'analyzer_failed':
                facts = {'관측 한계': C05_ANALYSIS_FAILED}
                reason = detail.get('error') or detail.get('message')
                if reason:
                    facts['이유'] = reason
                self.limits[cause['id']] = facts
            elif code == 'analysis_unresolved_reason_not_recorded':
                if shared_tls_limit:
                    self.omitted_causes.add(cause['id'])
                else:
                    self.limits[cause['id']] = {'관측 한계': C05_UNRECORDED}
        self.fallback_limit = valid is None and not related

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            if self.additions:
                targets = document.lookup.get(('technical', 'tls-identity'), [])
                if targets:
                    targets[0]['source_pointers'].append(pointer)
                    document.lookup[('check', C05)].append(targets[0])
                else:
                    # Historical records can retain the verification result while
                    # omitting raw TLS identity; do not invent the inspected host.
                    eid = document.add('certificate_verification', value, pointer)
                    self.projected[eid] = {**deepcopy(self.additions), '검증 대상': 'TLS 접속 호스트 미기록'}
                    document.lookup[('check', C05)].append(document.definitions[-1])
            elif self.fallback_limit:
                eid = document.add('certificate_verification_limit', value, pointer)
                self.projected[eid] = self._limit({'관측 한계': C05_UNRECORDED}, document)
            document.model_omissions.append({'source': pointer, 'reason': 'c05_result_selected_chain_depth_and_record_wrapper_retained_in_audit'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer, 'reason': 'c05_unrecorded_placeholder_omitted_actual_tls_limit_retained'})
            return True
        if collection == 'causes' and value.get('id') in self.limits:
            eid = document.add('certificate_verification_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            self.projected[eid] = self._limit(self.limits[value['id']], document)
            return True
        return False

    @staticmethod
    def _limit(facts, document):
        facts = deepcopy(facts)
        if document.lookup.get(('technical', 'tls-identity')):
            facts['certificate_ref'] = document.ref('technical', 'tls-identity')
        return facts

    def prepare_technical(self, value):
        if value.get('kind') == 'certificate_identity_comparison':
            # v8 has a dedicated record-based C05 result. A raw-only value must
            # not bypass selection, including when the C05 record is missing.
            value.pop('chain_valid', None)
            if 'source_evidence_ids' in value:
                value['source_evidence_ids'] = [x for x in value['source_evidence_ids'] if x != C05]
                if not value['source_evidence_ids']:
                    value.pop('source_evidence_ids')
        return value

    def finish_technical(self, facts):
        if facts.get('kind') == 'certificate_identity_comparison':
            facts.update(deepcopy(self.additions))
        return facts

    def visible_occurrence(self, occurrence):
        if self.item is not None and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C05]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def validate_c05_selection(context):
    rows = context.get('evidence', [])
    count = 0
    for row in rows:
        facts, kind = row.get('facts') or {}, row.get('kind')
        if kind == 'check' and _owned(facts):
            raise ValueError('c05_record_wrapper_leaked_to_model_context')
        if kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison':
            forbidden = {'chain_valid', 'valid', 'chain_depth', 'certificate_chain', 'chain_error'}
            if set(facts) & forbidden or any(set(facts.get(key, [])) & forbidden for key in ('not_recorded', 'no_entries_recorded')):
                raise ValueError('c05_duplicate_fields_leaked_to_model_context')
        if VERIFY_LABEL in facts:
            count += 1
            shared = kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison'
            if not shared and kind != 'certificate_verification':
                raise ValueError('invalid_c05_result_location')
            result = facts[VERIFY_LABEL]
            if result not in {VERIFY_PASSED, VERIFY_FAILED}:
                raise ValueError('invalid_c05_model_result')
            if result == VERIFY_FAILED:
                if not isinstance(facts.get(REASON_LABEL), str) or not facts[REASON_LABEL].strip() or facts.get(SCOPE_LABEL) != FAILED_SCOPE:
                    raise ValueError('invalid_c05_failure_reason_or_scope')
            elif REASON_LABEL in facts or SCOPE_LABEL in facts:
                raise ValueError('c05_success_with_failure_fields')
            forbidden = {'chain_valid', 'valid', 'chain_depth', 'certificate_chain', 'chain_error', 'detected', 'evidence', 'assessment'}
            if set(facts) & forbidden or any(set(facts.get(key, [])) & forbidden for key in ('not_recorded', 'no_entries_recorded')):
                raise ValueError('c05_duplicate_fields_leaked_to_model_context')
        elif REASON_LABEL in facts or SCOPE_LABEL in facts or kind == 'certificate_verification':
            raise ValueError('c05_fields_without_verification_result')
        if kind == 'certificate_verification':
            if set(facts) - {VERIFY_LABEL, REASON_LABEL, SCOPE_LABEL, '검증 대상'} or facts.get('검증 대상') != 'TLS 접속 호스트 미기록':
                raise ValueError('invalid_c05_standalone_result')
        if kind == 'certificate_verification_limit':
            if set(facts) - {'관측 한계', '이유', 'certificate_ref'} or facts.get('관측 한계') not in {C05_UNRECORDED, C05_ANALYSIS_FAILED}:
                raise ValueError('invalid_c05_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c05_model_limit_reason')
            if 'certificate_ref' in facts:
                ref = facts['certificate_ref']
                target = next((r for r in rows if r.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
                if not target or set(ref) != {'evidence_ref'} or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                    raise ValueError('invalid_c05_certificate_reference')
    if count > 1:
        raise ValueError('duplicate_c05_verification_result')
