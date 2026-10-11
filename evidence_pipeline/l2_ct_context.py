"""C06: select recorded CT time, elapsed days and source without a freshness verdict."""
from copy import deepcopy
from datetime import datetime
import re

C06 = 'L2-C-06'
CT_TIME = '인증서 CT 기록 시각'
CT_AGE = '해당 시각 이후 경과'
CT_SOURCE = '출처'
SOURCE_LABELS = {'embedded_sct': '인증서에 포함된 SCT', 'crt.sh': 'crt.sh 조회'}
CT_MISSING = 'CT 기록 시각과 경과일이 기록되지 않음'
CT_AGE_MISSING = 'CT 기록 시각 이후 경과일이 기록되지 않음'
CT_EMPTY = 'crt.sh 조회 응답에 해당 인증서 항목이 없음'
CT_NO_TIME = 'crt.sh 조회 응답의 항목에 기록 시각이 없음'
CT_NO_CERT = 'CT 시각을 읽을 인증서가 수집 자료에 없음'
CT_FAILED = 'CT 기록 시각 이후 경과일 계산 실패'
CT_KINDS = {'certificate_ct_time', 'certificate_ct_limit'}


def _owned(item):
    return item.get('layer') == 'l2' and (item.get('id') == C06 or item.get('name') == 'ct_first_seen')


class C06Selection:
    def __init__(self, source):
        items = [item for item in source.get('observations', []) if _owned(item)]
        if len(items) > 1:
            raise ValueError('duplicate_l2_c06_observation')
        self.item = items[0] if items else None
        self.facts = {}
        self.projected = {}
        self.limits = {}
        self.omitted_causes = set()
        self.extra_limit = None
        if self.item is None:
            return
        evidence = self.item.get('evidence') or {}
        ct = source.get('l2_ct_source') or {}
        tls = source.get('l2_tls_source') or {}
        first_seen = evidence.get('first_seen')
        age = evidence.get('age_days')
        if first_seen:
            try:
                datetime.fromisoformat(first_seen)
            except (TypeError, ValueError) as exc:
                raise ValueError('invalid_c06_recorded_time') from exc
            if 'first_seen' in ct and first_seen != ct['first_seen']:
                raise ValueError('c06_raw_record_time_mismatch')
            recorded_source = evidence.get('source', ct.get('source'))
            if 'source' in evidence and 'source' in ct and evidence['source'] != ct['source']:
                raise ValueError('c06_raw_record_source_mismatch')
            if recorded_source is not None and (not isinstance(recorded_source, str) or not recorded_source):
                raise ValueError('invalid_c06_recorded_source')
            self.facts = {CT_TIME: first_seen,
                CT_SOURCE: SOURCE_LABELS.get(recorded_source, '미기록' if recorded_source is None else '기록된 출처: '+recorded_source)}
            if age is not None:
                if type(age) is not int:
                    raise ValueError('invalid_c06_recorded_age')
                self.facts[CT_AGE] = f'검사 당시 {age}일' + (' (검사 시각보다 뒤의 기록)' if age < 0 else '')
            else:
                self.extra_limit = CT_AGE_MISSING
        elif age is not None:
            raise ValueError('c06_age_without_recorded_time')

        causes = source.get('causes', [])
        types = source.get('cause_types', {})
        related = [c for c in causes if c['id'] in self.item.get('cause_ids', [])]
        no_certificate = 'leaf_certificate' in tls and not tls['leaf_certificate']
        shared_limit = any((c.get('occurrence') or {}).get('impact_scope') == 'acquisition'
            and ((c.get('occurrence') or {}).get('stage') == 'ct'
                 or no_certificate and (c.get('occurrence') or {}).get('stage') == 'tls') for c in causes)
        if self.facts:
            for cause in causes:
                if (cause.get('instance') or {}).get('analyzer') == C06 and types.get(cause.get('type_id'), {}).get('code') == 'analyzer_failed':
                    raise ValueError('c06_result_conflicts_with_analysis_failure')
        missing = (CT_EMPTY if ct.get('log_entries') == 0 else
                   CT_NO_TIME if type(ct.get('log_entries')) is int and ct['log_entries'] > 0 else
                   CT_NO_CERT if no_certificate else CT_MISSING)
        for cause in related:
            users = [o for o in source.get('observations', []) if cause['id'] in o.get('cause_ids', [])]
            if not users or not all(_owned(o) for o in users):
                continue
            detail = types.get(cause.get('type_id'), {})
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            code = detail.get('code')
            if code == 'analyzer_failed':
                facts = {'관측 한계': CT_FAILED}
                reason = detail.get('error') or detail.get('message')
                if reason:
                    facts['이유'] = reason
                self.limits[cause['id']] = facts
            elif code in {'ct_timestamp_unavailable', 'analysis_unresolved_reason_not_recorded'}:
                if shared_limit:
                    self.omitted_causes.add(cause['id'])
                else:
                    self.limits[cause['id']] = {'관측 한계': CT_AGE_MISSING if self.facts else missing}
                    self.extra_limit = None
        if not self.facts and not related and not shared_limit:
            self.extra_limit = missing

    @staticmethod
    def _link(facts, document):
        facts = deepcopy(facts)
        if document.lookup.get(('technical', 'tls-identity')):
            facts['certificate_ref'] = document.ref('technical', 'tls-identity')
        return facts

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            if self.facts:
                eid = document.add('certificate_ct_time', value, pointer)
                document.lookup[('check', C06)].append(document.definitions[-1])
                document.definitions[-1]['source_pointers'].append('/l2_ct_source')
                self.projected[eid] = self._link(self.facts, document)
            if self.extra_limit:
                eid = document.add('certificate_ct_limit', value, pointer)
                self.projected[eid] = self._link({'관측 한계': self.extra_limit}, document)
            document.model_omissions.append({'source': pointer,
                'reason': 'c06_recorded_time_age_source_selected_threshold_and_wrapper_retained_in_audit'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer,
                'reason': 'c06_unavailable_time_represented_by_recorded_collection_limit'})
            return True
        if collection == 'causes' and value.get('id') in self.limits:
            # An absent certificate can already be represented by C01-C04.
            common_absence = (any(kind == 'tls_observation_limit' for kind, _ in document.c01.limit_facts.values())
                or document.c02.absent_certificate_causes or document.c03.absent_certificate_causes or document.c04.absent_causes)
            if self.limits[value['id']]['관측 한계'] == CT_NO_CERT and common_absence:
                document.model_omissions.append({'source': pointer, 'reason': 'c06_certificate_absence_shared_with_tls_limit'})
                return True
            eid = document.add('certificate_ct_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            self.projected[eid] = self._link(self.limits[value['id']], document)
            return True
        return False

    def visible_occurrence(self, occurrence):
        if self.item is not None and not self.facts and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C06]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def validate_c06_selection(context):
    count = 0
    rows = context.get('evidence', [])
    for row in rows:
        facts, kind = row.get('facts') or {}, row.get('kind')
        if kind == 'check' and _owned(facts):
            raise ValueError('c06_record_wrapper_leaked_to_model_context')
        if kind == 'certificate_ct_time':
            count += 1
            if set(facts) - {CT_TIME, CT_AGE, CT_SOURCE, 'certificate_ref'} or not {CT_TIME, CT_SOURCE} <= set(facts):
                raise ValueError('invalid_c06_model_fields')
            try:
                datetime.fromisoformat(facts[CT_TIME])
            except (ValueError, TypeError) as exc:
                raise ValueError('invalid_c06_model_time') from exc
            source = facts[CT_SOURCE]
            if not isinstance(source, str) or not (source in {*SOURCE_LABELS.values(), '미기록'} or source.startswith('기록된 출처: ') and len(source) > len('기록된 출처: ')):
                raise ValueError('invalid_c06_model_source')
            if CT_AGE in facts and (not isinstance(facts[CT_AGE], str) or not re.fullmatch(
                    r'검사 당시 (?:(?:0|[1-9][0-9]*)일|-[1-9][0-9]*일 \(검사 시각보다 뒤의 기록\))', facts[CT_AGE])):
                raise ValueError('invalid_c06_model_age')
        elif set(facts) & {CT_TIME, CT_AGE}:
            raise ValueError('c06_fields_outside_ct_evidence')
        if kind == 'certificate_ct_limit':
            if set(facts) - {'관측 한계', '이유', 'certificate_ref'} or facts.get('관측 한계') not in {
                    CT_MISSING, CT_AGE_MISSING, CT_EMPTY, CT_NO_TIME, CT_NO_CERT, CT_FAILED}:
                raise ValueError('invalid_c06_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c06_model_reason')
        if kind in CT_KINDS and 'certificate_ref' in facts:
            ref = facts['certificate_ref']
            target = next((r for r in rows if r.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
            if not target or set(ref) != {'evidence_ref'} or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                raise ValueError('invalid_c06_certificate_reference')
    if count > 1:
        raise ValueError('duplicate_c06_model_result')
