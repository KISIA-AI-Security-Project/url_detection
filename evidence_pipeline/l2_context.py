"""Approved H09 and C01-C03 selections; HTTP and C04 have companion modules."""
from copy import deepcopy
from datetime import datetime
import re

H01 = 'L2-H-01'
H09 = 'L2-H-09'
DOWNGRADE_LABEL = 'HTTPS→HTTP 이동 지시'


def _is_h09(value):
    return value.get('layer') == 'l2' and (
        value.get('id') == H09 or value.get('name') == 'protocol_downgrade')


class H09Selection:
    def __init__(self, source):
        observations = source.get('observations', [])
        selected = [(i, item) for i, item in enumerate(observations) if _is_h09(item)]
        if len(selected) > 1:
            raise ValueError('duplicate_l2_h09_observation')
        self.selected = selected
        self.observed = bool(selected and selected[0][1].get('detected') is True)
        self.omitted_causes = set()
        if not selected:
            return
        h09 = selected[0][1]
        # A check-specific analysis failure adds no fact to this positive-only
        # selection. Shared acquisition/HTTP limits remain in the model.
        for cause in source.get('causes', []):
            users = [item for item in observations if cause['id'] in item.get('cause_ids', [])]
            if (users and all(_is_h09(item) for item in users)
                    and (cause.get('occurrence') or {}).get('impact_scope') == 'analysis'):
                self.omitted_causes.add(cause['id'])
        if not self.observed:
            return
        journeys = [item for item in observations if item.get('layer') == 'l2' and item.get('id') == H01]
        if len(journeys) != 1 or journeys[0].get('detected') is not True:
            raise ValueError('l2_h09_observed_without_h01_journey')
        destinations = (journeys[0].get('evidence') or {}).get('chain')
        original = next((layer.get('target', {}).get('original_url') for layer in source.get('layers', [])
                         if layer.get('layer') == 'l2'), None)
        evidence = h09.get('evidence') or {}
        first_pair = (evidence.get('source_url'), evidence.get('destination_url'))
        # Compare supplied addresses only; do not rerun scheme detection or
        # infer arrival from the destination of an observed redirect instruction.
        if (not isinstance(original, str) or not isinstance(destinations, list) or not destinations
                or not all(isinstance(url, str) and url for url in destinations)
                or first_pair not in list(zip([original, *destinations[:-1]], destinations))):
            raise ValueError('l2_h09_h01_journey_mismatch')

    def omit(self, collection, value, pointer, document):
        if collection == 'observations' and _is_h09(value):
            document.model_omissions.append({'source': pointer,
                'reason': 'h09_details_retained_in_record_and_audit',
                'selection': 'observed_instruction_attached_to_h01' if self.observed else 'no_positive_instruction'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer,
                'reason': 'h09_only_analysis_limit_retained_in_record_and_audit'})
            return True
        return False

    def annotate(self, value, definition, document):
        if self.observed and value.get('layer') == 'l2' and definition['original_id'] == H01:
            value = deepcopy(value)
            value['evidence'][DOWNGRADE_LABEL] = '관측됨'
            document.removed.append({'source': f'/observations/{self.selected[0][0]}',
                'represented_by': definition['id'], 'field': DOWNGRADE_LABEL})
        return value

    def visible_occurrence(self, occurrence):
        if self.selected and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [identifier for identifier in occurrence['affected_signal_ids']
                                                  if identifier != H09]
        return occurrence


def validate_h09_selection(context):
    """Check newly built documents without invalidating older saved projections."""
    count = 0
    for row in context.get('evidence', []):
        facts = row.get('facts', {})
        if row.get('kind') == 'check' and _is_h09(facts):
            raise ValueError('standalone_h09_leaked_to_model_context')
        if row.get('kind') == 'http_journey' and DOWNGRADE_LABEL in facts:
            count += 1
            if facts[DOWNGRADE_LABEL] != '관측됨' or len(facts.get('관측된 HTTP 경로', [])) < 2:
                raise ValueError('invalid_h09_instruction_in_path')
            continue
        evidence = facts.get('evidence')
        if not isinstance(evidence, dict) or DOWNGRADE_LABEL not in evidence:
            continue
        count += 1
        if (row.get('kind') != 'check' or facts.get('layer') != 'l2'
                or facts.get('name') != 'redirect_chain'
                or evidence[DOWNGRADE_LABEL] != '관측됨'
                or not evidence.get('chain')):
            raise ValueError('invalid_h09_instruction_annotation')
        if set(evidence) & {'source_url', 'destination_url', 'downgrade_count', 'upgrade_count'}:
            raise ValueError('h09_details_duplicated_in_model_context')
    if count > 1:
        raise ValueError('duplicate_h09_instruction_annotation')


C01 = 'L2-C-01'
AGE_LABEL = '인증서 유효기간 시작 후 경과'
TIME_LABEL = '계산 기준 시각'
C01_MISSING = '인증서 유효 시작 시각이 수집 자료에 없음'
C01_FAILED = '인증서 경과일 계산 실패'
TLS_MISSING = '수집 자료에 인증서가 없음'
C01_KINDS = {'certificate_age', 'certificate_age_limit', 'tls_observation_limit'}


def _is_c01(value):
    return value.get('layer') == 'l2' and (
        value.get('id') == C01 or value.get('name') == 'certificate_age')


class C01Selection:
    def __init__(self, source):
        selected = [item for item in source.get('observations', []) if _is_c01(item)]
        if len(selected) > 1:
            raise ValueError('duplicate_l2_c01_observation')
        self.item = selected[0] if selected else None
        self.projected = {}
        self.omitted_causes = set()
        self.limit_facts = {}
        self.observed = bool(self.item and self.item.get('result_kind') == 'measurement'
                             and self.item.get('measurement_state') == 'observed')
        if self.item is None:
            return
        self.legacy = self.item.get('result_kind') != 'measurement'
        tls = source.get('l2_tls_source') or {}
        leaf = tls.get('leaf_certificate') or {}
        if self.observed:
            evidence = self.item['evidence']
            if not leaf or leaf.get('not_before') != evidence.get('not_before'):
                raise ValueError('c01_raw_measurement_mismatch')
            return
        related = [cause for cause in source.get('causes', []) if cause['id'] in self.item.get('cause_ids', [])]
        tls_limits = [cause for cause in related if (cause.get('occurrence') or {}).get('stage') == 'tls'
                      and (cause.get('occurrence') or {}).get('impact_scope') == 'acquisition']
        for cause in related:
            users = [item for item in source.get('observations', []) if cause['id'] in item.get('cause_ids', [])]
            if not users or not all(_is_c01(item) for item in users):
                continue
            detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
            code = detail.get('code')
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            if self.legacy or (not leaf and tls_limits and code == 'certificate_not_before_unavailable'):
                self.omitted_causes.add(cause['id'])
            elif code == 'certificate_not_before_unavailable':
                self.limit_facts[cause['id']] = (
                    'certificate_age_limit' if leaf else 'tls_observation_limit',
                    {'관측 한계': C01_MISSING if leaf else TLS_MISSING})
            elif code == 'analyzer_failed':
                facts = {'관측 한계': C01_FAILED}
                reason = detail.get('error') or detail.get('message')
                if isinstance(reason, str) and reason:
                    facts['이유'] = reason
                self.limit_facts[cause['id']] = ('certificate_age_limit', facts)

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _is_c01(value):
            if self.observed:
                evidence = value['evidence']
                days = evidence['age_days']
                facts = {AGE_LABEL: f'{days}일' + (' (유효기간 시작 전; 시간차를 24시간 단위로 내림한 값)' if days < 0 else ''),
                         TIME_LABEL: evidence['measured_at']}
                if document.lookup.get(('technical', 'tls-identity')):
                    facts['certificate_ref'] = document.ref('technical', 'tls-identity')
                eid = document.add('certificate_age', value, pointer)
                # Existing cause references may still use the native check ID.
                document.lookup[('check', C01)].append(document.definitions[-1])
                self.projected[eid] = facts
            document.model_omissions.append({'source': pointer, 'reason':
                'legacy_c01_without_measurement_contract_retained_in_audit' if self.legacy else
                'c01_unavailable_measurement_row_omitted' if not self.observed else
                'c01_not_before_and_record_wrapper_retained_in_audit'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer,
                'reason': 'c01_limit_represented_by_tls_observation_or_legacy_audit'})
            return True
        if collection == 'causes' and value.get('id') in self.limit_facts:
            kind, facts = self.limit_facts[value['id']]
            eid = document.add(kind, value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            self.projected[eid] = deepcopy(facts)
            return True
        return False

    def visible_occurrence(self, occurrence):
        if self.item is not None and not self.observed and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [identifier for identifier in occurrence['affected_signal_ids']
                                                  if identifier != C01]
        return occurrence

    def trim_omitted_references(self, original, result):
        recorded = (original.get('occurrence') or {}).get('affected_signal_ids', [])
        occurrence = result['occurrence']
        if (self.item is not None and not self.observed and C01 in recorded
                and occurrence.get('affected_signal_ids') == []):
            # The reference was deliberately omitted, not absent in the record.
            occurrence.pop('affected_signal_ids')
            if result.get('affected_checks') == 'not_recorded':
                result.pop('affected_checks')
        return result


def validate_c01_selection(context):
    measurements = []
    for row in context.get('evidence', []):
        kind, facts = row.get('kind'), row.get('facts', {})
        if kind == 'check' and _is_c01(facts):
            raise ValueError('c01_record_wrapper_leaked_to_model_context')
        if kind == 'certificate_age':
            measurements.append(row)
            if set(facts) != {AGE_LABEL, TIME_LABEL, 'certificate_ref'}:
                raise ValueError('invalid_c01_model_fields')
            age = facts[AGE_LABEL]
            suffix = r'유효기간 시작 전; 시간차를 24시간 단위로 내림한 값' if context.get('model_context_version', 'decision-evidence-11') in {'decision-evidence-7', 'decision-evidence-8', 'decision-evidence-9', 'decision-evidence-10', 'decision-evidence-11'} else r'유효기간 시작 전(?:; 시간차를 24시간 단위로 내림한 값)?'
            if not isinstance(age, str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)일|-[1-9][0-9]*일 \('+suffix+r'\)', age):
                raise ValueError('invalid_c01_elapsed_days')
            try:
                measured_at = datetime.fromisoformat(facts[TIME_LABEL])
                if measured_at.utcoffset() is None:
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError('invalid_c01_measurement_time') from None
            if 'certificate_ref' in facts:
                ref = facts['certificate_ref']
                target = next((r for r in context.get('evidence', []) if r.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
                if not target or set(ref) != {'evidence_ref'} or target.get('kind') != 'technical' or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                    raise ValueError('invalid_c01_certificate_reference')
        elif kind in {'certificate_age_limit', 'tls_observation_limit'}:
            allowed = {C01_MISSING, C01_FAILED} if kind == 'certificate_age_limit' else {TLS_MISSING}
            if set(facts) - {'관측 한계', '이유'} or facts.get('관측 한계') not in allowed:
                raise ValueError('invalid_c01_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c01_model_limit_reason')
    if len(measurements) > 1:
        raise ValueError('duplicate_c01_measurement')


C02 = 'L2-C-02'
VALIDITY_LABEL = '인증서 유효기간 상태'
VALIDITY_TEXT = {'valid': '검사 당시 유효기간 내', 'expired': '검사 당시 만료됨',
                 'not_valid': '검사 당시 유효기간 시작 전'}
C02_FAILED = '인증서 유효기간 검사 실패'
C02_UNRECORDED = '인증서 유효기간 검사 결과가 없으며 사유도 기록되지 않음'


def _is_c02(value):
    return value.get('layer') == 'l2' and (
        value.get('id') == C02 or value.get('name') == 'certificate_validity')


class C02Selection:
    def __init__(self, source):
        selected = [item for item in source.get('observations', []) if _is_c02(item)]
        if len(selected) > 1:
            raise ValueError('duplicate_l2_c02_observation')
        self.item = selected[0] if selected else None
        self.projected = {}
        self.limit_facts = {}
        self.absent_certificate_causes = set()
        self.status = (self.item.get('evidence') or {}).get('status') if self.item else None
        if self.item is None:
            return
        tls = source.get('l2_tls_source') or {}
        leaf = tls.get('leaf_certificate') or {}
        certificate_absent = 'leaf_certificate' in tls and not leaf
        self.tls_limit_recorded = any(cause['id'] in self.item.get('cause_ids', [])
            and (cause.get('occurrence') or {}).get('stage') == 'tls'
            and (cause.get('occurrence') or {}).get('impact_scope') == 'acquisition'
            for cause in source.get('causes', []))
        if self.status is not None:
            if not isinstance(self.status, str) or self.status not in VALIDITY_TEXT:
                raise ValueError('invalid_c02_recorded_status')
            if self.item.get('detected') is not (self.status != 'valid'):
                raise ValueError('inconsistent_c02_recorded_status')
            evidence = self.item['evidence']
            if not leaf or any(not evidence.get(key) or leaf.get(key) != evidence[key]
                               for key in ('not_before', 'not_after')):
                raise ValueError('c02_raw_result_mismatch')
        elif self.item.get('detected') is not None:
            raise ValueError('inconsistent_c02_recorded_status')
        # Shared TLS occurrences remain shared. Only a recorded C02-specific
        # analysis cause receives a compact description; no absence is diagnosed.
        for cause in source.get('causes', []):
            users = [item for item in source.get('observations', [])
                     if cause['id'] in item.get('cause_ids', [])]
            if not users or not all(_is_c02(item) for item in users):
                continue
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
            if detail.get('code') == 'analyzer_failed':
                facts = {'관측 한계': C02_FAILED}
                reason = detail.get('error') or detail.get('message')
                if isinstance(reason, str) and reason:
                    facts['이유'] = reason
                self.limit_facts[cause['id']] = facts
            elif detail.get('code') == 'analysis_unresolved_reason_not_recorded':
                if certificate_absent:
                    self.absent_certificate_causes.add(cause['id'])
                else:
                    self.limit_facts[cause['id']] = {'관측 한계': C02_UNRECORDED}

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _is_c02(value):
            if self.status is not None:
                facts = {VALIDITY_LABEL: VALIDITY_TEXT[self.status],
                         'certificate_ref': document.ref('technical', 'tls-identity')}
                eid = document.add('certificate_validity', value, pointer)
                document.lookup[('check', C02)].append(document.definitions[-1])
                self.projected[eid] = facts
            document.model_omissions.append({'source': pointer, 'reason':
                'c02_dates_and_record_wrapper_retained_in_audit' if self.status is not None else
                'c02_unavailable_result_row_omitted_recorded_causes_retained'})
            return True
        if collection == 'causes' and value.get('id') in self.absent_certificate_causes:
            # C01 plans its limits before registration, so source ordering does
            # not determine whether a common certificate-absence fact is reused.
            shared_absence = any(kind == 'tls_observation_limit' and facts.get('관측 한계') == TLS_MISSING
                                 for kind, facts in document.c01.limit_facts.values())
            if not self.tls_limit_recorded and not shared_absence:
                eid = document.add('tls_observation_limit', value, pointer)
                document.lookup[('limitation', value['id'])].append(document.definitions[-1])
                self.projected[eid] = {'관측 한계': TLS_MISSING}
            document.model_omissions.append({'source': pointer,
                'reason': 'c02_unrecorded_reason_retained_in_audit_certificate_absence_shared_in_tls'})
            return True
        if collection == 'causes' and value.get('id') in self.limit_facts:
            eid = document.add('certificate_validity_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            self.projected[eid] = deepcopy(self.limit_facts[value['id']])
            return True
        return False

    def visible_occurrence(self, occurrence):
        if self.item is not None and self.status is None and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [identifier for identifier in occurrence['affected_signal_ids']
                                                  if identifier != C02]
        return occurrence

    def trim_omitted_references(self, original, result):
        recorded = (original.get('occurrence') or {}).get('affected_signal_ids', [])
        occurrence = result['occurrence']
        if (self.item is not None and self.status is None and C02 in recorded
                and occurrence.get('affected_signal_ids') == []):
            occurrence.pop('affected_signal_ids')
            if result.get('affected_checks') == 'not_recorded':
                result.pop('affected_checks')
        return result


def validate_c02_selection(context):
    results = []
    for row in context.get('evidence', []):
        kind, facts = row.get('kind'), row.get('facts', {})
        if kind == 'check' and _is_c02(facts):
            raise ValueError('c02_record_wrapper_leaked_to_model_context')
        if kind == 'certificate_validity':
            results.append(row)
            if set(facts) != {VALIDITY_LABEL, 'certificate_ref'}:
                raise ValueError('invalid_c02_model_fields')
            if facts[VALIDITY_LABEL] not in VALIDITY_TEXT.values():
                raise ValueError('invalid_c02_model_status')
            ref = facts['certificate_ref']
            target = next((r for r in context.get('evidence', []) if r.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
            if not target or set(ref) != {'evidence_ref'} or target.get('kind') != 'technical' or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                raise ValueError('invalid_c02_certificate_reference')
        elif kind == 'certificate_validity_limit':
            if set(facts) - {'관측 한계', '이유'} or facts.get('관측 한계') not in {C02_FAILED, C02_UNRECORDED}:
                raise ValueError('invalid_c02_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c02_model_limit_reason')
    if len(results) > 1:
        raise ValueError('duplicate_c02_result')


C03 = 'L2-C-03'
OLD_NAME_LABEL = '인증서 이름 대조'
NAME_LABEL = 'TLS 접속 호스트와 인증서 이름 대조'
NAME_GUIDE_LABEL = '인증서 이름 대조 기준'
NAME_GUIDES = {'typed_SAN': 'DNS 호스트는 SAN의 DNS 이름과, IP 호스트는 SAN의 IP 주소와 대조함. 문자열이 같아도 이름 유형이 다르면 일치하지 않음.',
    'legacy_CN_fallback_not_browser_acceptance': 'SAN이 없어 인증서 주체의 CN 이름으로 보완 대조한 결과이며, 브라우저의 인증서 수락을 뜻하지 않음.'}
MATCHED_NAME_LABEL = '일치한 인증서 이름'
DNS_NAMES_LABEL = '인증서에 기록된 DNS 이름'
IP_NAMES_LABEL = '인증서에 기록된 IP 주소'
UNTYPED_NAMES_LABEL = '인증서에 기록된 SAN 이름 (유형 미기록)'
SAN_EMPTY_LABEL = '인증서 SAN 이름'
SAN_EMPTY_TEXT = '기록된 DNS 이름과 IP 주소 없음'
UNTYPED_EMPTY_TEXT = '기록된 SAN 이름 없음 (유형 미기록)'
NAME_SCOPES = {'typed_SAN': 'SAN 기준',
    'legacy_CN_fallback_not_browser_acceptance': 'SAN 없이 CN으로 보완 대조',
    'historical_SAN_types_unavailable': '과거 SAN 목록 기준; 이름 유형 미기록',
    None: '대조 방식 미기록'}
C03_FAILED = '인증서 이름 대조 실패'
C03_UNRECORDED = '인증서 이름 대조 결과가 없으며 사유도 기록되지 않음'
C03_TYPES_MISSING = '인증서 이름의 DNS/IP 유형이 기록되지 않아 이름 대조 결과가 없음'
C03_HOST_MISSING = '인증서를 조회한 호스트명이 기록되지 않음'


def _is_c03(value):
    return value.get('layer') == 'l2' and (
        value.get('id') == C03 or value.get('name') == 'hostname_certificate_match')


class C03Selection:
    def __init__(self, source):
        selected = [(i, item) for i, item in enumerate(source.get('observations', [])) if _is_c03(item)]
        if len(selected) > 1:
            raise ValueError('duplicate_l2_c03_observation')
        self.selected = selected
        self.item = selected[0][1] if selected else None
        self.projected = {}
        self.limit_facts = {}
        self.absent_certificate_causes = set()
        self.technical_additions = {}
        if self.item is None:
            return
        evidence = self.item.get('evidence') or {}
        matched = evidence.get('matched')
        scope = evidence.get('comparison_scope')
        tls = source.get('l2_tls_source') or {}
        leaf = tls.get('leaf_certificate') or {}
        self.tls_limit_recorded = any(cause['id'] in self.item.get('cause_ids', [])
            and (cause.get('occurrence') or {}).get('stage') == 'tls'
            and (cause.get('occurrence') or {}).get('impact_scope') == 'acquisition'
            for cause in source.get('causes', []))
        if matched is not None:
            if type(matched) is not bool or self.item.get('detected') is not (not matched):
                raise ValueError('inconsistent_c03_recorded_result')
            if not isinstance(scope, (str, type(None))) or scope not in NAME_SCOPES:
                raise ValueError('invalid_c03_comparison_scope')
            host = evidence.get('hostname')
            if not leaf or not isinstance(host, str) or not host or tls.get('hostname') != host:
                raise ValueError('c03_raw_target_mismatch')
            text = '일치' if matched else '불일치'
            self.technical_additions[NAME_LABEL] = f'{text} ({NAME_SCOPES[scope]})'
            if scope in NAME_GUIDES:
                self.technical_additions[NAME_GUIDE_LABEL] = NAME_GUIDES[scope]
            if matched:
                name = evidence.get('matched_name')
                if not isinstance(name, str) or not name:
                    raise ValueError('c03_matched_name_missing')
                if name != host:
                    self.technical_additions[MATCHED_NAME_LABEL] = name
            elif scope != 'legacy_CN_fallback_not_browser_acceptance':
                # Quote the recorded certificate names; never reconstruct the
                # analyzer's candidate list or parse the hostname/CN here.
                if 'san_present' in leaf:
                    for key, label in [('san_dns', DNS_NAMES_LABEL), ('san_ip', IP_NAMES_LABEL)]:
                        names = leaf.get(key)
                        if not isinstance(names, list) or any(not isinstance(x, str) or not x for x in names):
                            raise ValueError('c03_recorded_san_names_missing')
                        if names:
                            self.technical_additions[label] = deepcopy(names)
                    if not leaf['san_dns'] and not leaf['san_ip']:
                        self.technical_additions[SAN_EMPTY_LABEL] = SAN_EMPTY_TEXT
                elif 'san' in leaf:
                    names = leaf['san']
                    if not isinstance(names, list) or any(not isinstance(x, str) or not x for x in names):
                        raise ValueError('invalid_c03_recorded_san_names')
                    if names:
                        self.technical_additions[UNTYPED_NAMES_LABEL] = deepcopy(names)
                    else:
                        self.technical_additions[SAN_EMPTY_LABEL] = UNTYPED_EMPTY_TEXT
        elif self.item.get('detected') is not None:
            raise ValueError('inconsistent_c03_recorded_result')
        for cause in source.get('causes', []):
            users = [item for item in source.get('observations', []) if cause['id'] in item.get('cause_ids', [])]
            if not users or not all(_is_c03(item) for item in users):
                continue
            if (cause.get('occurrence') or {}).get('impact_scope') != 'analysis':
                continue
            detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
            if detail.get('code') == 'analyzer_failed':
                facts = {'관측 한계': C03_FAILED}
                reason = detail.get('error') or detail.get('message')
                if isinstance(reason, str) and reason:
                    facts['이유'] = reason
                self.limit_facts[cause['id']] = facts
            elif detail.get('code') == 'analysis_unresolved_reason_not_recorded':
                if 'leaf_certificate' in tls and not leaf:
                    self.absent_certificate_causes.add(cause['id'])
                elif scope == 'historical_SAN_types_unavailable' and matched is None:
                    self.limit_facts[cause['id']] = {'관측 한계': C03_TYPES_MISSING}
                elif 'hostname' in tls and not tls['hostname'] and leaf:
                    self.limit_facts[cause['id']] = {'관측 한계': C03_HOST_MISSING}
                else:
                    self.limit_facts[cause['id']] = {'관측 한계': C03_UNRECORDED}

    def register(self, collection, value, pointer, document):
        if collection == 'technical_facts' and value.get('id') == 'tls-identity':
            document.add('technical', value, pointer)
            if self.item is not None:
                document.lookup[('check', C03)].append(document.definitions[-1])
                document.definitions[-1]['source_pointers'].append(f'/observations/{self.selected[0][0]}')
            document.model_omissions.append({'source': pointer,
                'reason': 'c03_raw_names_and_duplicate_comparison_fields_retained_in_audit'})
            return True
        if collection == 'observations' and _is_c03(value):
            if self.technical_additions and not document.lookup.get(('technical', 'tls-identity')):
                raise ValueError('c03_result_without_certificate_context')
            document.model_omissions.append({'source': pointer,
                'reason': 'c03_record_wrapper_represented_in_shared_certificate_context' if self.technical_additions else
                          'c03_unavailable_result_omitted_recorded_limits_retained'})
            return True
        if collection == 'causes' and value.get('id') in self.absent_certificate_causes:
            shared_absence = any(kind == 'tls_observation_limit' and facts.get('관측 한계') == TLS_MISSING
                                 for kind, facts in document.c01.limit_facts.values())
            shared_absence = shared_absence or bool(document.c02.absent_certificate_causes)
            if not self.tls_limit_recorded and not shared_absence:
                eid = document.add('tls_observation_limit', value, pointer)
                document.lookup[('limitation', value['id'])].append(document.definitions[-1])
                self.projected[eid] = {'관측 한계': TLS_MISSING}
            document.model_omissions.append({'source': pointer,
                'reason': 'c03_unrecorded_reason_retained_in_audit_certificate_absence_shared_in_tls'})
            return True
        if collection == 'causes' and value.get('id') in self.limit_facts:
            eid = document.add('certificate_name_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            facts = deepcopy(self.limit_facts[value['id']])
            if document.lookup.get(('technical', 'tls-identity')):
                facts['certificate_ref'] = document.ref('technical', 'tls-identity')
            self.projected[eid] = facts
            return True
        return False

    def prepare_technical(self, value):
        if value.get('kind') != 'certificate_identity_comparison':
            return value
        value['scope'] = '표시된 호스트를 대상으로 한 TLS 관측 정보이며 HTTP 응답 수집과는 별도다. 이 정보만으로 사이트 운영자나 브랜드 소유 관계를 확인할 수 없다.'
        for key in ('hostname_match', 'matched_name', 'certificate_alternative_names'):
            value.pop(key, None)
        if 'source_evidence_ids' in value:
            value['source_evidence_ids'] = [x for x in value['source_evidence_ids'] if x != C03]
            if not value['source_evidence_ids']:
                value.pop('source_evidence_ids')
        return value

    def finish_technical(self, facts):
        if facts.get('kind') == 'certificate_identity_comparison':
            facts.update(deepcopy(self.technical_additions))
        return facts

    def visible_occurrence(self, occurrence):
        if self.item is not None and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C03]
        return occurrence

    def trim_omitted_references(self, original, result):
        recorded = (original.get('occurrence') or {}).get('affected_signal_ids', [])
        occurrence = result['occurrence']
        if self.item is not None and C03 in recorded and occurrence.get('affected_signal_ids') == []:
            occurrence.pop('affected_signal_ids')
            if result.get('affected_checks') == 'not_recorded':
                result.pop('affected_checks')
        return result


def validate_c03_selection(context):
    count = 0
    modern = context.get('model_context_version', 'decision-evidence-11') in {'decision-evidence-7', 'decision-evidence-8', 'decision-evidence-9', 'decision-evidence-10', 'decision-evidence-11'}
    name_label = NAME_LABEL if modern else OLD_NAME_LABEL
    labels = {f'{state} ({scope})' for state in ('일치', '불일치') for scope in NAME_SCOPES.values()}
    lists = {DNS_NAMES_LABEL, IP_NAMES_LABEL, UNTYPED_NAMES_LABEL}
    removed = {'hostname_match', 'matched_name', 'certificate_alternative_names',
               'matched', 'detected', 'comparison_scope', 'hostname', 'assessment', 'evidence', 'state'}
    for row in context.get('evidence', []):
        kind, facts = row.get('kind'), row.get('facts', {})
        if kind == 'check' and _is_c03(facts):
            raise ValueError('c03_record_wrapper_leaked_to_model_context')
        if kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison':
            if modern and OLD_NAME_LABEL in facts:
                raise ValueError('c03_ambiguous_label_reintroduced')
            if (set(facts) & removed or any(set(facts.get(key, [])) & removed
                    for key in ('not_recorded', 'no_entries_recorded'))):
                raise ValueError('c03_duplicate_fields_leaked_to_model_context')
            if name_label not in facts:
                if set(facts) & (lists | {MATCHED_NAME_LABEL, SAN_EMPTY_LABEL}):
                    raise ValueError('c03_names_without_result')
                continue
            count += 1
            text = facts[name_label]
            if modern:
                expected = next((NAME_GUIDES[scope] for scope in NAME_GUIDES if text.endswith('('+NAME_SCOPES[scope]+')')), None)
                if facts.get(NAME_GUIDE_LABEL) != expected:
                    raise ValueError('invalid_c03_comparison_guide')
            if not isinstance(text, str) or text not in labels or not isinstance(facts.get('inspected_host'), str) or not facts['inspected_host']:
                raise ValueError('invalid_c03_model_result')
            matched = text.startswith('일치 ')
            if MATCHED_NAME_LABEL in facts:
                name = facts[MATCHED_NAME_LABEL]
                if not matched or not isinstance(name, str) or not name or name == facts['inspected_host']:
                    raise ValueError('invalid_c03_matched_name')
            names = set(facts) & (lists | {SAN_EMPTY_LABEL})
            if names and (matched or 'CN으로' in text):
                raise ValueError('c03_unnecessary_san_names')
            if SAN_EMPTY_LABEL in names and (names != {SAN_EMPTY_LABEL} or facts[SAN_EMPTY_LABEL] not in {SAN_EMPTY_TEXT, UNTYPED_EMPTY_TEXT}):
                raise ValueError('invalid_c03_empty_san_names')
            if UNTYPED_NAMES_LABEL in names and names != {UNTYPED_NAMES_LABEL}:
                raise ValueError('c03_mixed_san_types')
            for label in names & lists:
                values = facts[label]
                if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
                    raise ValueError('invalid_c03_model_names')
        elif kind == 'certificate_name_limit':
            if set(facts) - {'관측 한계', '이유', 'certificate_ref'} or facts.get('관측 한계') not in {C03_FAILED, C03_UNRECORDED, C03_TYPES_MISSING, C03_HOST_MISSING}:
                raise ValueError('invalid_c03_model_limit')
            if '이유' in facts and (not isinstance(facts['이유'], str) or not facts['이유']):
                raise ValueError('invalid_c03_model_limit_reason')
            if 'certificate_ref' in facts:
                ref = facts['certificate_ref']
                target = next((x for x in context.get('evidence', []) if x.get('id') == ref.get('evidence_ref')), None) if isinstance(ref, dict) else None
                if not target or set(ref) != {'evidence_ref'} or target.get('kind') != 'technical' or target.get('facts', {}).get('kind') != 'certificate_identity_comparison':
                    raise ValueError('invalid_c03_certificate_reference')
    if count > 1:
        raise ValueError('duplicate_c03_model_result')
