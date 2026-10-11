"""Keep C07 in record/audit; omit it from the malicious-URL judgment document."""

C07 = 'L2-C-07'


def _owned(value):
    return value.get('layer') == 'l2' and (value.get('id') == C07 or value.get('name') == 'tls_version')


class C07Selection:
    def __init__(self, source):
        observations = source.get('observations', [])
        self.omitted_causes = set()
        for cause in source.get('causes', []):
            users = [o for o in observations if cause['id'] in o.get('cause_ids', [])]
            occurrence = cause.get('occurrence') or {}
            # Retain collection failures, even when C07 is their only consumer.
            if (users and all(_owned(o) for o in users)
                    and occurrence.get('impact_scope') == 'analysis'
                    and not set(occurrence.get('affected_signal_ids', [])) - {C07}):
                self.omitted_causes.add(cause['id'])

    def omit(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            document.model_omissions.append({'source': pointer,
                'reason': 'c07_tls_version_retained_in_record_and_audit_excluded_from_url_judgment'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer,
                'reason': 'c07_only_analysis_limit_retained_in_record_and_audit'})
            return True
        return False

    @staticmethod
    def visible_occurrence(occurrence):
        if isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C07]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def validate_c07_selection(context):
    for row in context.get('evidence', []):
        facts = row.get('facts') or {}
        kind = row.get('kind')
        if kind == 'check' and _owned(facts):
            raise ValueError('c07_check_leaked_to_model_context')
        # Do not inspect page text or other untrusted content for matching words.
        if (kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison'
                or kind == 'check' and facts.get('layer') == 'l2'):
            if ('tls_version' in facts or 'tls_version' in (facts.get('evidence') or {})
                    or 'tls_version' in facts.get('not_recorded', [])):
                raise ValueError('c07_tls_version_leaked_to_model_context')
        if kind == 'limitation':
            occurrence = facts.get('occurrence') or {}
            if C07 in occurrence.get('affected_signal_ids', []):
                raise ValueError('omitted_c07_reference_leaked_to_model_context')
            detail = facts.get('observed_detail') or {}
            if occurrence.get('layer') == 'l2' and ('tls_version' in detail or 'tls_version' in detail.get('not_recorded', [])):
                raise ValueError('c07_tls_version_leaked_to_model_limit')
            refs = facts.get('affected_checks')
            if (detail.get('analyzer') == C07 and occurrence.get('impact_scope') == 'analysis'
                    and not (isinstance(refs, list) and refs)):
                raise ValueError('c07_only_analysis_limit_leaked_to_model_context')
