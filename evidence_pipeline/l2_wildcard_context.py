"""Omit standalone C08 metadata while preserving C03's certificate-name relation."""

C08 = 'L2-C-08'
OMITTED = {'L2-C-07', C08}
FIELDS = {'wildcard_names', 'san_count'}


def _owned(value):
    return value.get('layer') == 'l2' and (value.get('id') == C08 or value.get('name') == 'wildcard_certificate')


class C08Selection:
    def __init__(self, source):
        self.observations = source.get('observations', [])
        self.omitted_causes = set()
        for cause in source.get('causes', []):
            users = [o for o in self.observations if cause['id'] in o.get('cause_ids', [])]
            occurrence = cause.get('occurrence') or {}
            if (users and any(_owned(o) for o in users)
                    and all(o.get('layer') == 'l2' and o.get('id') in OMITTED for o in users)
                    and occurrence.get('impact_scope') == 'analysis'
                    and not set(occurrence.get('affected_signal_ids', [])) - OMITTED):
                self.omitted_causes.add(cause['id'])

    def omit(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            document.model_omissions.append({'source': pointer,
                'reason': 'c08_wildcard_metadata_retained_in_record_and_audit_c03_relation_preserved'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer,
                'reason': 'c07_c08_only_analysis_limit_retained_in_record_and_audit'})
            return True
        return False

    def retained_refs(self, cause, document):
        users = [o for o in self.observations if cause['id'] in o.get('cause_ids', [])]
        if not any(_owned(o) for o in users):
            return []
        # Selected C03 facts have a technical-row alias instead of a check row.
        refs = [document.ref('check', o['id']) for o in users if o.get('id') not in OMITTED]
        return [ref for ref in refs if 'evidence_ref' in ref]

    @staticmethod
    def visible_occurrence(occurrence):
        if isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x != C08]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def _has_fields(value):
    return bool(set(value) & FIELDS or set(value.get('not_recorded', [])) & FIELDS
                or set(value.get('no_entries_recorded', [])) & FIELDS)


def validate_c08_selection(context):
    for row in context.get('evidence', []):
        facts, kind = row.get('facts') or {}, row.get('kind')
        if kind == 'check' and _owned(facts):
            raise ValueError('c08_check_leaked_to_model_context')
        if (kind == 'technical' and facts.get('kind') == 'certificate_identity_comparison'
                or kind == 'check' and facts.get('layer') == 'l2'):
            if _has_fields(facts) or _has_fields(facts.get('evidence') or {}):
                raise ValueError('c08_metadata_leaked_to_model_context')
        if kind == 'limitation':
            occurrence, detail = facts.get('occurrence') or {}, facts.get('observed_detail') or {}
            if C08 in occurrence.get('affected_signal_ids', []):
                raise ValueError('omitted_c08_reference_leaked_to_model_context')
            if occurrence.get('layer') == 'l2' and _has_fields(detail):
                raise ValueError('c08_metadata_leaked_to_model_limit')
            refs = facts.get('affected_checks')
            if (detail.get('analyzer') == C08 and occurrence.get('impact_scope') == 'analysis'
                    and not (isinstance(refs, list) and refs)):
                raise ValueError('c08_only_analysis_limit_leaked_to_model_context')
