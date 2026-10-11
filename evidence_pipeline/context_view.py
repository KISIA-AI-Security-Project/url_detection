"""Present evidence for judgment; keep storage references in a separate audit map.

No risk-based selection, verdict assignment, page-claim interpretation, or
fabrication of missing historical causes takes place here.
"""
from copy import deepcopy
from urllib.parse import urlsplit
from os.path import commonprefix
from .context_source import build_context as build_source_context
from .records import canonical, digest

DEFAULT_MAX_BYTES = 200_000
STATES = {'observed': 'found', 'not_observed_in_analyzed_scope': 'not_found',
          'unresolved': 'unresolved', 'not_applicable': 'not_applicable',
          'relationship_record_only': 'relationship'}
SCOPES = {
    'url': 'URL string analysis only; encoded strings do not establish execution.',
    'infrastructure': 'Lookup responses for the recorded target; platform infrastructure does not establish tenant or page trust.',
    'transport': 'Collected HTTP/TLS metadata; TLS uses its own connection and host. No file execution observed.',
    'document': 'Static HTML structure in the collected document; browser execution unobserved.',
    'script': 'Static script analysis; execution, conditional reachability and browser behavior unobserved unless explicitly recorded.',
}


def pack_rows(items):
    """Lossless tabular encoding for long, uniform inventories, without sampling."""
    if not isinstance(items, list) or len(items) < 12 or not all(isinstance(x, dict) for x in items):
        return items
    keys = list(items[0])
    if not all(set(x) == set(keys) for x in items):
        return items
    shared = {k: items[0][k] for k in keys if all(x[k] == items[0][k] for x in items[1:])}
    columns = [k for k in keys if k not in shared]
    prefixes = {}
    for k in columns:
        if k.endswith('url') and all(isinstance(x[k], str) for x in items):
            prefix = commonprefix([x[k] for x in items])
            if len(prefix) >= 20:
                prefixes[k] = prefix
    packed = {'columns': columns, 'shared': shared,
              'rows': [[x[k][len(prefixes[k]):] if k in prefixes else x[k] for k in columns] for x in items]}
    if prefixes:
        packed['prefixes'] = prefixes
    return packed if len(canonical(packed)) + 128 < len(canonical(items)) else items


def unpack_rows(value):
    """Restore the exact original records; used by validation and preservation checks."""
    if isinstance(value, dict) and {'columns', 'shared', 'rows'} <= set(value) <= {'columns', 'shared', 'rows', 'prefixes'}:
        return [{**value['shared'], **{k: value.get('prefixes', {}).get(k, '') + v if k in value.get('prefixes', {}) else v
                                      for k, v in zip(value['columns'], row, strict=True)}} for row in value['rows']]
    return value


def _origin_relation(document_url, destination):
    try:
        a, b = urlsplit(document_url), urlsplit(destination)
        if a.scheme not in {'http','https'} or b.scheme not in {'http','https'} or not a.hostname or not b.hostname:
            return {'same_host': None, 'same_origin': None}
        ah, bh = a.hostname.encode('idna').decode().lower(), b.hostname.encode('idna').decode().lower()
        return {'same_host': ah == bh,
                'same_origin': (a.scheme, ah, a.port if a.port is not None else (443 if a.scheme=='https' else 80)) ==
                               (b.scheme, bh, b.port if b.port is not None else (443 if b.scheme=='https' else 80))}
    except (ValueError, TypeError, UnicodeError):
        return {'same_host': None, 'same_origin': None}


def document_interactions(documents):
    """Join recorded form associations; never infer an unrecorded script flow."""
    result = []
    for doc in documents:
        inputs = unpack_rows(doc.get('inputs', []))
        buttons = unpack_rows(doc.get('buttons', []))
        forms = unpack_rows(doc.get('forms', []))
        for position, form in enumerate(forms):
            fid = form.get('form_id')
            if fid is None:
                continue
            if sum(f.get('form_id') == fid for f in forms) > 1:
                result.append({'id':'I'+str(len(result)+1),'document_id':doc['id'],'form_id':fid,'form_index':position,
                    'association_status':'unresolved_duplicate_form_id',
                    'scope':'The supplied form IDs are not unique; inputs and buttons cannot be assigned to this specific form by ID alone.',
                    'execution_observed':False})
                continue
            attached = [b for b in buttons if b.get('form_id') == fid]
            target = form.get('action_url') or form.get('effective_action_url')
            submissions = [{'source': 'form', 'target_url': target, 'method': form.get('method'),
                            **_origin_relation(doc.get('url'), target)}]
            for button in attached:
                if button.get('type') not in {'submit', 'image'}:
                    continue
                submissions.append({'source': 'button', 'button_id': button.get('button_id'),
                    'target_url': button.get('effective_action_url'), 'method': button.get('effective_method'),
                    'disabled': button.get('disabled'),
                    **_origin_relation(doc.get('url'), button.get('effective_action_url'))})
            result.append({'id': 'I' + str(len(result)+1), 'document_id': doc['id'], 'form_id': fid,
                'input_ids': [x.get('field_id') for x in inputs if x.get('form_id') == fid and x.get('field_id')],
                'button_ids': [b.get('button_id') for b in attached if b.get('button_id')],
                'submissions': submissions, 'execution_observed': False})
    return result


def _source_ids(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {'id','script_id','event_id','form_id','field_id','button_id','link_id','frame_id','image_id'} and isinstance(child, str):
                found.add(child)
            found.update(_source_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_source_ids(child))
    return found


def _scope(o):
    return {'l0': 'url', 'l1': 'infrastructure', 'l2': 'transport'}.get(o.get('layer'),
        'script' if str(o.get('id', '')).startswith('L3-J') else 'document')


def present_context(source, *, max_bytes=DEFAULT_MAX_BYTES, audit=None):
    """Reorganize a frozen evidence view without changing substantive facts.

    Null/empty values inside evidence remain: an empty observed collection is
    not interchangeable with an unavailable collection.
    """
    source = deepcopy(source)
    references, aliases = {}, {}
    reserved_ids = _source_ids(source)

    def alias(old, prefix, detail):
        if old not in aliases:
            number = 1 + sum(x.startswith(prefix) for x in references)
            new = prefix + str(number)
            while new in reserved_ids or new in references:
                number += 1
                new = prefix + str(number)
            aliases[old] = new
            references[new] = {'original_id': old, **deepcopy(detail)}
        return aliases[old]

    for o in source.get('observations', []):
        alias(o['id'], 'E', {'layer': o.get('layer'), 'record_reference': o.get('record_reference')})
    for d in source.get('documents', []):
        alias(d['id'], 'D', {'raw_reference': d.get('raw_reference')})
    for f in source.get('technical_facts', []):
        alias(f['id'], 'T', {'raw_reference': f.get('raw_reference')})
    for c in source.get('causes', []):
        alias(c['id'], 'C', {'cause': c})

    def rewrite(value, key=None):
        if isinstance(value, dict):
            return {k: rewrite(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v, key) for v in value]
        if key in {'cause_ids', 'source_evidence_ids'} and isinstance(value, str):
            return aliases.get(value, value)
        return value

    observations = []
    normalizations = {}
    for o in source.get('observations', []):
        item = {'id': aliases[o['id']], 'scope': _scope(o),
                'check': o.get('detector_predicate') or str(o.get('name') or o['id']).replace('_', ' '),
                'result': STATES.get(o.get('state'), o.get('state', 'unresolved'))}
        if o.get('evidence') is not None:
            item['facts'] = deepcopy(o['evidence'])
        if o.get('meaning') is not None:
            item['meaning'] = deepcopy(o['meaning'])
        if o.get('cause_ids'):
            item['cause_ids'] = [aliases[x] for x in o['cause_ids']]
        positive_checks = {'L2-C-03': ('matched', 'certificate hostname matches the inspected host'),
                           'L2-C-05': ('valid', 'certificate chain verification is valid')}
        if o['id'] in positive_checks:
            fact_key, label = positive_checks[o['id']]
            value = (o.get('evidence') or {}).get(fact_key)
            if isinstance(value, bool):
                normalizations[item['id']] = {'original_check': item['check'], 'original_result': item['result'],
                                             'source_fact': fact_key}
                item['check'] = label
                item['result'] = 'found' if value else 'not_found'
        observations.append(item)

    causes = []
    cause_types = source.get('cause_types', {})
    for c in source.get('causes', []):
        common = cause_types.get(c.get('type_id'), {})
        causes.append({'id': aliases[c['id']], **deepcopy(common),
                       'instance': deepcopy(c.get('instance', c.get('detail', {})))})
    for old, item in zip(source.get('observations', []), observations):
        if item['result'] == 'unresolved' and not item.get('cause_ids'):
            cid = alias('unrecorded-reason:' + old['id'], 'C', {'source_evidence_id': old['id']})
            causes.append({'id': cid, 'kind': 'reason_not_recorded',
                           'code': 'analysis_unresolved_reason_not_recorded',
                           'instance': {'check_id': item['id']},
                           'message': 'The stored result does not explain why this check is unresolved. No specific failure or site property can be inferred.'})
            item['cause_ids'] = [cid]

    documents = [rewrite({**{k: v for k, v in d.items() if k not in {'id','raw_reference'}}, 'id': aliases[d['id']]})
                 for d in source.get('documents', [])]
    technical = [rewrite({**{k: v for k, v in f.items() if k not in {'id','raw_reference'}}, 'id': aliases[f['id']]})
                 for f in source.get('technical_facts', [])]
    for document in documents:
        for key in ['image_texts', 'inputs', 'buttons', 'forms', 'links', 'frames', 'inline_handlers']:
            if key in document:
                document[key] = pack_rows(document[key])
    for observation in observations:
        facts = observation.get('facts')
        if isinstance(facts, dict) and 'resources' in facts:
            facts['resources'] = pack_rows(facts['resources'])
    layers = [{k: deepcopy(v) for k, v in layer.items() if k not in {'provenance', 'status'}}
              for layer in source.get('layers', [])]
    urls = list(dict.fromkeys(layer.get('target', {}).get('original_url')
                             for layer in source.get('layers', [])
                             if layer.get('target', {}).get('original_url')))
    mode = [{k: v for k, v in layer.get('provenance', {}).items() if k != 'scanner_time'}
            for layer in source.get('layers', [])]
    target = {'requested_url': urls[0] if len(urls) == 1 else None,
              'observed_document_urls': [d.get('url') for d in documents]}
    if len(urls) > 1:
        target['conflicting_recorded_request_urls'] = urls
    result = {
        'context_version': '2.0-experimental', 'question': source.get('question'),
        'target': target, 'evidence_boundary': deepcopy(source.get('evidence_boundary', {})),
        'documents': documents, 'document_interactions': document_interactions(documents),
        'behaviors': rewrite(source.get('behaviors', [])),
        'technical_facts': technical, 'observations': observations, 'causes': causes,
        'analysis_scopes': SCOPES.copy(),
        'result_meanings': {
            'found': 'The named check condition was found; this is not a maliciousness verdict.',
            'not_found': 'The named condition was not found within its analysis scope; this is not proof of absence or benignness.',
            'unresolved': 'The condition is not determined; read the specific cause, or the explicit lack of a recorded reason.',
            'not_applicable': 'This check was not applicable to the supplied evidence.',
            'relationship': 'Only the recorded relation is supplied; no detector decision is assigned.',
        },
        'layers': layers, 'observation_modes': mode,
        'script_coverage': rewrite(source.get('script_coverage', [])),
        'omissions': deepcopy(source.get('omissions', [])),
        'cause_encoding': 'Each cause ID preserves its own occurrence or recorded condition. Multiple checks sharing one cause are dependent observations, not independent risk evidence.',
        'inventory_encoding': 'In tabular inventories, columns name each row value, shared fields apply to every row, and a column prefix is prepended to its row value to reconstruct the full URL. All rows are included; no sampling or risk-based filtering is used.',
    }
    used = reserved_ids | set(references)
    for interaction in result['document_interactions']:
        number = 1
        while 'I' + str(number) in used:
            number += 1
        interaction['id'] = 'I' + str(number)
        used.add(interaction['id'])
    size = len(canonical(result))
    if size > max_bytes:
        raise ValueError(f'context_budget_exceeded:{size}>{max_bytes}')
    if audit is not None:
        audit.update({'source_context_sha256': digest(source), 'context_sha256': digest(result),
                      'evidence_references': references,
                      'source_layer_provenance': [l.get('provenance') for l in source.get('layers', [])],
                      'source_layer_statuses': {l.get('layer'): l.get('status') for l in source.get('layers', [])},
                      'check_result_normalizations': normalizations,
                      'presentation': 'All check facts, documents, behaviors, technical facts and limitations retained; duplicate detector booleans and storage metadata moved out of model input.'})
    return result


def build_context(records, raws, *, max_bytes=DEFAULT_MAX_BYTES, audit=None):
    # Verify source hashes and request/attempt identity before presentation.
    source = build_source_context(records, raws, max_bytes=max(4_000_000, max_bytes * 20))
    return present_context(source, max_bytes=max_bytes, audit=audit)
