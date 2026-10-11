"""One approved selection feeds model text, public facts and internal mappings."""
from copy import deepcopy
from hashlib import sha256
import json

from .model_text import build_text_context
from .records import digest
from .fast_mapping import normalize_sources

VERSION = 'fast-context-1'
BASIS_LABELS = {
    'url_structure': '입력 URL의 구조',
    'observed_response': '기록된 조회·응답',
    'static_declaration': 'HTML의 정적 선언',
    'static_relation': 'JavaScript의 정적 구문·관계',
    'policy_comparison': '설정된 정책과의 대조',
}


def _pointer(document, path):
    value = document
    for token in path.lstrip('/').split('/') if path else []:
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def _base_sources(eids, selection, artifact_refs):
    """Use the projection's own provenance, never infer from a displayed value."""
    rows = []
    source = selection.get('source_context', {})
    for eid in eids:
        definition = selection.get('evidence_mapping', {}).get(eid, {})
        for path in definition.get('source_pointers', []):
            row = {'source': 'selection_source', 'pointer': path, 'evidence_id': eid}
            try:
                original = _pointer(source, path)
            except (KeyError, IndexError, TypeError, ValueError):
                original = None
            if path.startswith('/l0_url_observations/'):
                part, _, pointer = path[len('/l0_url_observations/'):].partition('/')
                row.update(layer='l0', source=part, pointer='/' + pointer if pointer else '')
            elif isinstance(original, dict):
                for name in ('record_reference', 'raw_reference'):
                    if original.get(name):
                        row[name] = deepcopy(original[name])
                if original.get('layer'):
                    row['layer'] = original['layer']
            if row.get('layer') in artifact_refs:
                row['artifacts'] = deepcopy(artifact_refs[row['layer']])
            if row not in rows:
                rows.append(row)
    return rows


def build_fast_context(records, raws, *, native=None, artifact_refs=None, max_bytes=400_000):
    artifact_refs = artifact_refs or {}
    audit = {}
    has_l3 = any(r['layer'] == 'l3' for r in records)
    doc = build_text_context(records, raws, audit=audit,
                             l3_scope='html_javascript' if has_l3 else None,
                             l3_native=native, html_max_bytes=max_bytes)
    first = records[0]
    selection = (doc.source_context.get('base_selection_audit', {}) if has_l3
                 else audit.get('selection', {}))
    sections, facts, links, model_parts = [], [], [], []
    for block_index, block in enumerate(doc.blocks, 1):
        labels = []
        section_id = f's{block_index}'
        ids = []
        for item_index, entry in enumerate(block.items, 1):
            fact_id = f'{section_id}-f{item_index}'
            text = '\n'.join(entry['lines']).strip()
            if not text:
                continue
            labels.append(entry['item_label'])
            ids.append(fact_id)
            facts.append({'fact_id': fact_id, 'title': entry.get('public_title', entry['item_label']),
                          'kind': 'fact', 'text': text,
                          'basis': {'kind': entry['basis'], 'label': BASIS_LABELS[entry['basis']]},
                          'condition_fact_ids': []})
            if entry.get('plain') is not None:
                facts[-1]['plain'] = deepcopy(entry['plain'])
            sources = deepcopy(entry.get('sources', []))
            for source in sources:
                if source['source'] in {'raw', 'record'}:
                    source.update(layer='l3', artifacts=deepcopy(artifact_refs.get('l3', {})))
            sources += _base_sources(entry.get('evidence_ids', []), selection, artifact_refs)
            links.append({'section_title': block.title, 'item_label': entry['item_label'],
                          'fact_ids': [fact_id], 'sources': normalize_sources(sources, artifact_refs),
                          'source_evidence_ids': deepcopy(entry.get('evidence_ids', []))})
        if ids:
            sections.append({'section_id': section_id,
                             'title': block.items[0].get('public_section_title', block.title), 'fact_ids': ids})
        if not labels:
            links.append({'section_title': block.title, 'item_label': block.title,
                           'fact_ids': [], 'sources': [], 'source_evidence_ids': list(block.evidence_ids)})
        # Keep source-only limits readable without an empty public-link shell.
        # The absence of targets remains in the internal mapping above.
        catalog = ('공개 상세에 연결 가능한 항목 이름: ' + json.dumps(labels, ensure_ascii=False) + '\n') if labels else ''
        model_parts.append('[' + block.title + ']\n' + catalog + '\n'.join(block.lines))
    body = '\n\n'.join(model_parts) + '\n'
    if len(body.encode('utf-8')) > max_bytes:
        raise ValueError('fast_context_budget_exceeded')
    identity = {'job_id': first['request_id'], 'attempt': int(first['attempt'])}
    # Revision binds all three outputs, not just a prose hash.
    revision = digest({'identity': identity, 'body': body, 'facts': facts, 'links': links})
    l3_lines = deepcopy(doc.source_context.get('line_map', []))
    for line in l3_lines:
        line['sources'] = normalize_sources([{**p, 'layer': 'l3'} for p in line['sources']], artifact_refs)
    return {'schema_version': VERSION, **identity, 'context_revision': revision,
            'model_body': body, 'model_body_sha256': sha256(body.encode('utf-8')).hexdigest(),
            'details': {'context_revision': revision, 'sections': sections, 'facts': facts},
            'item_mapping': links,
            'source_mapping': {'artifacts': deepcopy(artifact_refs),
                               'projection': {k: deepcopy(selection[k]) for k in
                                              ('evidence_mapping', 'source_context') if k in selection},
                               'l3_lines': l3_lines,
                               'omissions': deepcopy(doc.source_context.get('model_omissions', []))}}
