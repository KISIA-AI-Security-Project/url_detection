"""Compose reviewed HTML and JavaScript selections under one explicit contract."""
from copy import deepcopy
from dataclasses import asdict

from .l3_html_text import build_html_text_context, validate_input_bundle, validate_native_input, assemble
from .l3_javascript_text import build_javascript_text_context
from .records import canonical
from .text_blocks import TextBlock

VERSION = 'l3-content-text-1'


def build_l3_content_text_context(records, raws, *, native=None, audit=None,
                                  html_text_chars=6000, javascript_text_chars=1600, max_bytes=200_000):
    from .model_text import TextContext, build_text_context
    validate_input_bundle(records, raws)
    record = next((r for r in records if r['layer'] == 'l3'), None)
    if record is None:
        raise ValueError('l3_content_context_requires_l3_record')
    validate_native_input(record, raws['l3'], native)
    base_records = [r for r in records if r['layer'] != 'l3']
    base_audit = {}
    base = build_text_context(base_records, {r['layer']: raws[r['layer']] for r in base_records}, audit=base_audit) if base_records else None
    html = build_html_text_context(record, raws['l3'], native=native, text_chars=html_text_chars, max_bytes=max_bytes)
    js = build_javascript_text_context(record, raws['l3'], native=native, text_chars=javascript_text_chars, max_bytes=max_bytes)
    html_blocks, html_lines = deepcopy(html.blocks), deepcopy(html.source_context['line_map'])
    scope_rows = [r for r in html_lines if {'source': 'selection', 'pointer': '/scope'} in r['sources']]
    if len(scope_rows) != 1:
        raise ValueError('l3_content_html_scope_row_missing_or_ambiguous')
    row = scope_rows[0]
    row['text'] = '이 구획은 HTML 정적 선언과 제공된 구조 결과를 다룸. JavaScript 분석 결과는 이어지는 구획에서 함께 제공함.'
    block = next(b for b in html_blocks if b.title == row['title'])
    block.lines[row['line_in_block'] - 1] = row['text']
    for html_row in html_lines:
        for source in html_row['sources']:
            if source['source'] == 'selection' and source['pointer'] != '/scope':
                source['pointer'] = '/html' + source['pointer']

    # Share only the same normalized cause occurrence already represented in HTML.
    # Identical messages from different occurrences are deliberately kept apart.
    html_causes = {s['pointer'] for r in html_lines for s in r['sources']
                   if s['source'] == 'record' and s['pointer'].startswith('/causes/')}
    html_sources = {(s['source'], s['pointer']) for r in html_lines for s in r['sources']}
    # A classification failure and its explicitly bound HTML input are already
    # shown together in HTML. Share the richer JS-only subject label as well.
    shown_classification_targets = []
    for cause_index, cause in enumerate(record.get('causes') or []):
        cp = f'/causes/{cause_index}'
        target = (cause.get('detail') or {}).get('target') or {}
        if cause.get('code') != 'credential_classification_failed' or cp not in html_causes:
            continue
        matches = [i for i, field in enumerate((raws['l3'].get('html') or {}).get('inputs') or [])
                   if field.get('field_id') == target.get('field_id')
                   and (target.get('field_index') is None or target['field_index'] == i)]
        if len(matches) == 1:
            allowed = {('record', cp), ('raw', f'/html/inputs/{matches[0]}')}
            if allowed <= html_sources:
                shown_classification_targets.append(allowed)
    js_lines, js_blocks, shared_omissions = [], [], []
    for block in js.blocks:
        rows = [r for r in js.source_context['line_map'] if r['title'] == block.title]
        kept = []
        for original in rows:
            sources = original['sources']
            source_keys = {(s['source'], s['pointer']) for s in sources}
            same_classification_target = any(source_keys == allowed for allowed in shown_classification_targets)
            if sources and (all(s['source'] == 'record' and s['pointer'] in html_causes for s in sources)
                            or same_classification_target):
                for s in sources:
                    entry = {**s, 'reason': 'same normalized cause occurrence already shown with HTML; no duplicate JavaScript row'}
                    if entry not in shared_omissions:
                        shared_omissions.append(entry)
                continue
            changed = deepcopy(original)
            for source in changed['sources']:
                if source['source'] == 'selection':
                    source['pointer'] = '/javascript' + source['pointer']
            changed['line_in_block'] = len(kept) + 1
            kept.append(changed)
        if kept:
            js_blocks.append(TextBlock(block.title, [r['text'] for r in kept], block.evidence_ids, deepcopy(block.items)))
            js_lines.extend(kept)
    blocks = (deepcopy(base.blocks) if base else []) + html_blocks + js_blocks
    body, mapping = assemble(blocks)
    if len(body.encode('utf-8')) > max_bytes:
        raise ValueError('l3_content_text_context_budget_exceeded')
    source = {
        'evidence': (deepcopy(base.source_context['evidence']) if base else []) +
                    [{'id': s['id'], 'kind': 'l3_record', 'facts': deepcopy(s)} for s in record.get('signals', [])],
        'l3_raw': deepcopy(raws['l3']), 'l3_record': deepcopy(record), 'l3_native': deepcopy(native),
        'base_selected_context': deepcopy(base.source_context) if base else None,
        'base_selection_audit': deepcopy(base_audit.get('selection', {})),
        'line_map': html_lines + js_lines,
        'model_omissions': deepcopy(html.source_context['model_omissions']) + deepcopy(js.source_context['model_omissions']) + shared_omissions,
        'unreviewed_layers': [],
        'selection_contract': {
            'scope': 'HTML declarations and JavaScript static observations; optional L0/L1/L2 prefix',
            'html': deepcopy(html.source_context['selection_contract']),
            'javascript': deepcopy(js.source_context['selection_contract']),
            'composition': 'one scope contract; same normalized cause occurrences shared, distinct occurrences preserved',
        },
        'l3_review_input': {'records': deepcopy(records), 'raws': deepcopy(raws), 'native': deepcopy(native),
                            'html_text_chars': html_text_chars, 'javascript_text_chars': javascript_text_chars,
                            'max_bytes': max_bytes},
    }
    result = TextContext(body, blocks, mapping, source, VERSION)
    if audit is not None:
        audit.update(result.audit())
    return result


def validate_l3_content_text_document(document):
    inputs = document.source_context.get('l3_review_input')
    if not isinstance(inputs, dict):
        raise ValueError('l3_content_text_missing_review_input')
    rebuilt = build_l3_content_text_context(**inputs)
    if (document.version != VERSION or document.body != rebuilt.body or document.source_map != rebuilt.source_map
            or [asdict(b) for b in document.blocks] != [asdict(b) for b in rebuilt.blocks]):
        raise ValueError('l3_content_reviewed_body_or_mapping_changed')
    if canonical(document.source_context) != canonical(rebuilt.source_context):
        raise ValueError('l3_content_audit_input_or_selection_changed')
    return document
