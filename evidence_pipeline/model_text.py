"""Approved layer text, assembled once for review and the Messages user body.

Structured selection and its provenance remain internal. Output response binding
and unreviewed L3 selections are separate contracts, never silently approximated.
"""
from dataclasses import asdict, dataclass
import hashlib

from .context_inventory import restore
from .model_context import validate_model_context
from .text_blocks import TextBlock, field

VERSION = 'layer-text-1'


class TextContextNotReady(ValueError):
    pass


@dataclass
class TextContext:
    body: str
    blocks: list[TextBlock]
    source_map: list[dict]
    source_context: dict
    version: str = VERSION

    def audit(self):
        mapped = {eid for item in self.source_map for eid in item['source_evidence_ids']}
        return {'format': self.version, 'body_sha256': hashlib.sha256(self.body.encode()).hexdigest(),
                'source_map': self.source_map, 'blocks': [asdict(b) for b in self.blocks],
                'internal_context': self.source_context,
                'internal_only_rows': [row['id'] for row in self.source_context['evidence']
                                       if row['id'] not in mapped],
                'model_response_binding': 'not_implemented',
                'unreviewed_layers': self.source_context.get('unreviewed_layers', ['l3'])}


def render_text_context(context):
    from .l01_text import render_l0, render_l1
    from .l2_text import render_l2, KNOWN as L2_KINDS
    from .l0_context import KINDS as L0_KINDS
    from .l1_context import KINDS as L1_KINDS
    validate_model_context(context)
    source = restore(context)
    if source.get('url_activity_observation'):
        raise TextContextNotReady('orchestration_activity_text_not_reviewed')
    for row in source['evidence']:
        facts = row.get('facts', {})
        layer = facts.get('layer', (facts.get('occurrence') or {}).get('layer'))
        if layer == 'l3' or row['kind'] not in L0_KINDS | L1_KINDS | L2_KINDS:
            raise TextContextNotReady('l3_or_unreviewed_text_selection:' + row['kind'])
    blocks = []
    l0 = render_l0(source)
    urls = source.get('requested_urls')
    if not l0 and isinstance(urls, list) and urls:
        lines = []
        for url in urls:
            lines.extend(field('요청 URL', url))
        blocks.append(TextBlock('분석 대상', lines))
    blocks.extend(l0)
    blocks.extend(render_l1(source))
    blocks.extend(render_l2(source))
    if not blocks:
        raise TextContextNotReady('no_reviewed_layer_text')
    body, mapping = '', []
    for block in blocks:
        if not block.lines:
            raise ValueError('empty_text_block')
        rendered = '[' + block.title + ']\n' + '\n'.join(block.lines).strip('\n')
        if body:
            body += '\n\n'
        start = len(body)
        body += rendered
        mapping.append({'title': block.title, 'start': start, 'end': len(body),
                        'source_evidence_ids': list(block.evidence_ids)})
    body += '\n'
    mapped = {eid for item in mapping for eid in item['source_evidence_ids']}
    if any(row['id'] not in mapped and row['kind'] != 'coverage' for row in source['evidence']):
        raise ValueError('selected_evidence_missing_from_text_mapping')
    return TextContext(body, blocks, mapping, source)


def build_text_context(records, raws, *, audit=None, l3_scope=None,
                       html_text_chars=6000, html_max_bytes=200_000,
                       javascript_text_chars=1600, l3_native=None):
    if l3_scope == 'html_javascript':
        from .l3_content_text import build_l3_content_text_context
        return build_l3_content_text_context(records, raws, native=l3_native, audit=audit,
                                            html_text_chars=html_text_chars,
                                            javascript_text_chars=javascript_text_chars, max_bytes=html_max_bytes)
    if l3_native is not None:
        raise ValueError('native_input_requires_html_javascript_scope')
    if l3_scope is not None:
        if l3_scope != 'html':
            raise ValueError('unsupported_l3_text_scope')
        from copy import deepcopy
        from .l3_html_text import build_html_text_context, validate_input_bundle, assemble, VERSION as HTML_VERSION
        validate_input_bundle(records, raws)
        l3 = next((r for r in records if r['layer'] == 'l3'), None)
        if l3 is None:
            raise ValueError('html_context_requires_l3_record')
        html = build_html_text_context(l3, raws['l3'], text_chars=html_text_chars, max_bytes=html_max_bytes)
        base_records = [r for r in records if r['layer'] != 'l3']
        base_audit = {}
        base = build_text_context(base_records, {r['layer']: raws[r['layer']] for r in base_records},
                                  audit=base_audit) if base_records else None
        blocks = (base.blocks if base else []) + html.blocks
        body, mapping = assemble(blocks)
        if len(body.encode('utf-8')) > html_max_bytes:
            raise ValueError('html_text_context_budget_exceeded')
        source = deepcopy(html.source_context)
        if base:
            source['base_selected_context'] = deepcopy(base.source_context)
            source['evidence'] = deepcopy(base.source_context['evidence']) + source['evidence']
        source['html_review_input'].update(records=deepcopy(records), raws=deepcopy(raws))
        text = TextContext(body, blocks, mapping, source, HTML_VERSION)
        if audit is not None:
            audit.update(selection={'base': base_audit.get('selection'),
                                    'html': deepcopy(html.source_context)}, text=text.audit())
        return text
    from .context import build_context
    selected_audit = {}
    context = build_context(records, raws, audit=selected_audit)
    text = render_text_context(context)
    if audit is not None:
        audit.update(selection=selected_audit, text=text.audit())
    return text


def prepare_text_messages(context, gateway, system):
    """Return the same reviewed body in the real gateway's Messages envelope.

    This prepares the input only. It neither calls the provider nor applies the
    old E-ID response contract to a model that has not received those IDs.
    """
    document = context if isinstance(context, TextContext) else render_text_context(context)
    from .l3_javascript_text import VERSION as JS_VERSION, validate_javascript_text_document
    from .l3_content_text import VERSION as L3_VERSION, validate_l3_content_text_document
    from .l3_html_text import VERSION as HTML_VERSION, validate_html_text_document
    if document.version == JS_VERSION:
        validate_javascript_text_document(document)
    elif document.version == L3_VERSION:
        validate_l3_content_text_document(document)
    elif document.version == HTML_VERSION:
        validate_html_text_document(document)
    elif document.version == VERSION:
        rebuilt = render_text_context(document.source_context)
        if (document.body != rebuilt.body or [asdict(b) for b in document.blocks] != [asdict(b) for b in rebuilt.blocks]
                or document.source_map != rebuilt.source_map):
            raise ValueError('reviewed_text_body_or_mapping_changed')
    else:
        raise ValueError('unsupported_text_context_version')
    if any(marker in system for marker in ('basis_fact_id_', 'observed_fact_id_',
                                           'limitation_fact_id_', 'Cite only supplied IDs')):
        raise TextContextNotReady('legacy_id_response_prompt_with_text_input')
    request = gateway._payload(system, document.body)
    if request.get('messages', [{}])[-1].get('content') != document.body:
        raise ValueError('text_messages_body_mismatch')
    return document, request


def call_text_messages(context, gateway, system):
    """Use the Gateway transport with the exact reviewed body; return unvalidated output.

    The caller still owns response validation. This function does not publish a
    URL verdict or pretend that the future frontend evidence binding is settled.
    """
    import json
    document, expected = prepare_text_messages(context, gateway, system)
    result = gateway(system, document.body)
    captured = json.loads(gateway.last_request_body)
    if captured != expected:
        raise ValueError('text_gateway_request_mismatch')
    return result
