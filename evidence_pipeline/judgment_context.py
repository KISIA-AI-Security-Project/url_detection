"""Requested-subject view with explicit recorded relationships.

Source values and IDs are preserved. The judge interprets their meaning.
Actual model-window selection happens through gateway tokenization.
"""
import json
from .context_source import build_context as build_source_context
from .records import canonical, digest
from .model_context import build_model_context

DEFAULT_MAX_BYTES = 400_000


def present_context(source, *, max_bytes=DEFAULT_MAX_BYTES, audit=None):
    context = build_model_context(json.loads(canonical(source)),audit=audit)
    from .context_tables import present as table_view
    from .context_inventory import restore
    explicit=context
    context=table_view(context)
    if canonical(restore(context))!=canonical(explicit):raise ValueError('model_context_table_mismatch')
    # Large repeated inventories are represented losslessly before the byte guard.
    # Token-window selection remains the gateway's responsibility.
    if len(canonical(context))>100_000:
        from .context_inventory import present,restore
        packed=present(context)
        if canonical(restore(packed))!=canonical(explicit):raise ValueError('model_context_packing_mismatch')
        context=packed
    data = json.dumps(context, ensure_ascii=False, separators=(',', ':')).encode()
    if len(data) > max_bytes:
        raise ValueError(f'context_budget_exceeded:{len(data)}>{max_bytes}')
    # Preserve the deliberate subject/document/relationship order in live input.
    context = json.loads(data)
    if audit is not None:
        audit.update({
            'context_sha256': digest(context),
            'source_context_sha256': digest(source),
            'evidence_references': {
                item['id']: item.get('record_reference')
                for item in source.get('observations', [])
            },
            'presentation': 'Decision evidence document. Storage provenance is external; facts are defined once and joined by short evidence IDs. No semantic verdict or new analysis.',
        })
    return context


def build_context(records, raws, *, max_bytes=DEFAULT_MAX_BYTES, audit=None):
    source = build_source_context(records, raws, max_bytes=max(4_000_000, max_bytes * 20))
    return present_context(source, max_bytes=max_bytes, audit=audit)
