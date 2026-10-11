"""Translate recorded provenance into an explicit stored JSON location.

Used for the internal deep-analysis handoff, never to validate an LLM citation.
"""
from copy import deepcopy


def location(layer, source, pointer, artifacts):
    refs = artifacts.get(layer, {})
    if source not in {'raw', 'record'} or source not in refs:
        return None
    root = refs.get(source + '_root_pointer', '')
    return {'layer': layer, 'source': source, 'key': refs[source],
            'artifact_pointer': root + pointer}


def normalize_sources(sources, artifacts):
    result = deepcopy(sources)
    known_keys = {f'{kind}-{layer}.json': (layer, kind)
                  for layer in ('l0', 'l1', 'l2', 'l3') for kind in ('raw', 'record')}
    raw_paths = {'/l1_raw': ('l1', ''), '/l2_http_source': ('l2', '/http'),
                 '/l2_tls_source': ('l2', '/tls'), '/l2_ct_source': ('l2', '/ct')}
    for row in result:
        locations = []
        if row.get('source') in {'raw', 'record'}:
            found = location(row.get('layer'), row['source'], row['pointer'], artifacts)
            if found:
                locations.append(found)
        elif row.get('source') == 'selection_source':
            for prefix, (layer, raw_pointer) in raw_paths.items():
                if row['pointer'] == prefix or row['pointer'].startswith(prefix + '/'):
                    found = location(layer, 'raw', raw_pointer + row['pointer'][len(prefix):], artifacts)
                    if found:
                        locations.append(found)
            for field in ('record_reference', 'raw_reference'):
                reference = row.get(field)
                if isinstance(reference, dict) and reference.get('key') in known_keys:
                    layer, source = known_keys[reference['key']]
                    pointer = reference.get('pointer', '')
                    # The existing producer uses '/' for the complete raw object.
                    if source == 'raw' and pointer == '/':
                        pointer = ''
                    found = location(layer, source, pointer, artifacts)
                    if found and found not in locations:
                        locations.append(found)
        row['storage_locations'] = locations
    return result


def read_location(store, stored_location):
    """Internal caller reads a generated mapping; API clients cannot supply this."""
    value = store.get(stored_location['key'])
    pointer = stored_location['artifact_pointer']
    for token in pointer.lstrip('/').split('/') if pointer else []:
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value
