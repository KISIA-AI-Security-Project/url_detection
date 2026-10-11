"""Selection-time public facts. No parsing or interpretation of model prose."""
from copy import deepcopy


def item(label, lines, *, basis, sources=(), evidence_ids=(), plain=None):
    value = {'item_label': label, 'lines': list(lines), 'basis': basis,
             'sources': deepcopy(list(sources)), 'evidence_ids': list(evidence_ids)}
    if plain is not None:
        value['plain'] = deepcopy(plain)
    return value


class PresentationCapture:
    """Renderers explicitly start factual groups; notes are private by default."""
    def reset_items(self):
        self.items, self.current_item = [], None

    def begin_item(self, label, *, basis='static_declaration', plain=None):
        self.current_item = item(label, [], basis=basis, plain=plain)
        self.items.append(self.current_item)

    def capture(self, lines, sources, ids, *, public):
        if public and self.current_item is not None:
            self.current_item['lines'].extend(lines)
            for source in sources:
                if source not in self.current_item['sources']:
                    self.current_item['sources'].append(deepcopy(source))
            for eid in ids:
                if eid not in self.current_item['evidence_ids']:
                    self.current_item['evidence_ids'].append(eid)

    def end_item(self):
        self.current_item = None
