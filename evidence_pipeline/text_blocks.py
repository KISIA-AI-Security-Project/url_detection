"""Text blocks with provenance kept outside the model-facing body."""
from dataclasses import dataclass, field as dataclass_field
import re


@dataclass
class TextBlock:
    title: str
    lines: list[str]
    evidence_ids: tuple[str, ...] = ()
    # Emitted with the selected facts, never reconstructed from rendered prose.
    items: list[dict] = dataclass_field(default_factory=list)


def scalar(value):
    if isinstance(value, str):
        return value
    if value is None:
        return '미기록'
    if type(value) is bool:
        return '예' if value else '아니요'
    if isinstance(value, (int, float)):
        return str(value)
    raise ValueError('text_scalar_requires_recorded_scalar')


def field(label, value):
    """Indent recorded text; never interpret data as headings or instructions."""
    text = scalar(value)
    if '\n' in text or '\r' in text:
        # Preserve the original newline sequences under a labelled data block.
        return [label + ':', '  ' + re.sub(r'\r\n|\r|\n', lambda m: m.group() + '  ', text)]
    return [f'{label}: {text}']


def nested_fields(value, indent=''):
    """Render already selected observation values without dropping occurrences."""
    lines = []
    if isinstance(value, dict):
        for label, item in value.items():
            if isinstance(item, (list, dict)):
                lines.append(indent + str(label) + ':')
                lines.extend(nested_fields(item, indent + '  '))
            else:
                lines.extend(indent + line for line in field(str(label), item))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (list, dict)):
                lines.append(indent + f'항목 {index + 1}:')
                lines.extend(nested_fields(item, indent + '  '))
            else:
                lines.append(indent + '- ' + scalar(item).replace('\n', '\n' + indent + '  '))
        if not value:
            lines.append(indent + '기록된 항목 없음')
    else:
        lines.append(indent + scalar(value))
    return lines
