"""Optional user focus is request data, separate from captured findings."""


def normalize_request_text(value):
    if not isinstance(value, str):
        raise ValueError('invalid_request_text')
    value = value.strip()
    if len(value) > 2000 or len(value.encode('utf-8')) > 8000:
        raise ValueError('invalid_request_text')
    return value
