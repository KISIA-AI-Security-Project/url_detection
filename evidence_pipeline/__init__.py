"""Public APIs, loaded only when their role needs them."""
from importlib import import_module

_EXPORTS = {
    "build_record": "records", "build_context": "context",
    "build_l1_context": "l1_context", "build_text_context": "model_text",
    "render_text_context": "model_text", "build_html_text_context": "l3_html_text",
    "build_javascript_text_context": "l3_javascript_text",
    "build_l3_content_text_context": "l3_content_text",
    "build_fast_context": "fast_context", "FastPipeline": "pipeline",
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
