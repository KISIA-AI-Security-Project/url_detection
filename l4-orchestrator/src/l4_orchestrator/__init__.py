"""L4 Agents SDK entry point; storage imports remain independent of the SDK."""

__all__ = ["run_l4"]


def __getattr__(name):
    if name == "run_l4":
        from .sdk_runtime import run_l4
        return run_l4
    raise AttributeError(name)
