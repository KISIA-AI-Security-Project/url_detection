"""Control signals propagate outside native Tool error handling."""


class ExecutionEnded(Exception):
    """The manager has ended execution; already started work may finish recording."""


class AssignmentError(ValueError):
    """The whole returned assignment was rejected before saving or execution."""


class ProgressError(RuntimeError):
    pass


class ExecutionLimitExceeded(RuntimeError):
    pass


class StoreError(RuntimeError):
    """Recording failure; never converted into a native Tool failure."""
