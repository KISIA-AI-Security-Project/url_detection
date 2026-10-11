"""Plain, finite UTF-8 JSON without coercion, duplicate keys or shared objects."""
import json

from .tools.read_result import _json_copy
from .tools.record_reader import _finite_float, _invalid_constant, _unique_object


def copy_json(value):
    return _json_copy(value)[0]


def dumps(value):
    return json.dumps(copy_json(value), ensure_ascii=False, allow_nan=False,
                      separators=(",", ":"))


def loads(value):
    result = json.loads(value, parse_constant=_invalid_constant,
                        parse_float=_finite_float, object_pairs_hook=_unique_object)
    return copy_json(result)


def same_json(left, right):
    """Compare JSON values without equating bool/int/float or object key order."""
    def identity(value):
        return json.dumps(copy_json(value), ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":"))
    return identity(left) == identity(right)
