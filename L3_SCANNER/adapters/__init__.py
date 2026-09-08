"""공통 HTTP 스냅샷을 L3 입력 계약으로 변환하는 어댑터."""

from .page_snapshot import page_collection_policy, to_l3_input
from .script_snapshot import apply_script_snapshot, script_collection_policy

__all__ = [
    "apply_script_snapshot",
    "page_collection_policy",
    "script_collection_policy",
    "to_l3_input",
]
