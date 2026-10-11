"""본문 자체를 결과에 중복 저장하지 않고 식별하기 위한 안정적 해시 유틸리티."""

import hashlib


def sha256_text(value: str, encoding: str = "utf-8") -> str:
    """문자열을 지정 인코딩으로 정규화해 SHA-256 16진수 값을 반환한다."""
    return hashlib.sha256(value.encode(encoding, errors="replace")).hexdigest()
