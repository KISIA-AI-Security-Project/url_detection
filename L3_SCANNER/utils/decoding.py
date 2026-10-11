"""HTML 응답의 문자 인코딩을 선택하고 해석 손실을 명시한다."""

import codecs
import re
from typing import Any


def decode_html(body: bytes, declared: str | None, *, allow_html_meta=True):
    candidates = []
    if body.startswith(codecs.BOM_UTF8):
        candidates.append(("utf-8-sig", "bom"))
    elif body.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        candidates.append(("utf-16", "bom"))
    if declared:
        candidates.append((declared, "http_charset"))
    # 앞부분 meta 요소 내부에서만 charset을 찾는다. JS/본문의 문자열은 선언이 아니다.
    for tag in (
        re.findall(rb"<meta\s[^>]*>", body[:1024], re.I) if allow_html_meta else []
    ):
        m = re.search(rb"charset\s*=\s*[\"']?([a-zA-Z0-9._-]+)", tag, re.I)
        if m:
            candidates.append((m.group(1).decode("ascii"), "html_meta"))
            break
    candidates.append(("utf-8", "default"))
    errors: list[dict[str, Any]] = []
    for encoding, source in candidates:
        try:
            encoding = codecs.lookup(encoding).name
        except LookupError:
            errors.append(
                {"code": "unknown_encoding", "encoding": encoding, "source": source}
            )
            continue
        # WHATWG의 EUC-KR 라벨은 확장 한글(CP949)을 포함한다.
        if encoding == "euc_kr":
            encoding = "cp949"
        try:
            return body.decode(encoding), encoding, source, errors
        except UnicodeDecodeError as exc:
            errors.append(
                {
                    "code": "decoding_loss",
                    "encoding": encoding,
                    "source": source,
                    "start": exc.start,
                    "end": exc.end,
                }
            )
            return body.decode(encoding, errors="replace"), encoding, source, errors
    raise AssertionError("utf-8 fallback unavailable")
