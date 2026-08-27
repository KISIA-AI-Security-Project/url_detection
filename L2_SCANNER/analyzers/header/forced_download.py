"""L2-H-07 강제 다운로드 Analyzer

[목적] 웹페이지 표시가 아니라 파일 다운로드를 강제하는 응답인지 확인한다.
       (Content-Disposition: attachment - 브라우저가 화면에 띄우지 않고 저장창을 연다)

[입력]  Raw Data의 headers.content_disposition
[출력]  Signal evidence{filename, extension, content_disposition(원문)}

[detected 기준 = attachment 값. 헤더의 존재가 아니다]
Content-Disposition에는 inline("화면에 표시하되 저장 시 이 파일명을 제안")이라는
흔한 정상 용법이 있다. 헤더 존재를 기준으로 삼으면 정상 사이트가 대량 오탐된다.
반면 L2-H-08(Refresh)은 정상 용법이 사실상 없는 헤더라 존재 자체가 기준이다.
-> detected 기준은 "그 헤더/값의 정상 용법이 존재하는가"로 정한다는 잣대의 두 적용.

[파싱은 공용 유틸 사용 - 두 벌 구현 방지]
Content-Disposition 파싱은 Collector(download 트리 채움)와 이 Analyzer 두 곳에서
필요하다. utils/http_parsing.parse_content_disposition 하나를 같이 쓰므로
"같은 헤더를 놓고 두 모듈의 해석이 다른" 버그가 원천 차단된다.
RFC 5987 확장 표기(filename*=UTF-8''%..%.. - 비ASCII 파일명, filename=보다 우선)도
이 유틸이 처리한다. 상세는 utils/http_parsing.py 참고.

네트워크 접속 없음 - L2-H-01의 Collector가 수집한 값을 재사용한다.
"""

from utils.http_parsing import parse_content_disposition, extension_from_filename

SIGNAL = {"id": "L2-H-07", "scanner": "header", "name": "forced_download"}


def analyze(raw: dict) -> dict:
    cd_value = raw["headers"]["content_disposition"]

    if cd_value is None:
        # 최종 응답을 아예 못 받았으면 헤더의 유무 자체를 관측 못 한 것 -> 판정 불가(null).
        # 응답을 받았는데 헤더가 없으면 일반적인 웹페이지 -> false (정상 사이트 대부분)
        return {
            **SIGNAL,
            "detected": None if raw["final_url"] is None else False,
            "evidence": {
                "filename": None,
                "extension": None,
                "content_disposition": None,
            },
        }

    parsed = parse_content_disposition(cd_value)

    # 결정 1: 기준은 attachment 값 (inline은 정상 용법이므로 미탐지)
    detected = parsed["type"] == "attachment"

    # 결정 2: 확장자 = 마지막 점 뒤, 소문자 (invoice.pdf.exe -> exe). 점이 없으면 null
    extension = extension_from_filename(parsed["filename"])

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            # 결정 3: filename 없는 attachment도 강제는 사실 -> detected true + filename null
            # (확인 안 됨과 없음의 구분). inline이어도 filename은 관측 사실이므로 보존.
            "filename": parsed["filename"],
            "extension": extension,
            # 결정 4: 헤더 원문 전체 보존 - 파싱에서 놓친 것이 있어도
            # 사람/LLM이 재확인할 수 있게 
            "content_disposition": cd_value,
        },
    }
