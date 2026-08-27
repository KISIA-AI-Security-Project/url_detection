"""L2-H-06 위험 파일 다운로드 Analyzer

[목적] 실행파일, 스크립트 등 위험한 유형의 파일을 제공하는지 확인한다.

[입력]  Raw Data의 download{filename, extension, mime_type}, response_body{detected_type, sha256}
[출력]  Signal evidence{filename, extension, file_type, mime_type, sha256}

[두 갈래 탐지 - 서로의 사각을 보완]
1. 이름 기반: 확장자가 위험 명단(DANGEROUS_EXTENSIONS)에 있는가
   -> 스크립트류(ps1/bat/vbs)는 텍스트라 magic 서명이 약해서 이름으로만 잡힌다.
2. 실체 기반: magic 판독 결과가 실행파일 MIME(EXECUTABLE_MIMES)인가
   -> 파일명을 photo.jpg로 위장해도 바이트 서명(exe=MZ)은 조작 불가.
둘 중 하나라도 걸리면 detected: true (OR 결합).

[extension은 어디서 오는가 - Collector의 2단계 수집]
Content-Disposition의 filename(RFC 5987 filename*= 포함)이 1순위,
없으면 URL 경로명(http://x/payload.ps1 -> ps1)이 fallback.
이 fallback 덕분에 헤더 없는 직링크 스크립트 배포도 이름 기반으로 잡힌다.

[L2-H-07과의 분업]
H-07 = "다운로드를 강제하는가"(행위), H-06 = "그 파일이 '위험'한가"(유형).
pdf 강제 다운로드는 H-07 true + H-06 false. 관측 대상이 다른 독립 신호이며,
둘 다 true면 위험 파일을 강제로 내려꽂는 조합 - 해석은 Rule/LLM의 몫.

[sha256을 evidence에 담는 이유]
1. 분석 시점의 파일을 봉인(악성 파일은 접속마다 바뀌거나 사라짐)
2. S3 원본과의 무결성 링크  3. VirusTotal 등 위협 DB 조회 열쇠
4. 동일 파일의 다중 URL 유포 식별. 단, 바디가 상한에 잘린 경우(truncated)
Collector가 sha256을 null로 남긴다 - 부분 해시는 파일 식별자로 쓰면 거짓 정보.

네트워크 접속 없음 - L2-H-01의 Collector가 수집한 값을 재사용한다.
"""

# 위험 확장자, 실행파일 MIME 명단 - 지식 데이터는 config에서 관리
from config.knowledge import DANGEROUS_EXTENSIONS, EXECUTABLE_MIMES

SIGNAL = {"id": "L2-H-06", "scanner": "header", "name": "dangerous_file_download"}


def analyze(raw: dict) -> dict:
    dl = raw["download"]
    body = raw["response_body"]

    # 각 검사는 재료가 있을 때만 수행한다 - 한쪽 재료가 없어도(null)
    # 다른 쪽으로 탐지 가능한 구조 (unknown != 안전)
    ext_dangerous = dl["extension"] in DANGEROUS_EXTENSIONS if dl["extension"] else False
    mime_dangerous = body["detected_type"] in EXECUTABLE_MIMES if body["detected_type"] else False

    # 두 갈래의 재료(확장자, magic 판독)가 모두 없으면 어느 검사도 못 한 것 -> 판정 불가
    if dl["extension"] is None and body["detected_type"] is None:
        detected = None
    else:
        detected = ext_dangerous or mime_dangerous   # 이름이든 실체든 하나라도 위험이면 관측

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "filename": dl["filename"],
            "extension": dl["extension"],
            "file_type": body["detected_type"],   # magic이 판독한 실제 유형
            "mime_type": dl["mime_type"],         # 서버가 선언한 유형
            "sha256": body["sha256"],             # truncated 시 null 
        },
    }
