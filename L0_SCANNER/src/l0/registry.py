"""
L0 정적 분석 실행기.

URL 문자열 하나를 받아 0단계 파싱부터 그룹 A~F의 18개 판정까지 끝내고
Raw Evidence와 analysis_record 목록을 함께 돌려준다.

[순차 실행한다. 병렬화하지 않는다]
판정들은 서로 결과를 참조하지 않아 논리적으로는 독립적이지만, 전부 순수 CPU
연산(정규식·문자열 비교·목록 대조)이고 I/O가 전혀 없다.
  - 스레드 병렬화 -> GIL 때문에 CPU-bound 작업은 실제 동시 실행이 안 된다
  - 프로세스 병렬화 -> 생성·직렬화 오버헤드가 판정 하나(마이크로초 단위)보다 훨씬 크다
URL 간 처리량은 애플리케이션 코드가 아니라 Lambda 동시성으로 확보한다.

[항목별로 장애를 격리한다]
판정 하나가 예외를 던져도 나머지는 계속 진행하고, 실패한 항목은
status: "판정실패" 레코드로 남긴다. 18개 중 하나가 터졌다고 URL 하나의
분석 결과를 통째로 잃으면 안 된다.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from l0.models import AnalysisRecord, failed
from l0.parsing import ParseResult, ParseStatus, parse_url_stage

from l0.groups.group_a_host import GROUP_A_DETECTORS
from l0.groups.group_b_text_trick import GROUP_B_DETECTORS
from l0.groups.group_c_link_file import GROUP_C_DETECTORS
from l0.groups.group_d_parameter import GROUP_D_DETECTORS
from l0.groups.group_e_string import GROUP_E_DETECTORS
from l0.groups.group_f_misc import GROUP_F_DETECTORS

logger = logging.getLogger(__name__)

Detector = Callable[[ParseResult], AnalysisRecord]

# 그룹 A~F를 순서대로 이어 붙인 전체 판정 목록.
#
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한
# 형태다(코드 규약). 이 규약 덕분에 registry가 타입 분기 없이 균일하게
# 호출할 수 있고, 새 판정을 추가할 때 해당 그룹 파일의 튜플에만 넣으면 된다.
ALL_DETECTORS: tuple[Detector, ...] = (
    *GROUP_A_DETECTORS,   # A: 호스트 구조     (4)
    *GROUP_B_DETECTORS,   # B: 텍스트 트릭     (3)
    *GROUP_C_DETECTORS,   # C: 링크·파일       (3)
    *GROUP_D_DETECTORS,   # D: 파라미터        (2)
    *GROUP_E_DETECTORS,   # E: 문자열 구조     (5)
    *GROUP_F_DETECTORS,   # F: 기타            (1)
)


def run_detectors(result: ParseResult) -> list[AnalysisRecord]:
    """
    파싱 결과에 모든 판정을 순차 적용하고 레코드 목록을 돌려준다.

    판정 하나가 예외를 던져도 중단하지 않는다. 실패한 항목은 '판정실패'
    레코드로 남기고 다음 판정을 계속한다.
    """
    records: list[AnalysisRecord] = []

    for detector in ALL_DETECTORS:
        try:
            records.append(detector(result))
        except Exception as e:
            # 어떤 예외든 잡는다. 판정 함수는 18개고 각자 다른 라이브러리를
            # 쓰므로 예외 타입을 미리 열거할 수 없다. 여기서 놓치면
            # URL 하나의 분석이 통째로 날아간다.
            records.append(failed(detector.__name__, e))
            logger.warning(
                "판정 실패 (detector=%s, raw_url=%r): %s: %s",
                detector.__name__,
                result.raw_url,
                type(e).__name__,
                e,
                exc_info=True,
            )

    return records


def analyze(raw_url: str) -> dict[str, Any]:
    """
    URL 하나를 L0 정적 분석 전 과정에 태우고 저장 형식으로 돌려준다.

    Args:
        raw_url: 원본 URL 문자열 (메일·로그 등에서 추출된 그대로)

    Returns:
        {
          "raw_evidence":     0단계 파싱 결과,
          "analysis_records": [ {analysis_record: ...}, ... ]
        }

    [파싱 실패 시 판정을 돌리지 않는 이유]
    parse_status가 FAILURE면 호스트가 IP로도 도메인으로도 성립하지 않는
    문자열이다. 실제 브라우저도 접속을 거부하므로 후속 분석이 무의미하다.
    Raw Evidence만 남기고 판정은 건너뛴다.

    EMPTY_INPUT도 같다. 빈 문자열에 대해 18개의 '해당없음' 레코드를 만드는
    것은 저장 공간만 쓰고 아무것도 알려주지 않는다.
    """
    result = parse_url_stage(raw_url)

    if result.parse_status is not ParseStatus.SUCCESS:
        logger.info(
            "판정 생략 (parse_status=%s, raw_url=%r)",
            result.parse_status.value,
            raw_url,
        )
        return {**result.to_dict(), "analysis_records": []}

    records = run_detectors(result)
    return {**result.to_dict(), "analysis_records": [r.to_dict() for r in records]}


if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    test_urls = [
        "http://admin:pass@192.168.1.100:8080/path/view.php?id=1&name=test#section1",
        "https://kakao-login.workers.dev/auth",
        "https://g00gle.com/verify",
        "https://xn--80ak6aa92e.com/",
        "https://a.com/downloads/security_update.exe",
        "https://bit.ly/3yX9aBc",
        'https://a.com/index.php?page="/><img src=x onerror=alert(1)>',
        "https://portal.com/login?goto=https%3A%2F%2Fphishing-steal.com%2Fauth",
        "https://xjq87zpk91bwc.xyz/login",
        "https://www.google.com@attacker-portal.net/auth",
        "https://naver.com.account-verify.security-center.evil-host.com/login",
        "ftp://malicious-server.net/payload.exe",
        "https://www.naver.com/",
        "http://300.300.1.1/",  # 구조적 무효 URL
        "",                      # 빈 입력
    ]

    for url in test_urls:
        report = analyze(url)
        hits = [
            r["analysis_record"]
            for r in report["analysis_records"]
            if r["analysis_record"]["status"] == "확인함"
        ]
        print(f"\n입력: {url!r}")
        print(f"  parse_status : {report['raw_evidence']['parse_status']}")
        print(f"  판정 레코드   : {len(report['analysis_records'])}건")
        for hit in hits:
            print(f"    확인함 {hit['name']}: "
                  f"{json.dumps(hit['value'], ensure_ascii=False)}")
