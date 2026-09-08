"""L2 Scanner 패키지 — 악성 URL 분석 파이프라인의 L2(응답·통신 분석) 계층.

공개 진입점 세 개를 노출한다:
    scan(url)           - URL 하나를 관측·분석해 명세서 10장 형식 dict 반환
    scan_snapshot(value)- 이미 수집된 공통 PageSnapshot을 HTTP 재요청 없이 분석
    save_record(result) - 결과 dict를 Analysis Record JSON 파일로 저장

다른 계층(통합 Scanner, Fargate Job)은 `from l2_scanner import scan, scan_snapshot, save_record`
로 사용한다. 내부 모듈(collectors/analyzers/utils/config)은 직접 import하지 않는 것을 권장.
"""
from l2_scanner.scanner import scan, scan_snapshot
from l2_scanner.storage import save_record

__all__ = ["scan", "scan_snapshot", "save_record"]
