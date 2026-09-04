"""L2 Scanner 패키지 

공개 진입점 두 개만 노출한다:
    scan(url)             - URL 하나를 관측, 분석해 dict 반환
    save_evidence(result) - 결과 dict를 Raw Evidence, Analysis Record 파일로 분리 저장

다른 계층(L3, 공통 Collector, AWS Job)은 `from l2_scanner import scan, save_evidence`
로 사용한다. S3 저장은 l2_scanner.storage_s3.save_evidence (boto3 필요 - 배포 전용).
"""
from l2_scanner.scanner import scan
from l2_scanner.storage import save_evidence

__all__ = ["scan", "save_evidence"]
