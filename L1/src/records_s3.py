"""records_s3.py — records.py와 같은 출구·원본 파일을 S3에 쓴다(배포판). 경로와 쓰는 순서는 records.py의 files_to_write 그대로.

boto3는 Lambda 런타임에만 있다. 로컬 검증은 이 파일을 import하지 않는다(handler도 lambda_handler 안에서만 가져온다).
"""

import boto3

from src.records import files_to_write

__all__ = ["save"]


def save(output: dict, raws: dict[str, dict[str, str]], job_id: str, attempt_id: str, bucket: str) -> None:
    """출구·원본을 bucket에 put. IfNoneMatch="*"로 이미 있는 키는 412 예외 — 로컬판의 "xb"와 같은 거부 규칙."""
    client = boto3.client("s3")
    for key, body in files_to_write(output, raws, job_id, attempt_id):
        client.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json", IfNoneMatch="*")
