"""storage.py와 같은 Raw Evidence, Analysis Record 파일을 S3에 쓴다.

경로와 쓰는 순서는 storage.py의 files_to_write 그대로 
boto3는 Lambda/컨테이너 런타임에만 있다. 로컬 실행, 테스트는 이 모듈을 import하지 않는다.
"""
import boto3

from l2_scanner.storage import files_to_write

__all__ = ["save_evidence"]


def save_evidence(result: dict, job_id: str, attempt_id: str, bucket: str) -> None:
    # Raw, Record를 bucket에 put. IfNoneMatch="*"로 이미 있는 키는 412 예외
    client = boto3.client("s3")
    for key, body in files_to_write(result, job_id, attempt_id):
        client.put_object(Bucket=bucket, Key=key, Body=body,
                          ContentType="application/json", IfNoneMatch="*")
