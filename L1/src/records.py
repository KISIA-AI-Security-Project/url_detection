"""records.py — 실행 한 번의 출구를 정본 1.3 모양으로 조립하고, 출구 파일과 원본 응답 파일을 로컬에 저장한다.

S3판 저장은 records_s3.py에 있다 — 경로와 쓰는 순서는 이 파일의 files_to_write를 그대로 가져다 쓴다.
"""

import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from src.common import (
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    NAME_IP_ASN,
    NAME_RDAP,
    OVERALL_COMPLETED,
    OVERALL_FAILED,
    InfraRecord,
)
from src.domain_units import DomainUnits

__all__ = [
    "build_output",
    "save",
    "files_to_write",
    "output_key",
    "raw_key",
    "OUTPUT_FILE_NAME",
    "RAW_FILE_BY_NAME",
    "UNIT_KEYS",
    "KEY_JOB_ID",
    "KEY_ATTEMPT_ID",
    "KEY_DOMAIN_UNITS",
    "KEY_INFRA_RECORDS",
    "KEY_OVERALL",
    "KEY_FAILURE_REASON",
]

# 출구 키 — 정본 1.3 그대로. 검증이 같은 이름을 읽어 문자열이 두 곳에 생기지 않게 한다.
KEY_JOB_ID: str = "job_id"
KEY_ATTEMPT_ID: str = "attempt_id"
KEY_DOMAIN_UNITS: str = "도메인단위"
KEY_INFRA_RECORDS: str = "인프라결과_목록"
KEY_OVERALL: str = "전체상태"
KEY_FAILURE_REASON: str = "실패사유"

# DomainUnits 필드 → 출구 「도메인단위」 안의 키. 필드가 늘거나 이름이 바뀌면 조립에서 KeyError가 나 어긋남이 바로 드러난다.
UNIT_KEYS: dict[str, str] = {
    "host_kind": "호스트 종류",
    "registrable_unit": "등록 단위",
    "responsibility_boundary": "책임 경계",
    "platform_match": "플랫폼 목록 일치",
    "list_version": "대조한 목록의 판",
}

OUTPUT_FILE_NAME: str = "l1.json"

# 관측 이름 → raw/ 아래 원본 파일 이름. 기록마다 파일 하나, 이름은 고정.
RAW_FILE_BY_NAME: dict[str, str] = {
    NAME_DNS_A: "dns_a.json",
    NAME_DNS_AAAA: "dns_aaaa.json",
    NAME_DNS_NS: "dns_ns.json",
    NAME_IP_ASN: "ip_asn.json",
    NAME_RDAP: "rdap.json",
}


def build_output(
    job_id: str, attempt_id: str, units: DomainUnits, records: Sequence[InfraRecord], failure_reason: str | None
) -> dict:
    """입구 꼬리표 둘·도메인 단위·끝난 기록들·실패사유 → 출구 dict(정본 1.3). 기록의 None 칸은 여기서 뺀다.

    전체상태는 따로 받지 않고 실패사유에서 낸다 — 사유가 없으면 완료, 있으면 실패. 어긋난 짝을 구조로 막는다.
    """
    output: dict = {
        KEY_JOB_ID: job_id,
        KEY_ATTEMPT_ID: attempt_id,
        KEY_DOMAIN_UNITS: {UNIT_KEYS[field]: value for field, value in asdict(units).items()},
        KEY_INFRA_RECORDS: [_without_none(asdict(record)) for record in records],
        KEY_OVERALL: OVERALL_COMPLETED if failure_reason is None else OVERALL_FAILED,
    }
    if failure_reason is not None:   # 완료면 칸 자체가 없다 — 기록의 None 칸과 같은 규칙
        output[KEY_FAILURE_REASON] = failure_reason
    return output


def save(output: dict, raws: dict[str, dict[str, str]], job_id: str, attempt_id: str, root: Path) -> None:
    """출구·원본을 root 아래 파일로 쓴다(로컬판). 이미 있는 파일은 덮지 않고 FileExistsError — 같은 attempt_id로 두 번 도는 것은 사고다."""
    for key, body in files_to_write(output, raws, job_id, attempt_id):
        path = root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as fp:
            fp.write(body)


def files_to_write(output: dict, raws: dict[str, dict[str, str]], job_id: str, attempt_id: str) -> list[tuple[str, bytes]]:
    """쓸 파일을 쓸 순서대로 (경로, 바이트)로 — 원본 파일들 먼저, 출구 l1.json 마지막.

    출구가 「이 실행이 성립했다」의 도장이라, 원본 저장이 실패하면 출구가 없어야 한다. 원본이 빈 기록은 파일이 없다.
    로컬판·S3판이 같은 목록을 받아 쓰는 곳만 다르다.
    """
    files = [(raw_key(job_id, attempt_id, name), _json_bytes(raw)) for name, raw in raws.items() if raw]
    files.append((output_key(job_id, attempt_id), _json_bytes(output)))
    return files


def output_key(job_id: str, attempt_id: str) -> str:
    return f"records/{job_id}/{attempt_id}/{OUTPUT_FILE_NAME}"


def raw_key(job_id: str, attempt_id: str, name: str) -> str:
    return f"raw/{job_id}/{attempt_id}/l1/{RAW_FILE_BY_NAME[name]}"


def _without_none(record: dict) -> dict:
    # 최상위 다섯 칸만 본다. result·detail 안쪽은 부품이 만든 그대로 둔다.
    return {key: value for key, value in record.items() if value is not None}


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
