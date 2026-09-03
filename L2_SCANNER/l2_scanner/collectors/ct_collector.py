"""L2 CT Collector (L2-C-06의 수집 담당)

[역할]
인증서가 CT(Certificate Transparency) 로그에 최초 관측된 시각을 수집한다.
1차: 인증서에 내장된 SCT의 시각을 사용. 2018년 이후 공인 인증서는 사실상 전부 보유하며, Certificate Collector가 이미 파싱해 둔 값이라 외부 접속이 필요 없다.
2차: SCT가 없는 인증서(자체 서명,사설,구식)만 crt.sh 색인 조회로 폴백.

[전체 overview]
leaf(fingerprint, sct_timestamps) -> [이 Collector] -> CT Raw Data -> [L2-C-06 Analyzer: 계산만] -> Signal
Certificate Collector와 파일을 분리한 이유 - TLS handshake는 대상 서버 접속이고 CT 폴백 조회는 제3자 서비스 접속이라, 실패 양상과 정책(타임아웃, 재시도)이 서로 다르다.
Analyzer는 네트워크 없음 원칙은 그대로 유지된다.

[왜 SCT를 1차로 쓰는가]
- SCT timestamp = CT 로그가 인증서(프리인증서)를 접수하고 서명한 시각 — 정의상 최초 관측
- 제3자(CT 로그)가 서명한 값이라 notBefore(발급자 기입)보다 조작이 어렵다
- crt.sh는 무료 공개 서비스라 장애가 잦다 
- 스캔마다 외부 의존을 만들지 않는 것이 대량 스캔(Fargate)에도 유리

[crt.sh 폴백 조회 방식]
GET https://crt.sh/?q=<sha256 fingerprint>&output=json
-> 이 인증서의 CT 로그 진입 항목 배열. 각 항목의 entry_timestamp(UTC, 오프셋 없는 ISO)가 로그 관측 시각이며, 그 최솟값이 최초 관측(first_seen)이다.

[오류 처리 - 다른 Collector와 동일]
조회 실패는 예외가 아니라 관측 결과(확인 못 함 = null)로 기록하고 스캔은 계속된다.
조회했는데 CT에 없음(log_entries=0)과 조회 못 함(log_entries=null)은 구분해 남긴다.
공인 CA 인증서는 사실상 전부 CT에 기록되므로 없음 자체가 의미 있는 관측이다.
"""
import json
from datetime import datetime, timezone

import httpx

from l2_scanner.config.tuning import CT_LOOKUP_URL, CT_TIMEOUT_SECONDS, CT_MAX_ATTEMPTS


def _to_utc(timestamp: str) -> datetime:
    # 오프셋 없는 ISO 시각(= UTC)을 tz 붙은 datetime으로 파싱한다.
    dt = datetime.fromisoformat(timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def collect(fingerprint: str | None, sct_timestamps: list[str] | None = None) -> dict:
    """인증서 하나의 CT 최초 관측 시각을 수집하고 CT Raw Data를 반환한다.

    입력: fingerprint      - leaf_certificate.fingerprint (sha256 hex). 인증서를 못 봤으면 None
          sct_timestamps   - leaf_certificate.sct_timestamps (내장 SCT ISO 목록)
    출력: fingerprint / first_seen(ISO UTC | null) / source("embedded_sct"|"crt.sh"|null) / sct_count(int | null) / log_entries(int | null) / errors[]

    인증서 자체를 못 본 경우(fingerprint None)는 조회 없이 unknown 구조만 반환한다 -
    실패 사유는 이미 TLS errors에 있다.
    """
    result = {
        "fingerprint": fingerprint,
        "first_seen": None,      # 최초 관측 시각 (확인 못 했으면 null)
        "source": None,          # 어디서 관측했나 - "embedded_sct" | "crt.sh" | null
        "sct_count": None,       # 내장 SCT 수 (인증서를 봤으면 0 이상, 못 봤으면 null)
        "log_entries": None,     # crt.sh 조회 성공 시 항목 수 (0 = CT에 없음), 미조회, 실패 시 null
        "errors": [],
    }

    if not fingerprint:
        return result

    # ---- 1차: 내장 SCT - 외부 접속 없음 ----
    scts = sct_timestamps or []
    result["sct_count"] = len(scts)
    if scts:
        result["first_seen"] = min(_to_utc(ts) for ts in scts).isoformat()
        result["source"] = "embedded_sct"
        return result

    # ---- 2차: crt.sh 폴백 - SCT 없는 인증서(자체 서명, 사설, 구식)만 ----
    last_error = None
    for _ in range(CT_MAX_ATTEMPTS):
        try:
            response = httpx.get(
                CT_LOOKUP_URL,
                params={"q": fingerprint, "output": "json"},
                timeout=CT_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                last_error = f"crt.sh returned HTTP {response.status_code}"
                continue

            entries = json.loads(response.text)

            # entry_timestamp가 null인 항목(중복 제거된 프리인증서 등)은 제외하고 최솟값
            observed = [_to_utc(e["entry_timestamp"])
                        for e in entries if e.get("entry_timestamp")]
            result["log_entries"] = len(entries)
            if observed:
                result["first_seen"] = min(observed).isoformat()
                result["source"] = "crt.sh"
            return result

        except httpx.HTTPError as e:
            last_error = f"{type(e).__name__}: {e}"
        except (json.JSONDecodeError, ValueError, KeyError, TypeError) as e:
            # 200인데 JSON이 아니거나(점검 페이지 등) 형식이 예상과 다른 경우
            last_error = f"crt.sh response parse error: {e}"

    result["errors"].append({"host": "crt.sh", "error": last_error})
    return result
