"""Team5-result — 확장 프로그램이 폴링하는 곳.

장부(Team5-firstDB)의 내부 상태를 확장이 이해하는 형태로 번역한다.

  장부 status                       -> API status   verdict
  ----------------------------------------------------------------------
  (항목 없음)                          404          -
  PENDING / L0_DONE / L1_DONE /
  REACH_DONE / COLLECT_DONE /
  EXPLORE_DONE / FINAL_DONE /
  COLLECT_SKIPPED                     RUNNING      -
  JUDGED (final_verdict 있음)          COMPLETED    final_verdict
  JUDGED (final=PENDING)              COMPLETED    UNDETERMINED
  GATE_BLOCKED                        COMPLETED    UNDETERMINED
  FAILED                              FAILED       UNDETERMINED

UNDETERMINED를 BENIGN처럼 보이게 하지 않는 것이 이 함수의 존재 이유다.

rev.2 (2026-08-23) — 배관 시험판에 맞춰 추가된 것
  · attempt          : 몇 번째 시도인지
  · progress         : 장부의 fragments 맵을 계층 7개 배열로 펼침. 확장의 진행 막대용
  · stub             : 스텁 조각이 섞였는지. 섞였으면 이 판정은 판정이 아니다
  · coverage         : 종합본의 실행/생략/스텁 계층 목록

환경 변수
  JOBS_TABLE       = Team5-firstDB
  EVIDENCE_BUCKET  = (선택) 없으면 S3를 아예 읽지 않는다
"""
import json
import os
import re
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock

import boto3

try:
    from api_timing import current_trace, invocation, span
except ImportError:
    from deployment.api_timing import current_trace, invocation, span

_REQUEST_READS = ContextVar('result_request_reads', default=None)


class _ReadCache:
    """One invocation only; confirmed misses are reusable, read errors are not."""
    def __init__(self):
        self.values = {}
        self.lock = Lock()

    def get(self, kind, key, load):
        with self.lock:
            identity = (kind, key)
            owner = identity not in self.values
            future = self.values.setdefault(identity, Future())
        if owner:
            try:
                future.set_result(load(key))
            except BaseException as exc:
                with self.lock:
                    self.values.pop(identity, None)
                future.set_exception(exc)
                raise
        else:
            with span('result.s3.reuse', artifact=kind, reused=True):
                return future.result()
        return future.result()


def _cached(kind, key, load):
    cache = _REQUEST_READS.get()
    try:
        return cache.get(kind, key, load) if cache is not None else load(key)
    except _ReadFailure:
        return None


class _ReadFailure(Exception):
    """Keep the legacy None result while excluding failed reads from reuse."""


def _missing_object(error):
    response = getattr(error, 'response', {})
    if not isinstance(response, dict):
        return False
    return ((response.get('Error') or {}).get('Code') in ('NoSuchKey', 'NotFound', '404') or
            (response.get('ResponseMetadata') or {}).get('HTTPStatusCode') == 404)


def _load_many(specs):
    """Read independent v2 artifacts; finish all workers before returning."""
    with span('result.artifacts.parallel_read', count=len(specs)):
        with ThreadPoolExecutor(max_workers=min(4, len(specs))) as pool:
            futures = {name: pool.submit(copy_context().run, load, key)
                       for name, (load, key) in specs.items()}
            return {name: future.result() for name, future in futures.items()}


def _fresh_activity_expiry(value):
    if not isinstance(value, str):
        return False
    try:
        expiry = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return False
    return expiry.tzinfo is not None and expiry > datetime.now(timezone.utc)

try:                      # Lambda Layer team5-common
    import keys
except ImportError:       # 레이어가 없어도 죽지 않게 한다
    keys = None

ddb = boto3.client("dynamodb")
s3 = boto3.client("s3")

TABLE = os.environ["JOBS_TABLE"]
BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
ID_RE = re.compile(r"^[0-9a-f]{32}$")

RUNNING_STATES = {
    "PENDING", "L0_DONE", "L1_DONE", "REACH_DONE",
    "COLLECT_DONE", "EXPLORE_DONE", "FINAL_DONE", "COLLECT_SKIPPED",
    # v4(pipeline-parallel.json)에서 도입. 병렬판은 reach·collect·explore를 한 번에
    # 돌리므로 REACH_DONE/COLLECT_DONE/EXPLORE_DONE 세 단계가 이 하나로 합쳐진다.
    # v3 값들을 지우지 않는 이유: 롤백해도 진행 중 판정이 그대로 동작해야 한다.
    "OBSERVE_DONE",              # ← 추가
}
LAYER_KO = {
    "L0": "L0 URL 구조 분석", "L1": "L1 도메인·평판 조회",
    "REACH": "도달성 확인", "L2": "L2·L3 수집", "L4": "L4 탐색",
    "OBSERVE": "관측 (도달성·수집·탐색)",   # ← 추가
    "FINAL": "종합", "-": "판정 중",
}
# 진행 막대에 그릴 계층. 순서가 곧 파이프라인 순서다.
PROGRESS_LAYERS = [
    ("l0", "L0 URL 구조"), ("l1", "L1 도메인·평판"), ("gate", "도달성·분기"),
    ("l2", "L2 접속 통신"), ("l3", "L3 콘텐츠"), ("l4", "L4 능동 관측"),
    ("final", "종합"),
]


def _json(status, body):
    with span('result.json.encode'):
        encoded = json.dumps(body, ensure_ascii=False)
    return {"statusCode": status,
            "headers": {"content-type": "application/json; charset=utf-8"},
            "body": encoded}


def _load(key):
    return _cached('json', key, _load_json)


def _load_json(key):
    """S3의 JSON 한 개. 없거나 권한이 없으면 조용히 None."""
    if not (BUCKET and key):
        return None
    try:
        with span('result.s3.get', artifact='json') as timing:
            response = s3.get_object(Bucket=BUCKET, Key=key)
            body = response['Body']
            try:
                data = body.read()
            finally:
                body.close()
            timing.update(bytes=len(data), retries=response.get('ResponseMetadata', {}).get('RetryAttempts', 0))
        with span('result.json.decode'):
            return json.loads(data)
    except Exception as e:                  # noqa: BLE001 - 근거 표시는 부가 기능이다
        print(json.dumps({"msg": "s3_load_failed", "key": key, "err": str(e)}))
        if _missing_object(e):
            return None
        raise _ReadFailure() from e


def _load_bytes(key):
    return _cached('bytes', key, _load_bytes_uncached)


def _load_bytes_uncached(key):
    if not (BUCKET and key):
        return None
    try:
        with span('result.s3.get', artifact='bytes') as timing:
            response = s3.get_object(Bucket=BUCKET, Key=key)
            body = response['Body']
            try:
                data = body.read(8_000_001)
            finally:
                body.close()
            timing.update(bytes=len(data), retries=response.get('ResponseMetadata', {}).get('RetryAttempts', 0))
        return data if len(data) <= 8_000_000 else None
    except Exception as e:
        if _missing_object(e):
            return None
        raise _ReadFailure() from e


def _hash_json(value, *, ordered=False):
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=not ordered,
                             separators=(",", ":")).encode("utf-8")).hexdigest()


def _valid_v2_request_contract(request, view):
    from evidence_pipeline.aws_judgment_v2 import PROMPT as V2_PROMPT, LEGACY_STRUCTURED_PROMPT
    from evidence_pipeline.judgment_contract_v2 import anthropic_output_config_v2
    """Accept both recorded protocols without weakening either artifact check."""
    fields = {"model", "max_tokens", "temperature", "system", "messages"}
    if set(request) == fields:
        return request.get("system") == V2_PROMPT
    if set(request) == fields | {"output_config"}:
        return (request.get("system") == LEGACY_STRUCTURED_PROMPT and
                request["output_config"] == anthropic_output_config_v2(view))
    return False


def _valid_v2_result(scan_id, attempt, url, verdict, judgment, final_doc,
                     view, selection, review, processing, saved_consumer,
                     request_bytes, response, request_claim, transport):
    from evidence_pipeline.judgment_contract_v2 import process_judgment_output_v2
    from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
    if not all(isinstance(v, dict) for v in (
            judgment, final_doc, view, selection, review, processing,
            saved_consumer, response, request_claim, transport)) or not isinstance(request_bytes, bytes):
        return False
    consumer = judgment.get("consumer")
    context = final_doc.get("model_context")
    facts = view.get("fact_units")
    accounting = view.get("source_accounting")
    if not isinstance(context, dict):
        return False
    try:
        expected_view = build_judgment_view_v2(context)
        expected_processing = process_judgment_output_v2(selection, view)
        request = json.loads(request_bytes)
        messages = request.get("messages")
        if (not isinstance(messages, list) or len(messages) != 1 or
                not isinstance(messages[0], dict) or
                set(messages[0]) != {"role", "content"} or
                messages[0]["role"] != "user" or
                not isinstance(messages[0]["content"], str)):
            return False
        request_view = json.loads(messages[0]["content"])
        response_text = "\n".join(block.get("text", "") for block in response["content"]
                                  if block.get("type") == "text").strip()
        if response_text.startswith("```"):
            fenced = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", response_text, re.DOTALL)
            if not fenced:
                return False
            response_text = fenced.group(1)
        response_selection = json.loads(response_text)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
    if (view != expected_view or expected_processing["status"] != "accepted" or
            expected_processing["review"] != review or
            expected_processing["consumer"] != consumer or
            response.get("stop_reason") != "end_turn" or response_selection != selection or
            sha256(request_bytes).hexdigest() != judgment.get("request_sha256") or
            request_claim != {
                "request_sha256": judgment.get("request_sha256"),
                "context_sha256": final_doc.get("model_context_sha256"),
                "model": judgment.get("model"),
                "judgment_contract_version": "fact-interpretation-selection-2"} or
            transport.get("request_sha256") != judgment.get("request_sha256") or
            transport.get("requested_model") != judgment.get("model") or
            transport.get("http_status") != 200 or
            not isinstance(request, dict) or
            not _valid_v2_request_contract(request, view) or
            type(request.get("max_tokens")) is not int or
            not 0 < request["max_tokens"] <= 8192 or
            request.get("model") != judgment.get("model") or
            request.get("temperature") != 0 or
            request_view != view):
        return False
    if (not isinstance(consumer, dict) or not isinstance(context, dict) or
            not isinstance(facts, list) or not isinstance(accounting, dict) or
            not isinstance(view.get("requested_urls"), list) or
            not isinstance(view.get("url_activity_observation"), dict) or
            view.get("omitted_evidence") != [] or
            not all(isinstance(row, dict) and isinstance(row.get("id"), str) and
                    isinstance(row.get("facts"), dict) for row in facts) or
            verdict not in ("MALICIOUS", "LIKELY_BENIGN", "SUSPICIOUS", "UNKNOWN") or
            (final_doc.get("job_id"), str(final_doc.get("attempt")),
             final_doc.get("input_url"), final_doc.get("analysis_status")) !=
            (scan_id, str(attempt), url, "COMPLETED") or
            _hash_json(context, ordered=True) != final_doc.get("model_context_sha256") or
            judgment.get("context_sha256") != final_doc.get("model_context_sha256") or
            judgment.get("judgment_contract_version") != "fact-interpretation-selection-2" or
            judgment.get("processing_status") != "accepted" or
            judgment.get("judgment_status") != "completed" or
            (judgment.get("job_id"), str(judgment.get("attempt")),
             judgment.get("input_url"), judgment.get("verdict")) !=
            (scan_id, str(attempt), url, verdict) or
            judgment.get("view_sha256") != _hash_json(view) or
            url not in view["requested_urls"] or
            view.get("url_activity_observation") != context.get("url_activity_observation") or
            accounting.get("source_evidence_sha256") != _hash_json(facts) or
            accounting.get("source_activity_sha256") != _hash_json(view["url_activity_observation"]) or
            accounting.get("source_evidence_ids") != [row["id"] for row in facts] or
            accounting.get("source_evidence_count") != len(facts) or
            judgment.get("source_evidence_sha256") != accounting["source_evidence_sha256"] or
            processing.get("status") != "accepted" or
            processing.get("consumer_created") is not True or
            consumer != saved_consumer or consumer.get("provider_selection") != selection or
            consumer.get("judgment_contract_version") != "fact-interpretation-selection-2" or
            consumer.get("verdict") != verdict or selection.get("verdict") != verdict):
        return False
    by_id = {row.get("id"): row for row in facts if isinstance(row, dict)}
    if len(by_id) != len(facts):
        return False
    allowed = {"verdict", "interpretation_text", "basis_fact_id_1"}
    for role in ("observed", "basis", "limitation"):
        allowed.update({f"{role}_fact_id_1", f"{role}_fact_id_2"})
    if not {"verdict", "interpretation_text", "basis_fact_id_1"} <= set(selection) or not set(selection) <= allowed:
        return False
    picked = {}
    for role in ("observed", "basis", "limitation"):
        ids = [selection[f"{role}_fact_id_{number}"] for number in (1, 2)
               if f"{role}_fact_id_{number}" in selection]
        if (not all(isinstance(identifier, str) for identifier in ids) or
                len(ids) != len(set(ids)) or any(identifier not in by_id for identifier in ids)):
            return False
        picked[role] = [by_id[identifier] for identifier in ids]
    interpretation = consumer.get("interpretation")
    if not isinstance(interpretation, dict):
        return False
    observations = []
    for row in picked["basis"]:
        scope = row.get("facts", {}).get("response_observation")
        if isinstance(scope, str) and scope not in observations:
            observations.append(scope)
    return (consumer.get("observed_facts") == picked["observed"] and
            consumer.get("limitation_support_facts") == picked["limitation"] and
            interpretation.get("basis_fact_ids") == [row["id"] for row in picked["basis"]] and
            interpretation.get("basis_facts") == picked["basis"] and
            interpretation.get("basis_response_observations") == observations and
            interpretation.get("text") == selection.get("interpretation_text") and
            isinstance(interpretation.get("text"), str) and
            bool(interpretation["text"].strip()))


def _notes(key):
    doc = _load(key)
    if isinstance(doc, dict):
        n = doc.get("notes")
        if isinstance(n, list):
            return [str(x) for x in n[:8]]
    return []


def _progress(frag, ledger, final_verdict):
    """장부의 fragments 맵 -> 준비 계층 7개와 판정 결과 1개.

    장부에 없는 계층은 PENDING이다. '아직 안 왔다'와 '건너뛰었다'는 다르다 -
    후자는 SKIPPED로 명시적으로 기록되어 있다.
    """
    rows, done, stubbed = [], 0, []
    for key, label in PROGRESS_LAYERS:
        entry = (frag.get(key) or {}).get("M") or {}
        st = (entry.get("status") or {}).get("S", "PENDING")
        rows.append({
            "key": key,
            "label": label,
            "status": st,
            "s3_key": (entry.get("key") or {}).get("S") or None,
            "at": (entry.get("at") or {}).get("S") or None,
            "reason": (entry.get("reason") or {}).get("S") or None,
        })
        if st in ("COMPLETED", "STUB", "PARTIAL", "SKIPPED", "NOT_PERFORMED"):
            done += 1
        if st == "STUB":
            stubbed.append(key)
    # These seven fragments describe evidence preparation, not final judgment.
    # The outcome row reports the job result, without guessing which stage failed.
    if ledger == "FAILED":
        outcome = "FAILED"
    elif ledger in ("GATE_BLOCKED", "TARGET_BLOCKED", "DNS_NAME_NONEXISTENT_AT_SCAN",
                    "URL_UNREACHABLE_AT_SCAN"):
        outcome = "SKIPPED"
    elif ledger == "JUDGED":
        outcome = "COMPLETED" if final_verdict and final_verdict != "PENDING" else "UNAVAILABLE"
    elif ledger in ("FINAL_DONE", "COLLECT_SKIPPED"):
        outcome = "RUNNING"
    else:
        outcome = "PENDING"
    rows.append({"key": "judgment", "label": "판정 결과", "status": outcome,
                 "s3_key": None, "at": None, "reason": None})
    if outcome in ("COMPLETED", "SKIPPED"):
        done += 1
    return {"layers": rows, "done": done, "total": len(rows)}, stubbed


def _fast_result(scan_id, attempt, ledger, result_key, judgment_status=None):
    # This module is packaged next to app.py; repository tests use the package.
    try:
        from fast_public import make_public_result, validate_public_result
    except ImportError:
        from evidence_pipeline.fast_public import make_public_result, validate_public_result
    prefix = f'records/{scan_id}/{attempt}/fast/'
    allowed = {prefix + 'pending.json', prefix + 'result.json'}
    if result_key is not None and result_key not in allowed:
        return _json(200, make_public_result(scan_id, attempt, status='failed'))
    value = _load(prefix + 'result.json')
    if value is None and result_key in allowed:
        value = _load(result_key)
    if value is None:
        if ledger == 'FAILED':
            state = 'failed'
        elif judgment_status == 'not_requested' or ledger == 'TARGET_BLOCKED':
            # The target-safety branch ends before Context writes public artifacts.
            state = 'not_requested'
        else:
            state = 'failed' if ledger == 'JUDGED' else 'pending'
        return _json(200, make_public_result(scan_id, attempt, status=state))
    try:
        with span('result.public.validate'):
            public = validate_public_result(value, job_id=scan_id, attempt=attempt)
    except (ValueError, KeyError, TypeError):
        return _json(200, make_public_result(scan_id, attempt, status='invalid'))
    if ledger == 'FAILED' and public['judgment_status'] == 'pending':
        public = make_public_result(scan_id, attempt, context=public, status='failed')
    return _json(200, public)


def handler(event, _ctx):
    with invocation(event, _ctx, role='result'):
        token = _REQUEST_READS.set(_ReadCache())
        try:
            return _handle(event, _ctx)
        finally:
            _REQUEST_READS.reset(token)


def _handle(event, _ctx):
    scan_id = (event.get("pathParameters") or {}).get("scanId", "")
    if not ID_RE.match(scan_id):
        return _json(400, {"error": "scanId 형식이 올바르지 않습니다."})

    with span('result.ddb.get_item') as timing:
        response = ddb.get_item(TableName=TABLE, Key={"job_id": {"S": scan_id}})
        timing['retries'] = response.get('ResponseMetadata', {}).get('RetryAttempts', 0)
        item = response.get('Item')
    if not item:
        return _json(404, {"error": "not_found", "scanId": scan_id})

    def s(k, d=None):
        return item.get(k, {}).get("S", d)

    ledger = s("status", "UNKNOWN")
    layer = s("current_layer", "-")
    attempt = int(item.get("attempt", {}).get("N", "1") or 1)
    if current_trace() is not None:
        current_trace().identify(job_id=scan_id, attempt=attempt)
    if s('result_contract_version') == 'fast-result-1':
        return _fast_result(scan_id, attempt, ledger, s('fast_result_key'), s('judgment_status'))
    frag = item.get("fragments", {}).get("M", {}) or {}
    progress, stubbed = _progress(frag, ledger, s("final_verdict"))

    out = {
        "scanId": scan_id,
        "url": s("url"),
        "attempt": attempt,
        "ledger_status": ledger,
        "stage": layer,
        "stage_ko": LAYER_KO.get(layer, layer),
        "progress": progress,
        # ★ 스텁 조각이 하나라도 섞이면 이 실행은 '판정'이 아니다.
        #   확장이 이 값을 보고 사용자에게 경고를 띄운다.
        "stub": {"any": bool(stubbed), "layers": stubbed},
        "updatedAt": s("updatedAt"),
    }

    # ── 진행 중 ────────────────────────────────────────────────
    if ledger in RUNNING_STATES:
        out["status"] = "RUNNING"
        return _json(200, out)

    # ── 파이프라인 실패 ────────────────────────────────────────
    if ledger == "FAILED":
        out.update(status="FAILED", verdict="UNDETERMINED", error=s("error"),
                   stage="FAILED", stage_ko="분석 실패")
        return _json(200, out)

    refs = [k for k in (s("l0_key"), s("l1_key"), s("final_key"), s("judgment_key")) if k]
    out["evidence_refs"] = refs

    if ledger in ("DNS_NAME_NONEXISTENT_AT_SCAN", "URL_UNREACHABLE_AT_SCAN"):
        key = s("url_activity_key")
        expected = f"records/{scan_id}/{attempt}/final/url-activity.json"
        decision = _load(key) if key == expected else None
        actual_hash = sha256(json.dumps(decision, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8")).hexdigest() if decision else None
        if (not decision or actual_hash != s("url_activity_sha256") or
                decision.get("request_id") != scan_id or
                str(decision.get("attempt")) != str(attempt) or
                decision.get("input_url") != s("url") or
                decision.get("state") != ledger or
                decision.get("can_skip_judgment") is not True or
                (ledger == "DNS_NAME_NONEXISTENT_AT_SCAN" and
                 decision.get("valid_until") != s("url_activity_valid_until")) or
                (ledger == "URL_UNREACHABLE_AT_SCAN" and
                 ((decision.get("reason") == "a_nodata_with_soa" and
                   (not _fresh_activity_expiry(decision.get("valid_until")) or
                    (decision.get("l23_preflight") or {}).get("addresses"))) or
                  (decision.get("reason") != "a_nodata_with_soa" and
                   (decision.get("reason") != "l1_and_l23_address_resolution_failed" or
                    decision.get("scope") != "scan_time_reachability_observation" or
                    # Preserve saved dual-stack observations as well as current A-only records.
                    set((decision.get("l1_address_observation") or {})) not in ({"A"}, {"A", "AAAA"}) or
                    (decision.get("l23_preflight") or {}).get("state") != "blocked_before_layer_network" or
                    (decision.get("l23_preflight") or {}).get("failure_kind") != "dns_resolution_error" or
                    (decision.get("l23_preflight") or {}).get("addresses") != [] or
                    decision.get("observed_at") != (decision.get("l23_preflight") or {}).get("observed_at")))))):
            out.update(status="FAILED", verdict="UNDETERMINED",
                       error="url_activity_artifact_unavailable_or_mismatched")
            return _json(200, out)
        absence = ledger == "DNS_NAME_NONEXISTENT_AT_SCAN"
        activity = {"state": decision["state"], "reason": decision["reason"],
                    "scope": decision.get("scope"),
                    "preflight_observed_at": (decision.get("l23_preflight") or {}).get("observed_at"),
                    "valid_until": decision.get("valid_until"),
                    "key": key, "sha256": actual_hash}
        if not absence and decision.get('reason') == 'l1_and_l23_address_resolution_failed':
            preflight = decision["l23_preflight"]
            activity["l1_address_observation"] = decision["l1_address_observation"]
            activity["l23_failure"] = {
                "failure_kind": preflight["failure_kind"],
                "error_type": preflight.get("error_type"),
                "reason": preflight.get("reason"),
                "layer_network_started": preflight.get("layer_network_started")}
        out.update(status="COMPLETED", verdict="UNDETERMINED", route=ledger,
                   judgment_status=("not_requested_dns_name_nonexistent_at_scan" if absence else
                                    "not_requested_url_unreachable_at_scan"),
                   stage="COMPLETED", stage_ko=("관측 시점 DNS 이름 부재" if absence else
                                                  "이번 검사 환경에서 URL 주소 확인 실패"),
                   url_activity=activity)
        return _json(200, out)

    if ledger == "TARGET_BLOCKED":
        out.update(status="COMPLETED", verdict="UNDETERMINED", route="TARGET_BLOCKED",
                   block_reason=s("block_reason"), judgment_status="not_requested_target_blocked",
                   stage="BLOCKED", stage_ko="접속 안전 정책 차단")
        return _json(200, out)

    # ── 게이트 차단 (사설 대역 등) ─────────────────────────────
    if ledger == "GATE_BLOCKED":
        out.update(status="COMPLETED", verdict="UNDETERMINED", route="BLOCKED",
                   stage="BLOCKED", stage_ko="접속 제한으로 분석 중단",
                   judgment={
                       "verdict": "UNDETERMINED",
                       "confidence": 0.0,
                       "rationale": ["L1 게이트가 사설·예약 대역으로 판정해 스캐너를 기동하지 않음"]
                                    + _notes(s("l1_key")),
                       "limitations": ["대상에 접촉하지 않았으므로 콘텐츠 기반 판단 불가",
                                       "접속하지 못했다는 사실은 안전의 근거가 아니다"],
                       "recommended_actions": ["공인 대역에 있는 URL로 다시 제출"],
                       "coverage": {"layers_run": ["l0", "l1"],
                                    "layers_skipped": ["gate", "l2", "l3", "l4"],
                                    "reason_skipped": "L1 게이트 차단"},
                       "source": "ledger"})
        return _json(200, out)

    # ── 판정 완료 ──────────────────────────────────────────────
    if ledger == "JUDGED":
        final = s("final_verdict") or "PENDING"
        placeholder = final in ("PENDING", "", None)
        if s("judgment_contract_version") == "fact-interpretation-selection-2":
            key = s("judgment_key")
            expected = f"judgments/{scan_id}/{attempt}.json"
            judgment = _load(key) if key == expected else None
            prefix = f"judgments/{scan_id}/{attempt}/v2/"
            final_key = s("final_key")
            specs = {name: (_load, prefix + filename + '.json') for name, filename in (
                ('selection', 'selection'), ('review', 'review'), ('processing', 'processing'),
                ('saved_consumer', 'consumer'), ('response', 'response'),
                ('request_claim', 'request-claim'), ('transport', 'transport'))}
            specs['request_bytes'] = (_load_bytes, prefix + 'request.json')
            if final_key == f"records/{scan_id}/{attempt}/final/final.json":
                specs['final_doc'] = (_load, final_key)
            if isinstance(judgment, dict) and judgment.get('view_key') == prefix + 'view.json':
                specs['view'] = (_load, prefix + 'view.json')
            artifacts = _load_many(specs)
            final_doc, view = artifacts.get('final_doc'), artifacts.get('view')
            selection, review = artifacts['selection'], artifacts['review']
            processing, saved_consumer = artifacts['processing'], artifacts['saved_consumer']
            request_bytes, response = artifacts['request_bytes'], artifacts['response']
            request_claim, transport = artifacts['request_claim'], artifacts['transport']
            if (not isinstance(judgment, dict) or judgment.get("context_key") != final_key or
                    not _valid_v2_result(scan_id, attempt, s("url"), final, judgment,
                                         final_doc, view, selection, review, processing,
                                         saved_consumer, request_bytes, response,
                                         request_claim, transport)):
                out.update(status="FAILED", verdict="UNDETERMINED",
                           error="judgment_v2_artifact_unavailable_or_mismatched")
                return _json(200, out)
            out.update(status="COMPLETED", verdict=final,
                       judgment_contract_version="fact-interpretation-selection-2",
                       judgment=judgment, route=s("reach_state", "ACTIVE"),
                       stage="COMPLETED", stage_ko="판정 완료")
            if judgment.get("coverage"):
                out["coverage"] = judgment["coverage"]
            return _json(200, out)
        out.update(status="COMPLETED",
                   verdict="UNDETERMINED" if placeholder else final,
                   route=s("reach_state", "ACTIVE"), stage="COMPLETED",
                   stage_ko="판정 결과 미확정" if placeholder else "판정 완료")

        judgment = _load(s("judgment_key"))
        if not judgment:
            judgment = {
                "verdict": out["verdict"],
                "confidence": 0.0,
                "rationale": _notes(s("l0_key")) + _notes(s("l1_key")),
                "limitations": ["판정 본문 파일을 읽지 못해 장부 값만 표시함"]
                               + ([] if BUCKET else ["Evidence 버킷 미설정"]),
                "recommended_actions": [],
                "source": "ledger",
            }
        out["judgment"] = judgment

        # 종합본의 커버리지를 위로 끌어올린다 - 확장이 '무엇을 못 봤는지'를 보여줄 수 있게
        cov = judgment.get("coverage")
        if not cov:
            f = _load(s("final_key"))
            cov = (f or {}).get("coverage")
        if cov:
            out["coverage"] = cov
        return _json(200, out)

    out.update(status="RUNNING")
    print(json.dumps({"msg": "unknown_ledger_status", "status": ledger, "job_id": scan_id}))
    return _json(200, out)
