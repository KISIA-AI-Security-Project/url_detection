"""Team5-gate — API Gateway가 처음 만나는 Lambda.

  1) SSRF/정책 게이트로 URL을 거른다
  2) 장부(DynamoDB)에 PENDING 항목을 '먼저' 쓴다
  3) Step Functions 실행을 시작한다
  4) 202 + scanId를 즉시 돌려준다  (파이프라인은 3~6분, API Gateway 상한은 29초)

  외부 계약은 scanId, 내부(DynamoDB·Step Functions)는 job_id다. 번역은 이 파일과
  Team5-result 두 곳에서만 일어난다. 값 자체는 같은 32자 hex다.

환경 변수
  JOBS_TABLE        = Team5-firstDB
  STATE_MACHINE_ARN = arn:aws:states:ap-northeast-2:998301375101:stateMachine:...
"""
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from urllib.parse import urlparse

import boto3
from evidence_pipeline.model_choices import ModelChoiceError, select_model, validate_selection

try:
    from api_timing import invocation, span
except ImportError:
    from deployment.api_timing import invocation, span

ddb = boto3.client("dynamodb")
sfn = boto3.client("stepfunctions")

TABLE = os.environ["JOBS_TABLE"]
SM_ARN = os.environ["STATE_MACHINE_ARN"]
PREPARED_SM_ARN = os.environ.get("PREPARED_STATE_MACHINE_ARN", "")
PREPARED_PREFIX = os.environ.get("PREPARED_JOB_PREFIX", "")
if bool(PREPARED_SM_ARN) != bool(PREPARED_PREFIX) or (
        PREPARED_PREFIX and not re.fullmatch(r"[0-9a-f]{1,16}", PREPARED_PREFIX)):
    raise ValueError("prepared_pipeline_configuration_invalid")
TTL_DAYS = 30
BLOCKED_PORTS = {22, 23, 25, 445, 3306, 3389, 5432, 6379, 9200, 11211, 27017}
ID_RE = re.compile(r"^[0-9a-f]{32}$")
# 진행 중으로 보는 장부 상태. Team5-result의 같은 이름 집합과 맞춰 둔다.
RUNNING_STATES = {
    "PENDING", "L0_DONE", "L1_DONE", "REACH_DONE",
    "COLLECT_DONE", "EXPLORE_DONE", "FINAL_DONE", "COLLECT_SKIPPED",
}


def _json(status, body):
    return {"statusCode": status,
            "headers": {"content-type": "application/json; charset=utf-8"},
            "body": json.dumps(body, ensure_ascii=False)}


def policy_gate(raw):
    """통과하면 (정규화된 URL, None), 막히면 (None, 사유).

    이 시스템은 '사용자가 준 URL에 서버가 접속하는' 구조다 - SSRF의 교과서적 정의다.
    네트워크(사설 서브넷·IMDS 없음)와 이 코드, 두 겹으로 막는다.
    """
    if not raw or len(raw) > 2048:
        return None, "URL이 비었거나 2048자를 넘습니다."
    try:
        u = urlparse(raw.strip())
    except ValueError:                      # 잘못된 IPv6 리터럴 등
        return None, "URL 형식이 올바르지 않습니다."
    if u.scheme not in ("http", "https"):
        return None, f"허용되지 않는 스킴: {u.scheme!r} (http/https만)"
    if u.username or u.password:
        return None, "URL에 자격증명(user:pass@)을 포함할 수 없습니다."
    if not u.hostname:
        return None, "호스트가 없습니다."
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:                      # ':99999' · ':8o8' 같은 입력은 여기서 던진다
        return None, "포트 번호가 올바르지 않습니다(0~65535)."
    if port in BLOCKED_PORTS:
        return None, f"차단된 포트: {port}"

    # 해석된 모든 A/AAAA 레코드를 검사한다. 하나라도 사설이면 거부.
    #
    # * 해석 '실패'는 차단 사유가 아니다. 미등록·삭제된 도메인을 여기서 400으로 끊으면
    #   "접속 실패는 안전이 아니라 확인 못 함"(reach INACTIVE -> UNDETERMINED) 경로를
    #   시연할 수 없다. 검사할 IP가 없으니 통과시킨다.
    #   (DNS rebinding을 완전히 막지는 못한다 - 한계로 문서에 남긴다.)
    try:
        infos = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return u.geturl(), None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return None, f"내부/예약 대역으로 해석됩니다: {ip}"
    return u.geturl(), None


def _pipeline_for(job_id):
    if PREPARED_SM_ARN and job_id.startswith(PREPARED_PREFIX):
        return PREPARED_SM_ARN
    return SM_ARN


def _new_job_id():
    value = uuid.uuid4().hex
    return PREPARED_PREFIX + value[len(PREPARED_PREFIX):] if PREPARED_SM_ARN else value


def _running_execution(job_id, state_machine_arn=None):
    """이 접수번호로 지금 돌고 있는 실행 이름. 없으면 None.

    실행 이름은 scan-{job_id} 또는 rescan-{job_id}-{epoch} 두 가지뿐이므로
    이름만 보면 판별된다. ListExecutions에 이름 접두어 필터가 없어서 RUNNING
    목록을 받아 훑는다 - 동시에 도는 분석이 수백 건이 되면 페이지를 넘겨야 하지만,
    지금 규모에서는 한 페이지로 충분하다.
    """
    try:
        with span('gate.sfn.list_executions'):
            page = sfn.list_executions(stateMachineArn=state_machine_arn or _pipeline_for(job_id),
                                       statusFilter="RUNNING", maxResults=100)
    except Exception as e:                      # noqa: BLE001
        # 조회가 실패했다고 접수를 막지는 않는다. 가드는 편의이지 정합성의 근거가 아니다.
        print(json.dumps({"msg": "list_executions_failed", "err": str(e)}))
        return None
    for ex in page.get("executions", []):
        name = ex.get("name", "")
        if name == f"scan-{job_id}" or name.startswith(f"rescan-{job_id}-"):
            return name
    return None


def _handle(event, _ctx, trace):
    # API Gateway payload 2.0 - 헤더 이름은 전부 소문자로 온다.
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _json(400, {"error": "본문이 JSON이 아닙니다."})
    if type(body) is not dict:
        return _json(400, {"error": "invalid_request"})
    selection = None
    if "model_choice" in body or "model_selection" in body or "reasoning_effort" in body:
        if os.environ.get("FAST_MODEL_SELECTION_ENABLED") != "1":
            return _json(503, {"error": "model_selection_unavailable"})
        try:
            if "reasoning_effort" in body and "model_choice" not in body:
                raise ModelChoiceError("model_choice_required")
            selection = select_model(body.get("model_choice"), **({"reasoning_effort": body["reasoning_effort"]}
                                     if "reasoning_effort" in body else {}))
            if "model_selection" in body and validate_selection(body["model_selection"]) != selection:
                raise ModelChoiceError("model_configuration_changed")
        except ModelChoiceError as error:
            return _json(400, {"error": str(error), "reason": "분석 모델 목록을 다시 확인해 주세요."})

    with span('gate.policy'):
        url, reason = policy_gate(body.get("url", ""))
    if reason:
        print(json.dumps({"msg": "gate_rejected", "reason": reason}, ensure_ascii=False))
        return _json(400, {"error": "policy_gate_rejected", "reason": reason})

    now = int(time.time())
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    # ── 재분석 경로 ────────────────────────────────────────────
    # 본문에 scanId가 오면 새 접수번호를 만들지 않고 그 번호로 다시 돌린다.
    # 상태머신의 AllocAttempt가 시도번호를 2, 3…으로 올리므로 S3에는
    # raw/{접수번호}/2/… 처럼 새 폴더가 생기고 이전 시도는 그대로 남는다.
    # 명세 규칙 4("재분석하면 새 시도번호 폴더")를 UI에서 쓸 수 있게 하는 유일한 통로다.
    reuse = str(body.get("scanId") or "").strip().lower()
    if reuse and not ID_RE.match(reuse):
        return _json(400, {"error": "bad_scan_id", "reason": "scanId는 소문자 hex 32자여야 합니다."})

    if reuse:
        # ★ 같은 접수번호로 두 실행이 동시에 돌면 장부의 fragments(진행 상태판)가 섞인다.
        #   새 시도의 AllocAttempt가 판을 비운 직후, 아직 살아 있는 이전 시도의 Mark*가
        #   자기 경로를 그 판에 써 넣기 때문이다. S3 조각은 시도별 폴더라 안전하지만
        #   상태판은 접수번호당 하나뿐이라 막을 방법이 없다.
        #   "접수번호 하나에 동시 분석 하나"를 여기서 강제한다.
        with span('gate.ddb.get_item'):
            cur = ddb.get_item(TableName=TABLE, Key={"job_id": {"S": reuse}}).get("Item")
        if not cur:
            return _json(404, {"error": "not_found", "scanId": reuse,
                               "reason": "장부에 없는 접수번호입니다."})

        # ★ 장부의 status로 판단하면 안 된다. 장부는 '마지막에 쓴 실행'의 상태라서,
        #   먼저 끝난 시도가 남긴 JUDGED가 아직 살아 있는 시도를 가려 버린다.
        #   (2026-08-23에 실제로 이 순서로 상태판이 섞였다.)
        #   유일하게 믿을 수 있는 것은 Step Functions에 직접 묻는 것이다.
        running = _running_execution(reuse, _pipeline_for(reuse))
        if running:
            return _json(409, {"error": "already_running", "scanId": reuse,
                               "execution": running,
                               "reason": "이 접수번호의 분석이 아직 진행 중입니다. 끝난 뒤 다시 시도하세요."})

    job_id = reuse or _new_job_id()      # 소문자 hex 32자 계약 유지
    state_machine_arn = _pipeline_for(job_id)
    if selection is not None and (not PREPARED_SM_ARN or state_machine_arn != PREPARED_SM_ARN):
        return _json(409, {"error": "model_selection_route_unsupported",
                           "reason": "이전 분석은 모델을 선택한 새 분석으로 요청해 주세요."})
    if trace is not None:
        trace.identify(job_id=job_id)

    if not reuse:
        # * 순서가 중요하다: 장부를 먼저 쓰고 그 다음 실행을 시작한다.
        #   뒤집으면 확장 프로그램의 첫 폴링이 404를 받는다.
        #   상태머신은 UpdateItem만 하므로 url을 넣어 주는 곳이 여기밖에 없다.
        item = {
                "job_id":        {"S": job_id},
                "url":           {"S": url},
                "status":        {"S": "PENDING"},
                "current_layer": {"S": "L0"},
                "created_at":    {"S": iso},
                "updatedAt":     {"S": iso},
                "ttl":           {"N": str(now + TTL_DAYS * 86400)},
            }
        if PREPARED_SM_ARN and state_machine_arn == PREPARED_SM_ARN:
            item.update(result_contract_version={"S": "fast-result-1"},
                        judgment_status={"S": "pending"})
        with span('gate.ddb.put_item'):
            ddb.put_item(TableName=TABLE, Item=item,
                         ConditionExpression="attribute_not_exists(job_id)")
    # 재분석일 때는 장부를 다시 쓰지 않는다. 덮어쓰면 이전 시도의 기록
    # (l0_key·fragments·attempt)이 통째로 날아간다. AllocAttempt가 갱신한다.

    # 실행 이름은 90일간 유일해야 한다. 재분석은 같은 job_id를 쓰므로
    # 초 단위 시각을 붙여 충돌을 피한다.
    exec_name = f"scan-{job_id}" if not reuse else f"rescan-{job_id}-{now}"
    execution_input = {"job_id": job_id, "url": url}
    if selection is not None:
        execution_input["model_selection"] = selection
    with span('gate.sfn.start_execution'):
        sfn.start_execution(
            stateMachineArn=state_machine_arn,
            name=exec_name,
            input=json.dumps(execution_input),
        )
    print(json.dumps({"msg": "rescan_accepted" if reuse else "accepted",
                      "job_id": job_id, "url": url}, ensure_ascii=False))

    accepted = {"scanId": job_id, "status": "PENDING",
                "rescan": bool(reuse), "pollUrl": f"/analyses/{job_id}"}
    if selection is not None:
        accepted.update(model_choice=selection["choice"], model_profile_sha256=selection["profile_sha256"],
                        reasoning_effort=selection["profile"]["output_effort"])
    return _json(202, accepted)


def handler(event, context):
    with invocation(event, context, role='gate') as trace:
        return _handle(event, context, trace)
