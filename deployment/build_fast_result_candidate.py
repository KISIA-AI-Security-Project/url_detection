"""Build local fast-result-1 Lambda ZIPs and an explicit ASL candidate; no AWS calls."""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = "fast-result-1"
BUCKET = "team5-evidence-998301375101-ap-northeast-2-an"
ARN_RE = re.compile(r"arn:aws:lambda:ap-northeast-2:998301375101:function:team5[-_][A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)?\Z")
QWEN_STATES = {"QwenInit", "QwenReady", "QwenWaitLimit", "QwenWait", "QwenIncrement", "QwenWaitTimedOut"}


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _split_assignments(value):
    """Split DynamoDB clauses without splitting if_not_exists(a, b)."""
    rows, start, depth = [], 0, 0
    for index, char in enumerate(value):
        depth += (char == "(") - (char == ")")
        if char == "," and depth == 0:
            rows.append(value[start:index].strip())
            start = index + 1
    rows.append(value[start:].strip())
    return [row for row in rows if row]


def _update(params, assignments, values, *, remove=()):
    """Extend the existing update; retain attempt allocation and progress fields."""
    text = params["UpdateExpression"]
    matches = list(re.finditer(r"\b(SET|REMOVE|ADD|DELETE)\s+", text))
    clauses = {m.group(1): _split_assignments(text[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)])
               for i, m in enumerate(matches)}
    if not matches or matches[0].start() != 0:
        raise ValueError("unsupported_dynamodb_update_expression")
    names = params.get("ExpressionAttributeNames", {})

    def field(row):
        name = row.split("=", 1)[0].strip().split(" ", 1)[0]
        return names.get(name, name)

    replaced = {field(row) for row in assignments} | set(remove)
    for kind in clauses:
        clauses[kind] = [row for row in clauses[kind] if field(row) not in replaced]
    clauses.setdefault("SET", []).extend(assignments)
    clauses.setdefault("REMOVE", []).extend(dict.fromkeys(remove))
    params["UpdateExpression"] = " ".join(kind + " " + ", ".join(clauses[kind])
                                          for kind in ("SET", "REMOVE", "ADD", "DELETE") if clauses.get(kind))
    params.setdefault("ExpressionAttributeValues", {}).update(values)
    expressions = " ".join(str(v) for k, v in params.items() if k.endswith("Expression"))
    tokens = set(re.findall(r"[#:][A-Za-z0-9_]+", expressions))
    for name in ("ExpressionAttributeNames", "ExpressionAttributeValues"):
        if name in params:
            params[name] = {k: v for k, v in params[name].items() if k in tokens}
            if not params[name]:
                del params[name]


def _check_graph(machine):
    """Check local transition names, including existing parallel branch scopes."""
    states = machine["States"]
    if machine["StartAt"] not in states:
        raise ValueError("missing_start_state")

    def check(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("Next", "Default") and child not in states:
                    raise ValueError("missing_transition_state:" + child)
                elif key == "Branches":
                    for branch in child:
                        _check_graph(branch)
                elif key in ("Iterator", "ItemProcessor"):
                    _check_graph(child)
                else:
                    check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    for state in states.values():
        check(state)


def _presence(path):
    return {"Variable": path, "IsPresent": True}


def patch_model_selection_definition(original):
    """Narrow patch of an existing Fast machine, including prepared callbacks.

    Prepared callbacks may replace the entire state with a worker's saved state.
    Read the immutable execution input immediately before Judgment so a selected
    model cannot be dropped or overwritten by that replacement.
    """
    result = deepcopy(original)
    states = result["States"]
    task = states.get("JudgmentTask", {})
    expected = {"job_id.$", "attempt.$", "url.$", "context_key.$", "context_sha256.$"}
    if task.get("Type") != "Task" or set(task.get("Parameters", {}).get("Payload", {})) != expected:
        raise ValueError("explicit_fast_judgment_payload_required")
    names = {"HasModelSelection", "UseModelSelection", "DefaultModelSelection"}
    if names & states.keys():
        raise ValueError("model_selection_states_already_present")

    def redirect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("Next", "Default") and child == "JudgmentTask":
                    value[key] = "HasModelSelection"
                elif key != "Branches":
                    redirect(child)
        elif isinstance(value, list):
            for child in value:
                redirect(child)
    redirect(states)
    if result["StartAt"] == "JudgmentTask":
        result["StartAt"] = "HasModelSelection"
    states["HasModelSelection"] = {"Type": "Choice", "Choices": [
        {"Variable": "$$.Execution.Input.model_selection", "IsPresent": True, "Next": "UseModelSelection"}],
        "Default": "DefaultModelSelection"}
    states["UseModelSelection"] = {"Type": "Pass",
        "Parameters": {"selected.$": "$$.Execution.Input.model_selection"},
        "ResultPath": "$.model_options", "Next": "JudgmentTask"}
    states["DefaultModelSelection"] = {"Type": "Pass", "Result": {"selected": {}},
        "ResultPath": "$.model_options", "Next": "JudgmentTask"}
    task["Parameters"]["Payload"]["model_selection.$"] = "$.model_options.selected"
    _check_graph(result)
    return result


def patch_definition(original, *, context_arn, judgment_arn, result_arn, task_timeout=75,
                     model_choices_enabled=False):
    """Adapt the stored direct/queued explicit-Context ASL contract, not a live machine."""
    for arn in (context_arn, judgment_arn, result_arn):
        if not isinstance(arn, str) or not ARN_RE.fullmatch(arn):
            raise ValueError("explicit_project_lambda_arn_required")
    if len({context_arn, judgment_arn, result_arn}) != 3:
        raise ValueError("distinct_lambda_roles_required")
    if type(task_timeout) is not int or task_timeout <= 0:
        raise ValueError("invalid_task_timeout")
    result = deepcopy(original)
    states = result["States"]
    required = {"AllocAttempt", "ContextTask", "MarkContext", "JudgmentTask", "MarkJudged", "MarkFailed", "PipelineFailed"}
    if not required <= states.keys() or states["ContextTask"]["Type"] != "Task":
        raise ValueError("explicit_context_state_contract_required")
    if set(name for name in states if name.startswith("Qwen")) - QWEN_STATES:
        raise ValueError("unsupported_qwen_state_contract")
    tables = {states[name]["Parameters"]["TableName"]
              for name in ("AllocAttempt", "MarkContext", "MarkJudged", "MarkFailed")}
    if len(tables) != 1 or not all(isinstance(t, str) for t in tables):
        raise ValueError("same_explicit_jobs_table_required")
    # The supplied baseline already carries all four joined layer references.
    payload = states["ContextTask"]["Parameters"]["Payload"]
    if not {"job_id.$", "attempt.$", "url.$", "layers", "url_activity.$"} <= payload.keys():
        raise ValueError("context_payload_contract_required")
    if set(payload["layers"]) != {"l0.$", "l1.$", "l2.$", "l3.$"}:
        raise ValueError("four_layer_context_payload_required")
    states["ContextTask"]["Parameters"]["FunctionName"] = context_arn
    states["ContextTask"]["TimeoutSeconds"] = 60
    if "ActivityTask" in states:
        states["ActivityTask"]["Parameters"]["FunctionName"] = context_arn
        states["ActivityTask"]["TimeoutSeconds"] = 60

    _update(states["AllocAttempt"]["Parameters"], [
        "result_contract_version = :fast_contract", "judgment_status = :fast_pending"], {
            ":fast_contract": {"S": VERSION}, ":fast_pending": {"S": "pending"}},
        remove=("fast_result_key", "context_revision", "result_revision", "final_verdict",
                "judgment_key", "judgment_contract_version"))
    _update(states["MarkContext"]["Parameters"], [
        "result_contract_version = :fast_contract", "fast_result_key = :fast_key",
        "context_revision = :fast_context_revision"], {
            ":fast_contract": {"S": VERSION},
            ":fast_key": {"S.$": "$.context.ctx.fast_result_key"},
            ":fast_context_revision": {"S.$": "$.context.ctx.context_revision"}})

    task = states["JudgmentTask"]
    task.update(Type="Task", Resource="arn:aws:states:::lambda:invoke",
                Parameters={"FunctionName": judgment_arn, "Payload": {
                    "job_id.$": "$.job_id", "attempt.$": "$.alloc.attempt", "url.$": "$.url",
                    "context_key.$": "$.context.ctx.final_key",
                    "context_sha256.$": "$.context.ctx.context_sha256"}},
                ResultSelector={"judgment.$": "$.Payload"}, ResultPath="$.final",
                TimeoutSeconds=task_timeout, Next="JudgmentSucceeded",
                Comment="Direct fast-result-1 Judgment. Service status is separate from URL verdict.")
    task.pop("End", None)
    common = [_presence("$.final.judgment." + name) for name in (
        "judgment_status", "fast_result_key", "context_revision", "result_revision", "result_contract_version")]
    common.append({"Variable": "$.final.judgment.result_contract_version", "StringEquals": VERSION})
    states["JudgmentSucceeded"] = {"Type": "Choice", "Choices": [
        {"And": common + [{"Variable": "$.final.judgment.judgment_status", "StringEquals": "accepted"},
                            _presence("$.final.judgment.verdict"), _presence("$.final.judgment.judgment_key")],
         "Next": "MarkJudged"},
        {"And": common + [{"Or": [
            {"Variable": "$.final.judgment.judgment_status", "StringEquals": status} for status in ("failed", "invalid")]},
            {"Variable": "$.final.judgment.verdict", "IsPresent": False}], "Next": "MarkFastResultFailed"}],
        "Default": "JudgmentInvalidReturn"}
    states["JudgmentInvalidReturn"] = {"Type": "Pass", "Result": {
        "Error": "JudgmentInvalidReturn", "Cause": "No usable fast-result-1 status and result reference"},
        "ResultPath": "$.error", "Next": "MarkFailed"}

    _update(states["MarkJudged"]["Parameters"], [
        "result_contract_version = :fast_contract", "judgment_contract_version = :fast_contract",
        "judgment_status = :fast_accepted", "fast_result_key = :fast_key",
        "context_revision = :fast_context_revision", "result_revision = :fast_result_revision"], {
            ":fast_contract": {"S": VERSION}, ":fast_accepted": {"S": "accepted"},
            ":fast_key": {"S.$": "$.final.judgment.fast_result_key"},
            ":fast_context_revision": {"S.$": "$.final.judgment.context_revision"},
            ":fast_result_revision": {"S.$": "$.final.judgment.result_revision"}})
    # Keep the existing job/table/update timestamp projection; the failed response has no verdict.
    failed = deepcopy(states["MarkJudged"])
    _update(failed["Parameters"], ["#st = :fast_failed", "judgment_status = :fast_status"], {
        ":fast_failed": {"S": "FAILED"}, ":fast_status": {"S.$": "$.final.judgment.judgment_status"}},
        remove=("final_verdict", "judgment_key"))
    failed["Parameters"].setdefault("ExpressionAttributeNames", {})["#st"] = "status"
    failed.pop("End", None)
    failed["Next"] = "PipelineFailed"
    states["MarkFastResultFailed"] = failed
    _update(states["MarkFailed"]["Parameters"], [
        "result_contract_version = :fast_contract", "judgment_status = :fast_failed"], {
            ":fast_contract": {"S": VERSION}, ":fast_failed": {"S": "failed"}},
        remove=("final_verdict", "judgment_key"))
    if "MarkSafetyBlocked" in states:
        _update(states["MarkSafetyBlocked"]["Parameters"], ["judgment_status = :fast_not_requested"],
                {":fast_not_requested": {"S": "not_requested"}})

    # Enter the direct task where the queue counter used to be initialized.
    def reconnect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("Next", "Default") and child == "QwenInit":
                    value[key] = "JudgmentTask"
                else:
                    reconnect(child)
        elif isinstance(value, list):
            for child in value:
                reconnect(child)
    for name in QWEN_STATES:
        states.pop(name, None)
    reconnect(result)
    result["Comment"] = "Local fast-result-1 candidate; explicit Context, direct Judgment, private handoff, public Result."
    _check_graph(result)
    return patch_model_selection_definition(result) if model_choices_enabled else result


def _copy_tree(source, target):
    for path in sorted(source.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            destination = target / path.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)


def _zip_tree(source, target):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                item = zipfile.ZipInfo(path.relative_to(source).as_posix(), (2026, 10, 2, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(item, path.read_bytes())
    return _hash(target.read_bytes())


IMPORT_PROBE = r'''
import io,json,os,pathlib,sys,types
root=pathlib.Path(sys.argv[1]).resolve(); role=sys.argv[2]
sys.path.insert(0,str(root))
if role=='runtime':
    import evidence_pipeline.aws_runtime as runtime
    import evidence_pipeline.aws_fast_result as fast
    import evidence_pipeline.fast_judgment as judgment
    import dns
    assert callable(runtime.handler) and callable(fast.load_deep_input)
    assert judgment.PROMPT.strip()
    modules=[runtime.__file__,fast.__file__,judgment.__file__,dns.__file__]
    assert all(pathlib.Path(p).resolve().is_relative_to(root) for p in modules)
    print(json.dumps({'status':'passed','role':role,'imports':[str(pathlib.Path(p).relative_to(root)) for p in modules],
                      'prompt_bytes':len(judgment.PROMPT.encode()),'aws_calls':0,'model_calls':0}))
else:
    os.environ['JOBS_TABLE']='Offline-fast-result-table'
    os.environ['EVIDENCE_BUCKET']='team5-evidence-998301375101-ap-northeast-2-an'
    import fast_public
    job='a'*32
    context={'context_revision':'offline-context','details':{'context_revision':'offline-context','sections':[],'facts':[]}}
    public=fast_public.make_public_result(job,1,context=context,status='accepted',
              judgment={'verdict':'UNKNOWN','summary':'패키지 확인용 합성 응답입니다.','reasons':[]})
    class DDB:
        def get_item(self,**kw):
            assert kw['TableName']=='Offline-fast-result-table' and kw['Key']=={'job_id':{'S':job}}
            return {'Item':{'job_id':{'S':job},'url':{'S':'https://example.org/'},'attempt':{'N':'1'},
                 'status':{'S':'JUDGED'},'result_contract_version':{'S':'fast-result-1'},
                 'judgment_status':{'S':'accepted'},'context_revision':{'S':'offline-context'},
                 'result_revision':{'S':public['result_revision']},
                 'fast_result_key':{'S':f'records/{job}/1/fast/result.json'}}}
    class S3:
        def get_object(self,**kw):
            assert kw=={'Bucket':os.environ['EVIDENCE_BUCKET'],'Key':f'records/{job}/1/fast/result.json'}
            return {'Body':io.BytesIO(json.dumps(public,ensure_ascii=False).encode())}
    boto3=types.ModuleType('boto3')
    def client(name,*args,**kwargs):
        assert name in ('s3','dynamodb')
        return S3() if name=='s3' else DDB()
    boto3.client=client;sys.modules['boto3']=boto3
    import app
    response=app.handler({'pathParameters':{'scanId':job}},None)
    assert response['statusCode']==200
    body=json.loads(response['body']);assert body==public
    assert not any(name.startswith('evidence_pipeline') for name in sys.modules)
    legacy_imports=[]
    if (root/'evidence_pipeline').is_dir():
        import evidence_pipeline.aws_judgment_v2 as legacy_gateway
        import evidence_pipeline.judgment_contract_v2 as legacy_contract
        import evidence_pipeline.judgment_view_v2 as legacy_view
        legacy_imports=[legacy_gateway.__file__,legacy_contract.__file__,legacy_view.__file__]
        assert all(pathlib.Path(p).resolve().is_relative_to(root) for p in legacy_imports)
        request={'model':'offline','max_tokens':100,'temperature':0,'system':legacy_gateway.PROMPT,'messages':[]}
        assert app._valid_v2_request_contract(request,{}) is True
    print(json.dumps({'status':'passed','role':role,'imports':['app.py','fast_public.py'],
                      'legacy_imports':[str(pathlib.Path(p).relative_to(root)) for p in legacy_imports],
                      'result_package_mode':'compatible' if legacy_imports else 'fast_only',
                      'input_kind':'synthetic persisted accepted UNKNOWN; no model execution',
                      'handler_response':body,'aws_calls':0,'model_calls':0},ensure_ascii=False))
'''


def verify_packages(output):
    """Extract away from the repo, disable site/PYTHONPATH, import, and invoke Result with SDK doubles."""
    reports = []
    with tempfile.TemporaryDirectory(prefix="fast-result-import-") as temp:
        for package, role in (("context.zip", "runtime"), ("judgment.zip", "runtime"), ("result.zip", "result")):
            extracted = Path(temp) / package.removesuffix(".zip")
            with zipfile.ZipFile(output / package) as archive:
                archive.extractall(extracted)
            run = subprocess.run([sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", IMPORT_PROBE,
                                  str(extracted), role], cwd=extracted, capture_output=True, text=True,
                                 encoding="utf-8", timeout=45)
            if run.returncode:
                raise RuntimeError(f"isolated_package_import_failed:{package}\n{run.stderr[-5000:]}")
            report = json.loads(run.stdout)
            reports.append({"package": package, "sha256": _hash((output / package).read_bytes()), **report})
    result = {"status": "passed", "isolation": "temporary extraction outside repository; Python -I -S; SDK doubles only",
              "live_aws_verified": False, "packages": reports}
    _write_json(output / "offline-import-verification.json", result)
    return result


def build(definition_path, output, *, context_arn, judgment_arn, result_arn, model, base_url=None,
          secret_id=None, provider='anthropic', model_timeout=50, lambda_timeout=60, task_timeout=75, max_tokens=4096,
          context_max_bytes=400_000, omit_temperature=False, output_effort=None,
          fast_only_result=False, verify_imports=True, source_root=ROOT, model_choices=None):
    definition_path, output, source_root = Path(definition_path), Path(output), Path(source_root)
    if provider not in ('anthropic', 'bedrock') or not model.strip():
        raise ValueError('explicit_provider_and_model_required')
    parsed = urlsplit(base_url or '')
    if provider == 'anthropic' and (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or
            parsed.fragment or not (secret_id or '').strip()):
        raise ValueError("explicit_model_https_origin_and_secret_id_required")
    if not 0 < model_timeout < lambda_timeout < task_timeout or max_tokens <= 0 or context_max_bytes <= 0:
        raise ValueError("invalid_timeout_or_budget_configuration")
    if type(omit_temperature) is not bool or output_effort not in (None, "low", "medium", "high", "xhigh", "max"):
        raise ValueError("invalid_anthropic_generation_configuration")
    choice_env = {}
    if model_choices is not None:
        from evidence_pipeline.model_choices import model_configuration
        configured = model_configuration({"FAST_MODEL_CHOICES_JSON": json.dumps(model_choices)})
        if any(profile["provider"] != provider or profile["timeout"] >= lambda_timeout
               for profile in configured["models"].values()):
            raise ValueError("model_choices_provider_or_deadline_mismatch")
        if configured["models"][configured["default_model_choice"]]["model"] != model:
            raise ValueError("default_choice_must_match_legacy_model")
        choice_env["FAST_MODEL_CHOICES_JSON"] = json.dumps(configured, ensure_ascii=False, separators=(",", ":"))
    original = json.loads(definition_path.read_text(encoding="utf-8"))
    candidate = patch_definition(original, context_arn=context_arn, judgment_arn=judgment_arn,
                                 result_arn=result_arn, task_timeout=task_timeout,
                                 model_choices_enabled=model_choices is not None)
    dns_spec = importlib.util.find_spec("dns")
    if dns_spec is None or not dns_spec.origin:
        raise ValueError("dnspython_required_for_runtime_package")
    output.mkdir(parents=True, exist_ok=False)
    runtime = output / "runtime-payload"
    _copy_tree(source_root / "evidence_pipeline", runtime / "evidence_pipeline")
    _copy_tree(Path(dns_spec.origin).parent, runtime / "dns")
    result_payload = output / "result-payload"
    result_payload.mkdir()
    if not fast_only_result:
        _copy_tree(runtime, result_payload)
    shutil.copyfile(source_root / "deployment/result/app.py", result_payload / "app.py")
    shutil.copyfile(source_root / "deployment/api_timing.py", result_payload / "api_timing.py")
    shutil.copyfile(source_root / "evidence_pipeline/fast_public.py", result_payload / "fast_public.py")
    package_hashes = {role: _zip_tree(runtime if role != "result" else result_payload, output / f"{role}.zip")
                      for role in ("context", "judgment", "result")}
    if model_choices is not None:
        gate_payload = output / "gate-payload"
        (gate_payload / "evidence_pipeline").mkdir(parents=True)
        for filename in ("__init__.py", "model_choices.py"):
            shutil.copyfile(source_root / "evidence_pipeline" / filename, gate_payload / "evidence_pipeline" / filename)
        shutil.copyfile(source_root / "deployment/gate/app.py", gate_payload / "app.py")
        shutil.copyfile(source_root / "deployment/api_timing.py", gate_payload / "api_timing.py")
        package_hashes["gate"] = _zip_tree(gate_payload, output / "gate.zip")
    _write_json(output / "definition-original.json", original)
    _write_json(output / "definition.json", candidate)
    table = candidate["States"]["AllocAttempt"]["Parameters"]["TableName"]
    common = {"OUTPUT_BUCKET": BUCKET, "EVIDENCE_RESULT_CONTRACT": VERSION}
    generation = {}
    if omit_temperature:
        generation["ANTHROPIC_OMIT_TEMPERATURE"] = "1"
    if output_effort is not None:
        generation["ANTHROPIC_OUTPUT_EFFORT"] = output_effort
    connection = ({"JUDGMENT_PROVIDER": "bedrock"} if provider == 'bedrock' else
                  {"ANTHROPIC_BASE_URL": base_url, "LLM_SECRET_ID": secret_id})
    contract = {"result_contract_version": VERSION, "aws_actions": 0, "deployment_performed": False,
        "lambda": {
            "context": {"arn": context_arn, "package": "context.zip", "handler": "evidence_pipeline.aws_runtime.handler",
                        "timeout_seconds": 55, "environment": {**common, "EVIDENCE_ROLE": "context", "CONTEXT_MAX_BYTES": str(context_max_bytes)}},
            "judgment": {"arn": judgment_arn, "package": "judgment.zip", "handler": "evidence_pipeline.aws_runtime.handler",
                         "timeout_seconds": lambda_timeout, "environment": {**common, "EVIDENCE_ROLE": "judgment",
                             **connection, "JUDGMENT_MODEL": model,
                             "LLM_TIMEOUT_SECONDS": str(model_timeout), "JUDGMENT_MAX_TOKENS": str(max_tokens), **generation, **choice_env}},
            "result": {"arn": result_arn, "package": "result.zip", "handler": "app.handler",
                       "package_mode": "fast_only" if fast_only_result else "compatible",
                       "environment": {"JOBS_TABLE": table, "EVIDENCE_BUCKET": BUCKET}}},
        "result_api": {"lambda_arn": result_arn, "event": {"pathParameters": {"scanId": "32-character lowercase hex job_id"}},
                       "note": "Result is a polling API consumer, not an SFN task. API integration is not changed by this tool."},
        "iam_requirements": {
            "context": [f"s3:GetObject on {BUCKET}/raw/{{job}}/{{attempt}}/* and records/{{job}}/{{attempt}}/*",
                        f"s3:PutObject on {BUCKET}/records/{{job}}/{{attempt}}/final/* and fast/*"],
            "judgment": [f"s3:GetObject and s3:PutObject on {BUCKET}/records/{{job}}/{{attempt}}/fast/*",
                         f"s3:GetObject on {BUCKET}/records/{{job}}/{{attempt}}/final/*",
                         "bedrock:InvokeModel on the supplied inference profile and its foundation models" if provider == 'bedrock'
                         else "secretsmanager:GetSecretValue for the supplied secret ID"],
            "result": [f"dynamodb:GetItem on {table}", f"s3:GetObject on {BUCKET}/records/{{job}}/{{attempt}}/fast/pending.json and result.json",
                       *([] if fast_only_result else ["Retain existing legacy result read permissions for its records and judgments prefixes"])],
            "state_machine": ["lambda:InvokeFunction on the supplied Context and Judgment ARNs", f"dynamodb:UpdateItem on {table}"]},
        "preserved": ["collector functions and safety/activity decisions", "existing VPC, role and API settings must be supplied at deployment"],
        "not_verified": ["Lambda runtime and SDK versions", "live IAM and API route", "actual provider model quality and timing", "deployed SFN revision"]}
    if model_choices is not None:
        contract["model_selection"] = {
            "server_environment": choice_env,
            "gate_environment_additions": {**choice_env, "FAST_MODEL_SELECTION_ENABLED": "1"},
            "gate_package": "gate.zip", "gate_handler": "app.handler",
            "api_environment_additions": choice_env,
            "required_rollout": ["Publish the supplied Gate package with its existing table and prepared route settings",
                                 "Point that Gate's prepared state machine to definition.json before enabling selection",
                                 "Configure identical catalog JSON on Web API, Gate and Judgment",
                                 "Point Web API FAST_GATE_ARN to that published Gate; the old pinned Gate ignores selection"],
            "availability": "Operator-configured Claude entries only; no provider access was tested by this build"}
    _write_json(output / "deployment-contract.json", contract)
    manifest = {"schema_version": "fast-result-candidate-1", "result_contract_version": VERSION,
                "source_definition": str(definition_path.resolve()), "source_definition_sha256": _hash(definition_path.read_bytes()),
                "candidate_definition_sha256": _hash((output / "definition.json").read_bytes()),
                "functions": {"context": context_arn, "judgment": judgment_arn, "result": result_arn},
                "packages": {role: {"file": f"{role}.zip", "sha256": digest} for role, digest in package_hashes.items()},
                "source_files": {path.relative_to(source_root).as_posix(): _hash(path.read_bytes())
                                 for path in sorted((source_root / "evidence_pipeline").rglob("*"))
                                 if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"},
                "builder_sha256": _hash(Path(__file__).read_bytes()),
                "result_source_sha256": _hash((result_payload / "app.py").read_bytes()),
                "result_package_mode": "fast_only" if fast_only_result else "compatible",
                "aws_actions": 0, "import_verification": "pending"}
    _write_json(output / "manifest.json", manifest)
    if verify_imports:
        verify_packages(output)
        manifest["import_verification"] = "passed"
        _write_json(output / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fast-only-result", action="store_true",
                        help="Build the optional three-file Result package for a dedicated fast-result-1 endpoint")
    parser.add_argument("--omit-temperature", action="store_true",
                        help="Omit the Anthropic Messages temperature field; legacy default is temperature=0")
    parser.add_argument("--output-effort", choices=("low", "medium", "high", "xhigh", "max"),
                        help="Explicit Anthropic output_config.effort; no model substitution or automatic setting")
    parser.add_argument('--provider', choices=('anthropic', 'bedrock'), default='anthropic')
    parser.add_argument('--model-choices', type=Path, help='Reviewed server Claude catalog JSON; enables the complete selection route')
    for name in ("base-url", "secret-id"):
        parser.add_argument('--' + name)
    for name in ("context-arn", "judgment-arn", "result-arn", "model"):
        parser.add_argument("--" + name, required=True)
    for name, default in (("model-timeout", 50), ("lambda-timeout", 60), ("task-timeout", 75),
                          ("max-tokens", 4096), ("context-max-bytes", 400_000)):
        parser.add_argument("--" + name, type=int, default=default)
    args = vars(parser.parse_args())
    if args["model_choices"] is not None:
        args["model_choices"] = json.loads(args["model_choices"].read_text(encoding="utf-8"))
    args["definition_path"] = args.pop("definition")
    manifest = build(**args)
    print(json.dumps({"output": str(args["output"].resolve()), "result_contract_version": VERSION,
                      "import_verification": manifest["import_verification"], "aws_actions": 0}, ensure_ascii=False))


if __name__ == "__main__":
    main()
