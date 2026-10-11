"""Run one authorized request with the installed, frozen L4 images."""
from datetime import datetime, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit
from uuid import uuid4

import boto3

from bootstrap import ROOT, docker_json, protect_guest_network, run


BUCKET = "team5-evidence-998301375101-ap-northeast-2-an"
REGION = "ap-northeast-2"


def status(s3, run_id, execution_status, **details):
    value = {"execution_status": execution_status, "updated_at": datetime.now(timezone.utc).isoformat(), **details}
    s3.put_object(Bucket=BUCKET, Key=f"l4/_runtime/{run_id}/worker-status.json",
                  Body=json.dumps(value).encode(), ContentType="application/json")


def actual_isolation(work, endpoint):
    code = """import json,os,urllib.request
bad=[k for k in os.environ if k.startswith(('AWS_', 'OPENAI_')) or 'API_KEY' in k]
try:
    urllib.request.urlopen('http://169.254.169.254/latest/meta-data/',timeout=2)
    blocked=False
except urllib.error.HTTPError:
    blocked=False
except (urllib.error.URLError,TimeoutError):
    blocked=True
print(json.dumps({'credential_environment_absent':not bad,'metadata_network_blocked':blocked}))
"""
    request = urllib.request.Request(endpoint + "/execute", headers={"Content-Type": "application/json"},
        data=json.dumps({"command": "python - <<'PY'\n" + code + "PY", "timeout_ms": 10000}).encode())
    with urllib.request.urlopen(request, timeout=20) as response:
        reply = json.load(response)
    checks = json.loads(reply["stdout"])
    (work / "isolation-check.json").write_text(json.dumps({"checks": checks, "bash_reply": reply}, indent=2))
    if reply["status"] != "success" or not reply["cleanup_confirmed"] or not all(checks.values()):
        raise RuntimeError("Guest isolation preflight failed")


def local_port(guest, port):
    bindings = docker_json(["inspect", guest])[0]["NetworkSettings"]["Ports"][str(port) + "/tcp"]
    if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("The guest endpoint must be bound only on loopback")
    return int(bindings[0]["HostPort"])


def execute(run_id, request, work, service):
    release = Path(service["release"])
    if not release.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Installed release is outside the L4 root")
    cfg = json.loads((release / "deployment/runtime-config.json").read_text())
    images = service["images"]
    artifacts = work / "artifacts"
    artifacts.mkdir(exist_ok=True)
    uid = int(run(["docker", "run", "--rm", "--entrypoint", "id", images["guest"], "-u"], capture_output=True).stdout.strip())
    gid = int(run(["docker", "run", "--rm", "--entrypoint", "id", images["guest"], "-g"], capture_output=True).stdout.strip())
    os.chown(artifacts, uid, gid)
    os.chmod(artifacts, 0o2770)
    network, cidr = protect_guest_network()
    guest = "team5-l4-guest-" + run_id
    request_path = work / "source-request.json"
    request_path.write_text(json.dumps(request))
    # An existing guest is evidence of an earlier start, never an instruction
    # to remove it or start another paid analysis.
    if subprocess.run(["docker", "inspect", guest], capture_output=True).returncode == 0:
        raise RuntimeError("An investigation guest already exists for this L4 run")
    run(["docker", "run", "-d", "--name", guest, "--init", "--read-only", "--cap-drop", "ALL",
         "--network", network, "--memory", "4g", "--cpus", "2", "--pids-limit", "512", "--shm-size", "1g",
         "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
         "--security-opt", "seccomp=" + str(release / "deployment/seccomp_profile.json"),
         "-p", "127.0.0.1::3000", "-p", "127.0.0.1::9100", "-e", "L4_WS_PATH=/" + uuid4().hex,
         "-v", str(artifacts) + ":/work/artifacts:rw", images["guest"]], capture_output=True)
    try:
        browser_port, bash_port = local_port(guest, 3000), local_port(guest, 9100)
        endpoint = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            output = run(["docker", "logs", guest], capture_output=True)
            line = next((line for line in output.stdout.splitlines() if line.startswith("L4_BROWSER_READY ")), None)
            if line:
                endpoint = "ws://127.0.0.1:" + str(browser_port) + urlsplit(line.split(" ", 1)[1]).path
                break
            if not docker_json(["inspect", guest])[0]["State"]["Running"]:
                (work / "guest-start.log").write_text(output.stderr + output.stdout)
                raise RuntimeError("Investigation browser did not start")
            time.sleep(1)
        if endpoint is None:
            raise RuntimeError("Browser readiness timeout")
        bash = "http://127.0.0.1:" + str(bash_port)
        actual_isolation(work, bash)
        (work / "deployment.json").write_text(json.dumps({"source_sha256": service["source_sha256"],
            "guest": guest, "network": network, "subnet": cidr, "chromium_sandbox": True,
            "images": {name: docker_json(["image", "inspect", image])[0]["Id"] for name, image in images.items()}}, indent=2))
        env = dict(os.environ, L4_BROWSER_WS=endpoint, L4_BASH_ENDPOINT=bash)
        with (work / "controller.log").open("w") as log:
            run(["docker", "run", "--rm", "--name", "team5-l4-controller-" + run_id,
                 "--init", "--read-only", "--cap-drop", "ALL", "--network", "host", "--group-add", str(gid),
                 "--memory", "3g", "--cpus", "2", "--pids-limit", "256",
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "-e", "AWS_DEFAULT_REGION=" + cfg["region"],
                 "-e", "L4_BROWSER_WS", "-e", "L4_BASH_ENDPOINT", "-v", str(work) + ":/work:rw",
                 "-v", str(request_path) + ":/opt/l4/request.json:ro", images["controller"],
                 "--config", "/opt/l4/runtime-config.json", "--request", "/opt/l4/request.json",
                 "--work", "/work", "--run-id", run_id], env=env, stdout=log, stderr=subprocess.STDOUT)
        verified = json.loads((work / "verification.json").read_text())
        if not all(verified["checks"].values()):
            raise RuntimeError("L4 readback did not pass")
        print(json.dumps({"run_id": run_id, "verified": True, "model_requests": verified["model_requests"]}))
    finally:
        subprocess.run(["docker", "stop", "--time", "10", guest], capture_output=True)


def main():
    run_id = sys.argv[1]
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise SystemExit("Invalid run identifier")
    work = ROOT / "jobs" / run_id
    work.mkdir(parents=True, exist_ok=True)
    with (work / "run.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"run_id": run_id, "reused": True, "reason": "already_running"}))
            return
        s3 = boto3.client("s3", region_name=REGION)
        ddb = boto3.client("dynamodb", region_name=REGION)
        meta = ddb.get_item(TableName="Team5-l4DB", Key={"job_id": {"S": run_id}, "record_key": {"S": "META"}}, ConsistentRead=True)
        if "Item" in meta:
            print(json.dumps({"run_id": run_id, "reused": True, "reason": "already_recorded"}))
            return
        try:
            with s3.get_object(Bucket=BUCKET, Key=f"l4/_runtime/{run_id}/request.json")["Body"] as stream:
                envelope = json.loads(stream.read())
            request = envelope["input"]
            canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if envelope["run_id"] != run_id or sha256(canonical.encode()).hexdigest()[:32] != run_id:
                raise RuntimeError("Requested run is not bound to its original Fast input")
            service = json.loads((ROOT / "service/service.json").read_text())
            status(s3, run_id, "InProgress")
            execute(run_id, request, work, service)
            status(s3, run_id, "Success")
        except Exception as exc:
            status(s3, run_id, "Failed", error_kind=type(exc).__name__)
            print(json.dumps({"run_id": run_id, "l4_error": type(exc).__name__}))
            raise SystemExit(1) from None


if __name__ == "__main__":
    main()
