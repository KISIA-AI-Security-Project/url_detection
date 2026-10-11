"""Install only the frozen L4 release and run its approved first AWS request."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
from urllib.parse import urlsplit
from uuid import uuid4
import zipfile


ROOT = Path("/opt/team5-l4-20261006")


def run(arguments, **options):
    return subprocess.run(arguments, check=True, text=True, **options)


def docker_json(arguments):
    return json.loads(run(["docker", *arguments], capture_output=True).stdout)


def ensure_rule(chain, rule):
    exists = subprocess.run(["iptables", "-w", "-C", chain, *rule], capture_output=True)
    if exists.returncode:
        run(["iptables", "-w", "-A", chain, *rule], capture_output=True)


def protect_guest_network():
    network = "team5-l4-investigation"
    found = subprocess.run(["docker", "network", "inspect", network], capture_output=True, text=True)
    if found.returncode:
        run(["docker", "network", "create", "--driver", "bridge", network], capture_output=True)
    info = docker_json(["network", "inspect", network])[0]
    if info.get("EnableIPv6"):
        raise RuntimeError("The L4 isolation rules require an IPv4-only investigation network")
    cidr = info["IPAM"]["Config"][0]["Subnet"]
    for chain in ("TEAM5-L4-FWD", "TEAM5-L4-INPUT"):
        found = subprocess.run(["iptables", "-w", "-L", chain], capture_output=True)
        if found.returncode:
            run(["iptables", "-w", "-N", chain], capture_output=True)
        ensure_rule(chain, ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"])
    # This affects the new guest subnet only. The trusted controller can use
    # EC2 metadata, while a model-selected command or webpage cannot.
    for destination in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                        "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"):
        ensure_rule("TEAM5-L4-FWD", ["-d", destination, "-j", "REJECT"])
    ensure_rule("TEAM5-L4-FWD", ["-j", "RETURN"])
    ensure_rule("TEAM5-L4-INPUT", ["-j", "REJECT"])
    for parent, child in (("DOCKER-USER", "TEAM5-L4-FWD"), ("INPUT", "TEAM5-L4-INPUT")):
        check = subprocess.run(["iptables", "-w", "-C", parent, "-s", cidr, "-j", child], capture_output=True)
        if check.returncode:
            run(["iptables", "-w", "-I", parent, "1", "-s", cidr, "-j", child], capture_output=True)
    return network, cidr


def verify_isolation(work):
    # Use the actual guest Bash API. No model call is made by this preflight.
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
    request = urllib.request.Request("http://127.0.0.1:19104/execute", headers={"Content-Type": "application/json"},
        data=json.dumps({"command": "python - <<'PY'\n" + code + "PY", "timeout_ms": 10000}).encode())
    with urllib.request.urlopen(request, timeout=20) as response:
        reply = json.load(response)
    checks = json.loads(reply["stdout"])
    (work / "isolation-check.json").write_text(json.dumps({"checks": checks, "bash_reply": reply}, indent=2))
    if reply["status"] != "success" or not reply["cleanup_confirmed"] or not all(checks.values()):
        raise RuntimeError("Guest isolation preflight failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-sha256", required=True)
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    release = ROOT / ("release-" + args.source_sha256[:12])
    release.mkdir(exist_ok=True)
    with urllib.request.urlopen(args.source_url, timeout=60) as response:
        archive_bytes = response.read()
    if sha256(archive_bytes).hexdigest() != args.source_sha256:
        raise RuntimeError("L4 deployment archive checksum mismatch")
    archive_path = release / "source.zip"
    archive_path.write_bytes(archive_bytes)
    with zipfile.ZipFile(archive_path) as archive:
        for name in archive.namelist():
            target = (release / name).resolve()
            if not target.is_relative_to(release.resolve()):
                raise RuntimeError("Deployment archive path is outside this L4 release")
        archive.extractall(release)
    manifest = json.loads((release / "source-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if sha256((release / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Deployed source differs from the frozen manifest: " + name)
    config = json.loads((release / "deployment/runtime-config.json").read_text())
    request_path = release / "deployment/first-request.json"
    request = json.loads(request_path.read_text())
    work = ROOT / "jobs" / request["job_id"]
    artifacts = work / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    tag = args.source_sha256[:12]
    images = {name: f"team5-l4-{name}:{tag}" for name in ("controller", "guest")}
    for name, image in images.items():
        with (release / f"build-{name}.log").open("w") as log:
            run(["docker", "build", "-f", f"deployment/Dockerfile.{name}", "-t", image, "."],
                cwd=release, stdout=log, stderr=subprocess.STDOUT)
        print("L4_IMAGE_BUILT " + name, flush=True)
    uid = int(run(["docker", "run", "--rm", "--entrypoint", "id", images["guest"], "-u"], capture_output=True).stdout.strip())
    gid = int(run(["docker", "run", "--rm", "--entrypoint", "id", images["guest"], "-g"], capture_output=True).stdout.strip())
    os.chown(artifacts, uid, gid)
    # The trusted producer and guest Bash share these artifacts. With all
    # capabilities dropped, root also needs the shared group to write here.
    os.chmod(artifacts, 0o2770)
    network, cidr = protect_guest_network()
    guest = "team5-l4-guest-" + request["job_id"][:12]
    if subprocess.run(["docker", "inspect", guest], capture_output=True).returncode == 0:
        raise RuntimeError("An L4 guest for this job already exists; inspect it before another start")
    run(["docker", "run", "-d", "--name", guest, "--init", "--read-only", "--cap-drop", "ALL",
         "--network", network, "--memory", "4g", "--cpus", "2", "--pids-limit", "512", "--shm-size", "1g",
         "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
         "--security-opt", "seccomp=" + str(release / "deployment/seccomp_profile.json"),
         "-p", "127.0.0.1:13004:3000", "-p", "127.0.0.1:19104:9100",
         "-e", "L4_WS_PATH=/" + uuid4().hex,
         "-v", str(artifacts) + ":/work/artifacts:rw", images["guest"]], capture_output=True)
    endpoint = None
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            logs = run(["docker", "logs", guest], capture_output=True).stdout
            line = next((line for line in logs.splitlines() if line.startswith("L4_BROWSER_READY ")), None)
            if line:
                parsed = urlsplit(line.split(" ", 1)[1])
                endpoint = "ws://127.0.0.1:13004" + parsed.path
                break
            inspect = docker_json(["inspect", guest])[0]
            if not inspect["State"]["Running"]:
                (work / "guest-start.log").write_text(run(["docker", "logs", guest], capture_output=True).stderr + logs)
                raise RuntimeError("L4 investigation browser did not start")
            time.sleep(1)
        if endpoint is None:
            raise RuntimeError("L4 browser readiness timeout")
        verify_isolation(work)
        (work / "deployment.json").write_text(json.dumps({"source_sha256": args.source_sha256,
            "manifest": manifest, "network": network, "subnet": cidr, "guest": guest,
            "chromium_sandbox": True, "images": {name: docker_json(["image", "inspect", image])[0]["Id"]
                                                 for name, image in images.items()}}, indent=2))
        env = dict(os.environ, L4_BROWSER_WS=endpoint, L4_BASH_ENDPOINT="http://127.0.0.1:19104")
        with (work / "controller.log").open("w") as log:
            run(["docker", "run", "--rm", "--name", "team5-l4-controller-" + request["job_id"][:12],
                 "--init", "--read-only", "--cap-drop", "ALL", "--network", "host",
                 "--group-add", str(gid),
                 "--memory", "3g", "--cpus", "2", "--pids-limit", "256",
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
                 "-e", "AWS_DEFAULT_REGION=" + config["region"], "-e", "L4_BROWSER_WS", "-e", "L4_BASH_ENDPOINT",
                 "-v", str(work) + ":/work:rw", "-v", str(request_path) + ":/opt/l4/request.json:ro",
                 images["controller"], "--config", "/opt/l4/runtime-config.json",
                 "--request", "/opt/l4/request.json", "--work", "/work"],
                env=env, stdout=log, stderr=subprocess.STDOUT)
        summary = json.loads((work / "verification.json").read_text())
        print("L4_AWS_VERIFIED " + json.dumps(summary), flush=True)
    finally:
        # Retire this job's OS sandbox, including command descendants.
        subprocess.run(["docker", "stop", "--time", "10", guest], capture_output=True)


if __name__ == "__main__":
    main()
