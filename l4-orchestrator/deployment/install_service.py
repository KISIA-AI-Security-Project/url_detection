"""Install the reviewed release, without starting or charging a model run."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import zipfile

import boto3

from bootstrap import ROOT, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha256", required=True)
    args = parser.parse_args()
    digest = args.source_sha256
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Source checksum required")
    s3 = boto3.client("s3", region_name="ap-northeast-2")
    with s3.get_object(Bucket="team5-evidence-998301375101-ap-northeast-2-an",
            Key="l4/_deployment/20261006/" + digest + ".zip")["Body"] as stream:
        raw = stream.read()
    if sha256(raw).hexdigest() != digest:
        raise ValueError("Downloaded source differs from the reviewed archive")
    release = ROOT / ("release-" + digest[:12])
    release.mkdir(parents=True, exist_ok=True)
    archive = release / "source.zip"
    archive.write_bytes(raw)
    with zipfile.ZipFile(archive) as zipped:
        if not all((release / name).resolve().is_relative_to(release.resolve()) for name in zipped.namelist()):
            raise ValueError("Archive path is outside this release")
        zipped.extractall(release)
    manifest = json.loads((release / "source-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if sha256((release / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Source file does not match the reviewed manifest")
    images = {kind: "team5-l4-" + kind + ":" + digest[:12] for kind in ("controller", "guest")}
    for kind, image in images.items():
        with (release / ("build-" + kind + ".log")).open("w") as output:
            run(["docker", "build", "-f", "deployment/Dockerfile." + kind, "-t", image, "."],
                cwd=release, stdout=output, stderr=-2)
    service = ROOT / "service"
    service.mkdir(exist_ok=True)
    for name in ("bootstrap.py", "run_job.py"):
        shutil.copy2(release / "deployment" / name, service / name)
    value = {"release": str(release), "source_sha256": digest, "images": images}
    (service / "service.json").write_text(json.dumps(value, indent=2))
    print("L4_SERVICE_INSTALLED " + json.dumps(value))


if __name__ == "__main__":
    main()
