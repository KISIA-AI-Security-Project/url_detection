"""Freeze an explicit source closure; never include keys, envs, or work outputs."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile


FAST_MODULES = ("__init__.py", "aws_fast_result.py", "aws_runtime.py", "fast_public.py",
                "records.py", "record_contract.py", "performance.py", "request_options.py", "model_choices.py")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parents[1]
    workspace = package.parent
    fast = workspace / "evidence_pipeline"
    files = {"pyproject.toml": package / "pyproject.toml"}
    for path in (package / "src").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".js", ".md"}:
            files[path.relative_to(package).as_posix()] = path
    for path in (package / "deployment").iterdir():
        if path.is_file() and path.suffix in {".py", ".json", ".cjs", ".md", ".controller", ".guest"}:
            files[path.relative_to(package).as_posix()] = path
    for name in FAST_MODULES:
        files["fast/evidence_pipeline/" + name] = fast / name
    manifest = {"schema_version": "l4-source-manifest-1", "files": {name: sha256(path.read_bytes()).hexdigest()
                                                                    for name, path in sorted(files.items())}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, path in sorted(files.items()):
            archive.write(path, name)
        archive.writestr("source-manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    digest = sha256(args.output.read_bytes()).hexdigest()
    receipt = {"path": str(args.output.resolve()), "files": len(files), "size_bytes": args.output.stat().st_size,
               "sha256": digest, "s3_key": "l4/_deployment/20261006/" + digest + ".zip", "manifest": manifest}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in receipt.items() if k != "manifest"}, ensure_ascii=True))


if __name__ == "__main__":
    main()
