"""Package Linux Lambda adapters without any model key or Agents runtime."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile

from package_runtime import FAST_MODULES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parents[1]
    fast = package.parent / "evidence_pipeline"
    files = {}
    for path in (package / "src").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".js", ".md"}:
            files[path.relative_to(package / "src").as_posix()] = path
    for name in FAST_MODULES:
        files["evidence_pipeline/" + name] = fast / name
    for path in args.dependencies.rglob("*"):
        if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts and "bin" not in path.parts:
            name = path.relative_to(args.dependencies).as_posix()
            if name in files:
                raise ValueError("Lambda source and dependency path overlap")
            files[name] = path
    if not any(name.endswith(".so") and "cpython-312-x86_64-linux-gnu" in name for name in files):
        raise ValueError("The Lambda package requires CPython 3.12 Linux x86_64 wheels")
    if any(path.suffix in {".pyd", ".exe"} for path in files.values()):
        raise ValueError("Windows binaries are not Lambda dependencies")
    manifest = {"schema_version": "l4-lambda-source-1", "files": {
        name: sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, path in sorted(files.items()):
            archive.write(path, name)
        archive.writestr("source-manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    receipt = {"path": str(args.output.resolve()), "bytes": args.output.stat().st_size,
               "files": len(files), "sha256": sha256(args.output.read_bytes()).hexdigest()}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(receipt | {"manifest": manifest}, indent=2))
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
