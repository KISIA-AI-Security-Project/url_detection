"""Build a context-only isolated AWS amendment from the deployed v3 package."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REPLACEMENT = 'evidence_pipeline/url_activity.py'
OLD_CONTEXT = ('arn:aws:lambda:ap-northeast-2:998301375101:'
               'function:team5-itg-context-20260914:2')
NEW_CONTEXT = OLD_CONTEXT[:-1] + '3'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(base, output):
    output.mkdir(parents=True, exist_ok=False)
    original = base / 'context.zip'
    replacement = (ROOT / REPLACEMENT).read_bytes()
    patched = output / 'context-v4.zip'
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(patched, 'w') as target:
        assert source.namelist().count(REPLACEMENT) == 1
        for info in source.infolist():
            target.writestr(info, replacement if info.filename == REPLACEMENT
                            else source.read(info.filename))
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(patched) as target:
        assert source.namelist() == target.namelist()
        assert all(source.read(name) == target.read(name)
                   for name in source.namelist() if name != REPLACEMENT)
        assert target.read(REPLACEMENT) == replacement
    original_definition = json.loads((base / 'definition.json').read_text(encoding='utf-8'))
    definition = json.loads(json.dumps(original_definition))
    for state in ('ActivityTask', 'ContextTask'):
        task = definition['States'][state]
        assert task['Parameters']['FunctionName'] == OLD_CONTEXT
        task['Parameters']['FunctionName'] = NEW_CONTEXT
    definition_path = output / 'definition-v4.json'
    definition_path.write_text(json.dumps(definition, ensure_ascii=False, indent=2),
                               encoding='utf-8')
    before = json.dumps(original_definition, ensure_ascii=False, sort_keys=True)
    after = json.dumps(definition, ensure_ascii=False, sort_keys=True)
    assert after.replace(NEW_CONTEXT, OLD_CONTEXT) == before
    manifest = {
        'role': 'context', 'old_function': OLD_CONTEXT, 'new_function': NEW_CONTEXT,
        'source_package_sha256': sha(original.read_bytes()),
        'patched_package_sha256': sha(patched.read_bytes()),
        'source_file': REPLACEMENT, 'source_file_sha256': sha(replacement),
        'old_definition_sha256': sha((base / 'definition.json').read_bytes()),
        'new_definition_sha256': sha(definition_path.read_bytes()),
        'unchanged_zip_entries': len(zipfile.ZipFile(original).namelist()) - 1,
        'definition_changes': ['ActivityTask.FunctionName', 'ContextTask.FunctionName']}
    (output / 'patch-manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.base, args.output), indent=2))
