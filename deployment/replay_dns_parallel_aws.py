"""Reclassify preserved AWS raw/record snapshots without network or AWS access."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence_pipeline import url_activity


def replay(path, at_capture=False):
    captured = json.loads(path.read_text(encoding='utf-8'))
    artifacts = captured['artifacts']
    for layer in ('l0', 'l1', 'l2', 'l3'):
        record = artifacts[layer]
        raw = artifacts[f'{layer}_raw']
        assert record['value']['artifact_refs'] == {
            'raw': raw['key'], 'record': record['key']}
        assert record['value']['evidence_record']['raw_ref']['sha256'] == raw['sha256']
    records = [artifacts[layer]['value']['evidence_record']
               for layer in ('l0', 'l1', 'l2', 'l3')]
    def assess():
        return url_activity.assess_url_activity(
            captured['input_url'], artifacts['l1']['value']['observation'],
            artifacts['l1_raw']['value'], records,
            request_id=captured['job_id'], attempt=1)

    if at_capture:
        reference = datetime.fromisoformat(captured['captured_at'])

        class ReplayDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return reference.astimezone(tz) if tz else reference.replace(tzinfo=None)

        with patch.object(url_activity, 'datetime', ReplayDatetime):
            result = assess()
    else:
        result = assess()
    return {'file': path.name, 'job_id': captured['job_id'],
            'replay_at': captured['captured_at'] if at_capture else 'now',
            'state': result['state'], 'reason': result['reason'],
            'can_skip_judgment': result['can_skip_judgment']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--at-capture', action='store_true')
    parser.add_argument('files', type=Path, nargs='+')
    args = parser.parse_args()
    for file in args.files:
        print(json.dumps(replay(file, at_capture=args.at_capture), ensure_ascii=False))
