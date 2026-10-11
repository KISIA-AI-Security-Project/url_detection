"""Hard stop and cancellation run in disposable subprocesses, never pytest."""
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def run(code):
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                          env={**os.environ, "PYTHONPATH": str(ROOT)},
                          capture_output=True, text=True, timeout=5)


def test_blocked_activity_exits_before_context_can_start():
    result = run('''
from evidence_pipeline.stage_deadline import hard_stage_deadline
import time
with hard_stage_deadline('activity', .08):
    time.sleep(3)
print('context-started', flush=True)
''')
    assert result.returncode == 124
    assert '"stage": "activity"' in result.stderr
    assert 'context-started' not in result.stdout


def test_context_has_its_own_budget_and_never_reaches_model():
    result = run('''
from evidence_pipeline.stage_deadline import hard_stage_deadline
import time
with hard_stage_deadline('activity', .2):
    time.sleep(.06)
    print('activity-saved', flush=True)
with hard_stage_deadline('context', .08):
    time.sleep(3)
print('model-started', flush=True)
''')
    assert result.returncode == 124
    assert 'activity-saved' in result.stdout
    assert '"stage": "context"' in result.stderr
    assert 'model-started' not in result.stdout


def test_success_and_exception_both_cancel_and_join_watchdog():
    result = run('''
from evidence_pipeline.stage_deadline import hard_stage_deadline
import time, threading
with hard_stage_deadline('activity', .08):
    pass
try:
    with hard_stage_deadline('context', .08):
        raise ValueError('saved-failure')
except ValueError:
    pass
time.sleep(.2)
assert not any(t.name.startswith('deadline-') for t in threading.enumerate())
print('alive', flush=True)
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'alive'
