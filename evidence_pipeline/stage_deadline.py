"""Keep separate hard time budgets inside one Lambda invocation.

A timeout ends this execution environment, as a Lambda timeout does. It must
never leave a worker running while the caller starts the next stage or model.
"""
from contextlib import contextmanager
import json
import math
import os
from threading import Event, Thread


@contextmanager
def hard_stage_deadline(stage, seconds=55.0):
    if stage not in ("activity", "context"):
        raise ValueError("unknown_stage_deadline")
    seconds = float(seconds)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("positive_stage_deadline_required")
    completed = Event()

    def enforce():
        if not completed.wait(seconds):
            try:
                message = json.dumps({"schema_version": "lambda-stage-timeout-1",
                                      "stage": stage, "limit_seconds": seconds}) + "\n"
                os.write(2, message.encode("utf-8"))
            finally:
                os._exit(124)

    watchdog = Thread(target=enforce, name="deadline-" + stage, daemon=True)
    watchdog.start()
    try:
        yield
    finally:
        completed.set()
        watchdog.join()
