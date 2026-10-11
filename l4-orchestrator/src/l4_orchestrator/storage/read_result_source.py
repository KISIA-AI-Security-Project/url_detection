"""Bind the existing bounded read_result Tool to one Store and read scope."""
from uuid import uuid4

from ..tools.read_result import ReadResultSource, ReadResultView, ReadResultLookupError
from .store import L4Store


def make_read_result_source(store: L4Store, *, allowed_work_ids=None):
    # None grants this job's manager all works; an explicit set limits an executor.
    allowed = None if allowed_work_ids is None else frozenset(allowed_work_ids)
    cursors = {}

    def fail(code, text):
        raise ReadResultLookupError(code, text)

    def authorize(work_id):
        if allowed is not None and work_id not in allowed:
            fail("FORBIDDEN", "This work is outside the caller's read scope.")

    def page(kind, identity, rows, limit, cursor, prefix, id_key):
        if type(limit) is not int or limit < 1:
            fail("INVALID_CURSOR", "Invalid page limit.")
        after = 0
        if cursor is not None:
            entry = cursors.get(cursor)
            if entry is None or entry[:3] != (store.job_id, kind, identity):
                fail("INVALID_CURSOR", "Cursor belongs to another query or Store.")
            after = entry[3]
        rows.sort(key=lambda r: int(r[id_key][len(prefix):]))
        remaining = [r for r in rows if int(r[id_key][len(prefix):]) > after]
        selected, next_cursor = remaining[:limit], None
        if len(remaining) > limit:
            next_cursor = uuid4().hex
            cursors[next_cursor] = (store.job_id, kind, identity,
                                    int(selected[-1][id_key][len(prefix):]))
        return selected, next_cursor

    async def work(identity, limit, cursor):
        authorize(identity)
        if "WORK#" + identity not in store._records:
            fail("NOT_FOUND", "Work is not registered.")
        entity = await store.read_work(identity)
        rows = [store.task_summary(store._task(i)) for i in store._task_keys
                if store._task(i)["work_id"] == identity]
        rows, nxt = page("work", identity, rows, limit, cursor, "T", "id")
        return ReadResultView(store.job_id, identity, {"work": entity, "tasks": rows}, nxt)

    async def task(identity, limit, cursor):
        if identity not in store._task_keys:
            fail("NOT_FOUND", "Task is not registered.")
        entity = await store.read_task(identity)
        authorize(entity["work_id"])
        rows = [{k: v for k, v in store._action(i).items()
                 if k not in {"arguments_json", "prepared_input_json"}}
                for i in store._action_keys if store._action(i)["task_id"] == identity]
        rows, nxt = page("task", identity, rows, limit, cursor, "ACT", "action_id")
        return ReadResultView(store.job_id, identity, {"task": entity, "actions": rows}, nxt)

    async def result(ref):
        if ref.startswith("result:"):
            identity = ref.removeprefix("result:")
            if identity not in store._action_keys:
                fail("NOT_FOUND", "Action is not registered.")
            owner = store._action(identity)
        elif ref.startswith("report:"):
            identity = ref.removeprefix("report:")
            if identity not in store._task_keys:
                fail("NOT_FOUND", "Task is not registered.")
            owner = store._task(identity)
        else:
            fail("NOT_FOUND", "Unsupported result reference.")
        authorize(owner["work_id"])
        if "RESULT#" + ref not in store._records:
            fail("RESULT_NOT_READY", "No result body has been recorded.")
        return ReadResultView(store.job_id, ref, await store.read_result(ref))

    return ReadResultSource(store.job_id, work, task, result)
