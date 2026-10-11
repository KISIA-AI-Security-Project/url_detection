"""One event-loop-owned recording object per L4 job.

Mutations prepare immutable JSON and publication values before committing them.
No Tool, Runner, file read or network I/O occurs here.
"""
import asyncio
from collections import deque
from datetime import datetime, timezone
from uuid import uuid4

from ..execution_control import AssignmentError, ExecutionEnded, StoreError
from ..json_values import dumps, loads, copy_json, same_json
from ..sdk_types import ManagerTurn, ExecutionReport
from .models import CompletedFile, Publication, Record, text_id

TASK_END = frozenset({"success", "returned", "failed", "ended_by_manager"})
ACTION_END = frozenset({"success", "failed"})
STATUS_MAP = {"ok": "success", "success": "success", "error": "failed",
              "failed": "failed", "timeout": "failed", "blocked": "failed"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def model_json(cls, value):
    if isinstance(value, cls):
        value = value.model_dump(mode="json")
    return cls.model_validate(copy_json(value)).model_dump(mode="json")


def normalize_status(value):
    native = value.get("status") if type(value) is dict else None
    if native not in STATUS_MAP:
        raise StoreError("Unknown native Tool status; supply an explicit status mapping")
    return STATUS_MAP[native], native


class L4Store:
    def __init__(self, job_id: str, *, clock=utc_now):
        self.job_id = text_id(job_id, "job_id", 2048)
        self._clock = clock
        self._loop = None
        self._action_lock = asyncio.Lock()
        self._records = {}
        self._task_keys = {}
        self._action_keys = {}
        self._files = {}
        self._assignments = {}
        self._decisions = {}
        self._accepted = {}
        self._history_json = "[]"
        self._delivered = set()
        self._next_action = 1
        self._execution_ended = False
        self._sealed = False
        self._terminal = None
        self._pending = deque()
        self._inflight = None
        self._publication_number = 0
        self._changed = asyncio.Event()
        self._publisher_owner = None
        self._publisher_done = False
        self._publisher_error = None
        self._last_saved_seq = 0
        self.start_token = uuid4().hex
        now = self._clock()
        self._records["META"] = Record.make("META", {
            "status": "running", "current_manager_call_id": None,
            "final_result_ref": None,
            "started_at": now, "updated_at": now,
        }, now)
        self.initial_meta = self._records["META"]

    def _check_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise StoreError("A Store belongs to one event loop")

    def _writable(self):
        self._check_loop()
        if self._sealed:
            raise StoreError("Records are sealed")

    def _get(self, key):
        try:
            return self._records[key].body()
        except KeyError:
            raise StoreError(f"Unknown record: {key}") from None

    def _task(self, identity):
        return self._get(self._task_keys.get(identity, "TASK#missing"))

    def _action(self, identity):
        return self._get(self._action_keys.get(identity, "ACTION#missing"))

    def _commit(self, rows, *, files=(), terminal=False):
        self._writable()
        now = self._clock()
        records = tuple(Record.make(key, body, now) for key, body in rows)
        if len({r.record_key for r in records}) != len(records):
            raise StoreError("Duplicate record in one mutation")
        publication = Publication(self._publication_number + 1, records,
                                  tuple(files), terminal)
        # Everything that can validate/serialize is done. No await in this commit.
        self._records.update({r.record_key: r for r in records})
        self._pending.append(publication)
        self._publication_number += 1
        self._changed.set()

    @property
    def execution_ended(self):
        return self._execution_ended

    @property
    def records_sealed(self):
        return self._sealed

    @property
    def pending_count(self):
        return len(self._pending)

    @property
    def inflight(self):
        return self._inflight

    @property
    def last_saved_seq(self):
        return self._last_saved_seq

    @property
    def manager_history(self):
        return loads(self._history_json)

    def snapshot_records(self):
        return tuple(self._records.values())

    async def read_work(self, identity):
        return self._get("WORK#" + identity)

    async def read_task(self, identity):
        return self._task(identity)

    async def read_result(self, ref):
        return self._get("RESULT#" + ref)

    def task_has_ended(self, identity):
        return self._task(identity)["status"] in TASK_END

    def next_assignment_ids(self):
        return {"work": f"W{1 + sum(k.startswith('WORK#') for k in self._records)}",
                "task": f"T{len(self._task_keys) + 1}"}

    def ready_tasks(self):
        if self.execution_ended:
            return []
        return [t for identity in self._task_keys
                if (t := self._task(identity))["status"] == "queued"
                and all(self.task_has_ended(p) for p in t["after"])]

    def new_task_result_refs(self):
        return [t["result_ref"] for identity in self._task_keys
                if (t := self._task(identity))["status"] in TASK_END
                and t["result_ref"] is not None and t["result_ref"] not in self._delivered]

    def manager_input_snapshot(self, selected_refs):
        """Additional result/state data, without SDK history or repeated work plans.

        The runtime adds this data to manager_history and supplies initial inputs
        and Tool instructions separately. This method does not call a model.
        """
        self._selected(selected_refs)
        tasks = [self._task(i) for i in self._task_keys]
        by_ref = {t["result_ref"]: t for t in tasks if t["result_ref"] is not None}
        return {"works": [{"id": r.body()["id"], "tasks": [
                    {name: t[name] for name in ("id", "status", "result_ref")}
                    for t in tasks if t["work_id"] == r.body()["id"]]}
                    for k, r in self._records.items() if k.startswith("WORK#")],
                "new_results": [{"work_id": by_ref[ref]["work_id"], "task_id": by_ref[ref]["id"],
                    "status": by_ref[ref]["status"], "data": self._get("RESULT#" + ref),
                    "error": by_ref[ref]["error"], "result_ref": ref} for ref in selected_refs],
                "next_ids": self.next_assignment_ids()}

    @staticmethod
    def task_summary(row):
        result = {k: v for k, v in row.items() if k != "execution"}
        result["execution"] = {k: v for k, v in row["execution"].items() if k in {"kind", "name"}}
        return copy_json(result)

    def _selected(self, refs):
        if type(refs) is not list or len(set(refs)) != len(refs):
            raise StoreError("Selected refs must be a unique list")
        if not set(refs).issubset(self.new_task_result_refs()):
            raise StoreError("Select only undelivered final results of ended tasks")

    def ensure_execution_open(self):
        self._writable()
        if self.execution_ended:
            raise ExecutionEnded("L4 execution has ended")

    async def start_manager_call(self, manager_call_id, selected_refs):
        self.ensure_execution_open()
        text_id(manager_call_id, "manager_call_id", 1016)
        key = "MANAGER#" + manager_call_id
        if key in self._records:
            if self._get(key)["selected_refs"] == selected_refs:
                return
            raise StoreError("Manager call ID reused with different input")
        self._selected(selected_refs)
        if any(r.body()["status"] == "running" for k, r in self._records.items() if k.startswith("MANAGER#")):
            raise StoreError("Only one manager call may run at a time")
        works = list(dict.fromkeys(self._task(t)["work_id"] for t in self._task_keys
                                  if self._task(t)["result_ref"] in selected_refs))
        now = self._clock()
        row = dict(id=manager_call_id, status="running", selected_refs=selected_refs,
                   review_work_ids=works, query_count=0, summary=None, decision_summary=None,
                   registration_status="pending", registration_error=None,
                   started_at=now, finished_at=None,
                   situation="다음 작업 판단 중" if self._task_keys else "업무 구성 중")
        meta = self._get("META") | {"current_manager_call_id": manager_call_id, "updated_at": now}
        self._commit([(key, row), ("META", meta)])

    async def start_manager_query(self, manager_call_id):
        self._manager_query(manager_call_id, 1)

    async def finish_manager_query(self, manager_call_id):
        self._manager_query(manager_call_id, -1)

    def _manager_query(self, identity, delta):
        row = self._get("MANAGER#" + identity)
        if row["status"] != "running" or row["query_count"] + delta < 0:
            raise StoreError("Manager query lifecycle mismatch")
        row["query_count"] += delta
        row["situation"] = "자료 확인 중" if row["query_count"] else "다음 작업 판단 중"
        self._commit([("MANAGER#" + identity, row)])

    def accept_manager_run(self, manager_call_id, *, history, delivered_refs, decision):
        self._writable()
        decision = model_json(ManagerTurn, decision)
        history_json = dumps(history)
        if type(history) is not list:
            raise StoreError("Manager SDK history must be a list")
        receipt = dumps([history, delivered_refs, decision])
        if manager_call_id in self._accepted:
            if self._accepted[manager_call_id] != receipt:
                raise StoreError("Manager return changed on retry")
            return
        row = self._get("MANAGER#" + manager_call_id)
        if row["status"] != "running" or row["query_count"] or row["selected_refs"] != delivered_refs:
            raise StoreError("Manager return does not match its start snapshot")
        row.update(status="returned", finished_at=self._clock(), summary=decision["summary"],
                   situation="판단 반환", decision_summary={
                       "new_work_ids": [w["id"] for w in decision["new_works"]],
                       "task_ids": [t["id"] for t in decision["tasks"]],
                       "answered_work_ids": [w["work_id"] for w in decision["work_answers"]],
                       "review_after": decision["review_after"], "finish": decision["finish"] is not None})
        self._commit([("MANAGER#" + manager_call_id, row)])
        self._history_json = history_json
        self._delivered.update(delivered_refs)
        self._decisions[manager_call_id] = dumps(decision)
        self._accepted[manager_call_id] = receipt

    async def fail_manager_call(self, manager_call_id, message=None):
        row = self._get("MANAGER#" + manager_call_id)
        if row["status"] == "failed" and row.get("error") == message:
            return
        if row["status"] != "running":
            raise StoreError("Cannot fail a returned manager call")
        row.update(status="failed", finished_at=self._clock(), query_count=0, error=message,
                   situation="총괄 호출 실패")
        self._commit([("MANAGER#" + manager_call_id, row)])

    async def reject_assignment(self, manager_call_id, message):
        row = self._get("MANAGER#" + manager_call_id)
        if row["status"] != "returned" or row["registration_status"] == "registered":
            raise StoreError("Only an unregistered return may be rejected")
        row.update(registration_status="rejected", registration_error=text_id(message, "message"))
        self._commit([("MANAGER#" + manager_call_id, row)])

    async def save_assignment(self, manager_call_id, decision):
        self.ensure_execution_open()
        decision = model_json(ManagerTurn, decision)
        encoded = dumps(decision)
        if manager_call_id in self._assignments:
            if self._assignments[manager_call_id] != encoded:
                raise AssignmentError("Different decision for the same manager call")
            return False
        if self._decisions.get(manager_call_id) != encoded:
            raise AssignmentError("Assignment must match the accepted manager return")
        row = self._get("MANAGER#" + manager_call_id)
        if row["registration_status"] != "pending":
            raise AssignmentError("A rejected return must be corrected in a new manager call")
        works, tasks = decision["new_works"], decision["tasks"]
        next_w = 1 + sum(k.startswith("WORK#") for k in self._records)
        next_t = len(self._task_keys) + 1
        if [w["id"] for w in works] != [f"W{n}" for n in range(next_w, next_w + len(works))]:
            raise AssignmentError("New work IDs must follow the announced sequence")
        if [t["id"] for t in tasks] != [f"T{n}" for n in range(next_t, next_t + len(tasks))]:
            raise AssignmentError("New task IDs must follow the announced sequence")
        work_map = {r.body()["id"]: r.body() for k, r in self._records.items() if k.startswith("WORK#")}
        work_map.update({w["id"]: w for w in works})
        task_map = {i: self._task(i) for i in self._task_keys} | {t["id"]: t for t in tasks}
        for task in tasks:
            if task["work_id"] not in work_map:
                raise AssignmentError("Task refers to an unknown work")
            if len(set(task["after"])) != len(task["after"]) or any(p not in task_map for p in task["after"]):
                raise AssignmentError("Invalid predecessor list")
            execution = task["execution"]
            tools = [execution["name"]] if execution["kind"] == "tool" else execution["allowed_tools"]
            if not set(tools).issubset(work_map[task["work_id"]]["scope"]["allowed_tools"]):
                raise AssignmentError("Task tools exceed the work scope")
        # Iterative topological check avoids recursion on large assignments.
        done = set()
        while len(done) < len(task_map):
            ready = {i for i, t in task_map.items() if i not in done and set(t["after"]) <= done}
            if not ready:
                raise AssignmentError("Cyclic task dependencies")
            done.update(ready)
        condition = decision["review_after"]
        if decision["finish"] is not None and (tasks or condition is not None):
            raise AssignmentError("A finishing decision cannot assign tasks or a review condition")
        if decision["finish"] is None and (condition is None or not condition["tasks"]):
            raise AssignmentError("A continuing decision needs a review condition")
        if condition is not None:
            ids = condition["tasks"]
            if len(set(ids)) != len(ids) or any(t not in task_map for t in ids):
                raise AssignmentError("Invalid review tasks")
            if any(t in self._task_keys and self._task(t)["result_ref"] in self._delivered for t in ids):
                raise AssignmentError("Review condition repeats an already delivered result")
        answers = decision["work_answers"]
        if len({a["work_id"] for a in answers}) != len(answers) or any(a["work_id"] not in work_map for a in answers):
            raise AssignmentError("Invalid work answers")
        now = self._clock()
        changes = {}
        for w in works:
            changes["WORK#" + w["id"]] = w | dict(status="assigned", answer=None, answer_refs=[],
                assigned_at=now, answered_at=None, updated_at=now)
        for answer in answers:
            try:
                self._check_local_refs(answer["refs"])
            except StoreError as exc:
                raise AssignmentError(str(exc)) from exc
            key = "WORK#" + answer["work_id"]
            w = changes.get(key) or self._get(key)
            changes[key] = w | dict(status="answered", answer=answer["answer"],
                                   answer_refs=answer["refs"], answered_at=now, updated_at=now)
        for task in tasks:
            key = f"TASK#{task['work_id']}#{task['id']}"
            changes[key] = task | dict(status="queued", waiting_reason=None, assigned_at=now,
                started_at=None, finished_at=None, result_ref=None, error=None)
        row.update(registration_status="registered", registration_error=None)
        changes["MANAGER#" + manager_call_id] = row
        self._commit(changes.items())
        self._task_keys.update({t["id"]: f"TASK#{t['work_id']}#{t['id']}" for t in tasks})
        self._assignments[manager_call_id] = encoded
        return True

    def _check_local_refs(self, refs):
        for ref in refs:
            if ref.startswith(("result:", "report:")) and "RESULT#" + ref not in self._records:
                raise StoreError(f"Unrecorded local result reference: {ref}")

    async def start_task(self, identity):
        self.ensure_execution_open()
        row = self._task(identity)
        if row["status"] == "running":
            return
        if row["status"] not in {"queued", "waiting"} or not all(self.task_has_ended(p) for p in row["after"]):
            raise StoreError("Task is not ready to start")
        row.update(status="running", started_at=self._clock(), waiting_reason=None)
        self._commit([(self._task_keys[identity], row)])

    async def set_task_waiting(self, identity, reason):
        self.ensure_execution_open()
        row = self._task(identity)
        if row["status"] not in {"queued", "waiting", "running"}:
            raise StoreError("Ended task cannot wait")
        row.update(status="waiting", waiting_reason=text_id(reason, "waiting_reason"))
        self._commit([(self._task_keys[identity], row)])

    async def create_action(self, work_id, task_id, tool_name, arguments_json):
        self._check_loop()
        async with self._action_lock:
            self.ensure_execution_open()
            task = self._task(task_id)
            if task["work_id"] != work_id or task["status"] != "running":
                raise StoreError("Action requires its running task and matching work")
            execution = task["execution"]
            allowed = [execution["name"]] if execution["kind"] == "tool" else execution["allowed_tools"]
            if tool_name not in allowed:
                raise StoreError("Action tool is outside the task scope")
            # Parsing/preparing is the runtime's next step. Keep malformed text
            # so that a real preparation failure can be attached to this ACT.
            if type(arguments_json) is not str:
                raise StoreError("Action arguments must be the original JSON text")
            identity = f"ACT{self._next_action}"
            key = f"ACTION#{work_id}#{task_id}#{identity}"
            row = dict(action_id=identity, work_id=work_id, task_id=task_id, tool_name=tool_name,
                       arguments_json=arguments_json, prepared_input_json=None, status="preparing",
                       native_status=None, started_at=None, finished_at=None, result_ref=None, error=None)
            self._commit([(key, row)])
            self._action_keys[identity] = key
            self._next_action += 1
            return identity

    async def start_action(self, identity, prepared_input):
        self.ensure_execution_open()
        row = self._action(identity)
        encoded = dumps(prepared_input)
        if row["status"] == "running" and row["prepared_input_json"] == encoded:
            return
        if row["status"] != "preparing":
            raise StoreError("Action cannot start twice with different input")
        row.update(status="running", prepared_input_json=encoded, started_at=self._clock())
        self._commit([(self._action_keys[identity], row)])

    async def finish_action(self, identity, tool_return):
        status, native = normalize_status(tool_return)
        return self._end_action(identity, tool_return, status, native, None)

    async def fail_action(self, identity, stage, error):
        failure = {"stage": text_id(stage, "stage"), "message": text_id(error, "error")}
        return self._end_action(identity, {"kind": "execution_error", **failure}, "failed", None, failure)

    def _end_action(self, identity, body, status, native, error):
        self._writable()
        row = self._action(identity)
        ref = "result:" + identity
        if row["status"] in ACTION_END:
            if row["result_ref"] == ref and same_json(self._get("RESULT#" + ref), body):
                return ref
            raise StoreError("Action end conflicts with recorded content")
        if error is None and row["status"] != "running":
            raise StoreError("Only an invoked action can have a native return")
        row.update(status=status, native_status=native, error=error, result_ref=ref,
                   finished_at=self._clock())
        self._commit([("RESULT#" + ref, body), (self._action_keys[identity], row)])
        return ref

    async def save_report(self, task_id, report):
        task = self._task(task_id)
        if task["execution"]["kind"] != "agent":
            raise StoreError("Only an Agent task produces an Agent report")
        if task["started_at"] is None:
            raise StoreError("A normal Agent report requires an actually started task")
        body = model_json(ExecutionReport, report)
        reference_errors = []
        checked = set()
        for finding in body["findings"]:
            for ref in finding["refs"]:
                if ref in checked:
                    continue
                checked.add(ref)
                if ref.startswith(("result:", "report:")) and "RESULT#" + ref not in self._records:
                    reference_errors.append({"ref": ref, "reason": "No saved result exists for this reference"})
        if reference_errors:
            # The report's original statements, refs and limits remain intact.
            # This is lookup evidence for the manager, not a verdict on findings.
            body["reference_errors"] = reference_errors
        return self._save_task_result(task_id, body)

    async def save_task_error(self, task_id, *, stage, message):
        return self._save_task_result(task_id, {"kind": "execution_error",
            "stage": text_id(stage, "stage"), "message": text_id(message, "message")})

    def _save_task_result(self, identity, body):
        self._writable()
        ref = "report:" + identity
        row = self._task(identity)
        if "RESULT#" + ref in self._records:
            if same_json(self._get("RESULT#" + ref), body):
                return ref
            raise StoreError("Task report changed on retry")
        if row["status"] in TASK_END:
            raise StoreError("Ended task cannot acquire a new report")
        self._commit([("RESULT#" + ref, body)])
        return ref

    async def finish_task(self, identity, status, result_ref=None):
        self._writable()
        row = self._task(identity)
        if row["status"] in TASK_END:
            if (row["status"], row["result_ref"]) == (status, result_ref):
                return
            raise StoreError("Task end conflicts with existing end")
        if status not in TASK_END:
            raise StoreError("Invalid task end status")
        if any(self._action(i)["task_id"] == identity and self._action(i)["status"] not in ACTION_END
               for i in self._action_keys):
            raise StoreError("Task still has unfinished actions")
        if status == "ended_by_manager":
            if not self.execution_ended or result_ref is not None or "RESULT#report:" + identity in self._records:
                raise StoreError("Manager end must preserve real reports and have no invented result")
        else:
            if result_ref is None or "RESULT#" + result_ref not in self._records:
                raise StoreError("Task end requires a saved result")
            if result_ref.startswith("result:"):
                action = self._action(result_ref.removeprefix("result:"))
                if action["task_id"] != identity or action["status"] != status or row["execution"]["kind"] != "tool":
                    raise StoreError("Direct task result must belong to this task and match its state")
            elif result_ref != "report:" + identity:
                raise StoreError("Report belongs to a different task")
            else:
                body = self._get("RESULT#" + result_ref)
                expected = "failed" if body.get("kind") == "execution_error" else "returned"
                if status != expected:
                    raise StoreError("Report and end state disagree")
        row.update(status=status, result_ref=result_ref, finished_at=self._clock(), waiting_reason=None)
        self._commit([(self._task_keys[identity], row)])

    async def register_file(self, completed_file: CompletedFile):
        self._writable()
        if not isinstance(completed_file, CompletedFile):
            raise StoreError("A trusted completed file descriptor is required")
        previous = self._files.get(completed_file.file_ref)
        if previous is not None:
            if previous != completed_file:
                raise StoreError("A file reference cannot be redirected")
            return
        self._commit([("FILE#" + completed_file.file_ref, completed_file.public_metadata())],
                     files=[completed_file])
        self._files[completed_file.file_ref] = completed_file

    def end_execution(self):
        self._writable()
        if self.execution_ended:
            return
        meta = self._get("META") | {"status": "finalizing", "updated_at": self._clock()}
        self._commit([("META", meta)])
        self._execution_ended = True

    async def save_final(self, final_result):
        body = model_json(ExecutionReport, final_result)
        for finding in body["findings"]:
            self._check_local_refs(finding["refs"])
        self._writable()
        if not self.execution_ended:
            raise StoreError("End execution before saving its final result")
        if self._terminal is not None:
            if same_json(self._get("RESULT#final"), body):
                return
            raise StoreError("Final result cannot be replaced")
        self._assert_quiet()
        meta = self._get("META") | {"updated_at": self._clock(),
            "final_result_ref": "final"}
        self._commit([("RESULT#final", body), ("META", meta)])
        self._terminal = "completed"

    def _assert_quiet(self):
        if any(not self.task_has_ended(i) for i in self._task_keys):
            raise StoreError("Tasks must finish cleanup before sealing")
        if any(self._action(i)["status"] not in ACTION_END for i in self._action_keys):
            raise StoreError("Actions must finish cleanup before sealing")
        if any(r.body()["status"] == "running" for k, r in self._records.items() if k.startswith("MANAGER#")):
            raise StoreError("Manager call is still running")

    def seal_records(self):
        self._writable()
        if self._terminal is None:
            raise StoreError("A recorded final result is required")
        self._assert_quiet()
        meta = self._get("META") | {"status": self._terminal, "updated_at": self._clock()}
        self._commit([("META", meta)], terminal=True)
        self._sealed = True

    def seal_without_final(self):
        """Flush an interrupted run's existing records without claiming completion.

        The caller propagates the original manager/API error. This introduces no
        failure result, public failure state, retry or process-resume policy.
        """
        self._writable()
        if not self.execution_ended or self._terminal is not None:
            raise StoreError("Only a stopped run without a final result may use this boundary")
        self._assert_quiet()
        self._commit([("META", self._get("META"))], terminal=True)
        self._sealed = True

    def _attach_publisher(self, owner):
        self._check_loop()
        if self._publisher_owner is not None:
            raise StoreError("A Store has exactly one publisher owner")
        self._publisher_owner = owner

    def _claim(self):
        if self._inflight is not None:
            return self._inflight
        if self._pending:
            self._inflight = self._pending.popleft()
        return self._inflight

    def _ack(self, publication, seq):
        if self._inflight is not publication or seq < self._last_saved_seq:
            raise StoreError("Publication acknowledgement mismatch")
        self._last_saved_seq = seq
        self._inflight = None
        self._changed.set()

    def _publisher_failed(self, error):
        self._publisher_error = error
        self._changed.set()

    async def wait_until_published(self):
        self._check_loop()
        while True:
            self._changed.clear()
            if self._publisher_error is not None:
                raise self._publisher_error
            if self._sealed and not self._pending and self._inflight is None and self._publisher_done:
                return
            await self._changed.wait()
