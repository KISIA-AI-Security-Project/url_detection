"""Execute commands in a caller-bound environment; no SDK, Store or Page access."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import threading
from time import perf_counter
from types import MappingProxyType
from typing import Mapping

from pydantic import Field, field_validator

from ..bash_process import CommandProcesses
from ..ports import ExecutionPort
from ..schemas import WireModel


class BashInput(WireModel):
    command: str = Field(strict=True, min_length=1)
    timeout_ms: int = Field(strict=True, ge=1)

    @field_validator("command")
    @classmethod
    def valid_command(cls, value):
        if not value.strip() or "\0" in value:
            raise ValueError("A nonblank command without NUL characters is required")
        value.encode("utf-8")
        return value


@dataclass(frozen=True)
class BashEnvironment:
    """Paths and the complete environment supplied by the trusted caller.

    This runs on the machine hosting Python. It does not create isolation,
    connect to EC2, inherit the host's environment or choose a storage location.
    """
    bash_path: Path
    cwd: Path
    env: Mapping[str, str]

    def __post_init__(self):
        for name in ("bash_path", "cwd"):
            path = Path(getattr(self, name))
            if not path.is_absolute():
                raise ValueError(f"{name} must be an absolute caller-provided path")
            path = path.resolve(strict=True)
            str(path).encode("utf-8")
            if not (path.is_file() if name == "bash_path" else path.is_dir()):
                raise ValueError(f"Invalid {name}")
            object.__setattr__(self, name, path)
        if not isinstance(self.env, Mapping):
            raise ValueError("Provide the complete command environment explicitly")
        copied = dict(self.env)
        for key, value in copied.items():
            if (type(key) is not str or not key or "=" in key or "\0" in key or
                    type(value) is not str or "\0" in value):
                raise ValueError("Environment keys and values must be valid strings")
            key.encode("utf-8")
            value.encode("utf-8")
        object.__setattr__(self, "env", MappingProxyType(copied))


class BashCleanupError(RuntimeError):
    """Cancellation ended, but the caller must inspect/retire the environment."""
    def __init__(self, reply):
        super().__init__("Bash process cleanup could not be confirmed.")
        self.reply = reply


class _Output:
    def __init__(self, limit):
        self.limit = limit
        self.prefix = bytearray()
        self.total = 0
        self.error = False
        self._lock = threading.Lock()

    def drain(self, pipe):
        try:
            with pipe:
                while chunk := pipe.read1(65536):
                    with self._lock:
                        self.total += len(chunk)
                        remaining = max(0, self.limit - len(self.prefix))
                        self.prefix.extend(chunk[:remaining])
        except OSError:
            with self._lock:
                self.error = True

    def fields(self, name):
        with self._lock:
            prefix, total = bytes(self.prefix), self.total
        encoded = None
        try:
            content = prefix.decode("utf-8")
        except UnicodeDecodeError:
            content = None
            encoded = base64.b64encode(prefix).decode("ascii")
        return {name: content, f"{name}_base64": encoded,
                f"{name}_bytes": total, f"{name}_truncated": total > len(prefix)}


class BashTool:
    def __init__(self, environment: BashEnvironment, *, max_timeout_ms: int,
                 max_output_bytes: int, cleanup_timeout_ms: int):
        if not isinstance(environment, BashEnvironment):
            raise ValueError("A caller-provided BashEnvironment is required")
        if os.name not in {"nt", "posix"}:
            raise ValueError("This execution adapter requires Windows or POSIX")
        for limit in (max_timeout_ms, max_output_bytes, cleanup_timeout_ms):
            if type(limit) is not int or limit < 1:
                raise ValueError("Caller limits must be positive integers")
        self._environment = environment
        self._max_timeout_ms = max_timeout_ms
        self._max_output_bytes = max_output_bytes
        self._cleanup_timeout_ms = cleanup_timeout_ms

    async def execute(self, arguments):
        request = BashInput.model_validate(arguments)
        if request.timeout_ms > self._max_timeout_ms:
            return self._reply(request, "failed", error={
                "code": "TIMEOUT_LIMIT_EXCEEDED",
                "message": "Request a timeout within the caller's configured maximum.",
            })
        cancelled = threading.Event()
        task = asyncio.create_task(asyncio.to_thread(self._run, request, cancelled))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled.set()
            # Repeated cancellation cannot abandon the worker/process cleanup.
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    pass
            if not task.cancelled():
                reply = task.result()
                if reply["error"] and reply["error"]["code"] == "CLEANUP_NOT_CONFIRMED":
                    raise BashCleanupError(reply)
            raise

    def _reply(self, request, status, *, error=None):
        return {
            "tool": "bash", "command": request.command, "cwd": str(self._environment.cwd),
            "status": status, "started_at": None, "finished_at": None,
            "duration_ms": 0, "exit_code": None,
            "stdout": "", "stderr": "", "stdout_base64": None, "stderr_base64": None,
            "stdout_bytes": 0, "stderr_bytes": 0,
            "stdout_truncated": False, "stderr_truncated": False,
            "timed_out": False, "cancelled": False,
            "cleanup_confirmed": None, "error": error,
        }

    def _run(self, request, cancelled):
        reply = self._reply(request, "failed")
        reply["started_at"] = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        deadline = started + request.timeout_ms / 1000
        scope, process, readers = None, None, []
        outputs = [_Output(self._max_output_bytes), _Output(self._max_output_bytes)]
        reason = None
        try:
            if cancelled.is_set():
                reason = "cancelled"
                return reply
            scope = CommandProcesses()
            process = scope.start(self._environment.bash_path, self._environment.cwd,
                                  dict(self._environment.env), request.command)
            for output, pipe in zip(outputs, (process.stdout, process.stderr)):
                reader = threading.Thread(target=output.drain, args=(pipe,), daemon=True)
                reader.start()
                readers.append(reader)
            if cancelled.is_set():
                reason = "cancelled"
            elif perf_counter() >= deadline:
                reason = "timeout"
            while reason is None and process.poll() is None:
                remaining = deadline - perf_counter()
                if cancelled.is_set():
                    reason = "cancelled"
                    break
                if remaining <= 0:
                    reason = "timeout"
                    break
                cancelled.wait(min(remaining, 0.02))
            if reason is None:
                start_error = scope.start_error()
                if start_error is not None:
                    reply["error"] = {"code": "START_FAILED", "message": start_error}
                else:
                    reply["exit_code"] = process.returncode
                    reply["status"] = "success" if process.returncode == 0 else "failed"
                    if process.returncode != 0:
                        reply["error"] = {"code": "COMMAND_FAILED",
                                          "message": "The command exited with a nonzero code."}
        except (OSError, ValueError) as exc:
            reply["error"] = {"code": "START_FAILED",
                              "message": f"The supplied command environment could not start: {exc}"}
        finally:
            if scope is not None:
                cleanup_deadline = perf_counter() + self._cleanup_timeout_ms / 1000
                try:
                    scope.stop()  # Also stop background children after normal shell exit.
                    while not scope.empty() and perf_counter() < cleanup_deadline:
                        threading.Event().wait(min(0.01, max(0, cleanup_deadline - perf_counter())))
                    reply["cleanup_confirmed"] = scope.empty()
                except OSError:
                    reply["cleanup_confirmed"] = False
                finally:
                    try:
                        scope.close()
                    except OSError:
                        reply["cleanup_confirmed"] = False
                process = scope.process  # A failed start can still have created a launcher.
                if process is not None:
                    reply["exit_code"] = process.poll()
                    for pipe in (process.stdout, process.stderr)[len(readers):]:
                        if pipe is not None:
                            pipe.close()
            for reader in readers:
                reader.join(max(0, cleanup_deadline - perf_counter()))
            for name, output in zip(("stdout", "stderr"), outputs):
                reply.update(output.fields(name))
            if reason == "timeout":
                reply["status"] = "timeout"
                reply["timed_out"] = True
                reply["exit_code"] = None  # Forced launcher exit is not a Bash result.
                reply["error"] = {"code": "COMMAND_TIMEOUT",
                                  "message": "The command exceeded the requested timeout."}
            elif reason == "cancelled":
                reply["status"] = "failed"
                reply["cancelled"] = True
                reply["exit_code"] = None
                reply["error"] = {"code": "COMMAND_CANCELLED",
                                  "message": "The caller cancelled this command."}
            elif reply["error"] and reply["error"]["code"] == "START_FAILED":
                reply["exit_code"] = None
            if any(reader.is_alive() for reader in readers):
                reply["cleanup_confirmed"] = False
            if reply["cleanup_confirmed"] is False:
                reply["status"] = "failed"
                reply["error"] = {"code": "CLEANUP_NOT_CONFIRMED",
                                  "message": "Process or output cleanup could not be confirmed."}
            elif any(output.error for output in outputs):
                reply["status"] = "failed"
                reply["error"] = {"code": "OUTPUT_READ_FAILED",
                                  "message": "A command output stream could not be read completely."}
            reply["finished_at"] = datetime.now(timezone.utc).isoformat()
            reply["duration_ms"] = round((perf_counter() - started) * 1000)
        return reply

    def as_port(self):
        def prepare(request, assigned_task):
            return BashInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Execute a Bash command in a caller-bound environment and working directory. "
                        "Requires command and timeout_ms. Returns actual exit code, bounded stdout/stderr "
                        "and explicit truncation/cleanup state. Files can persist between calls; shell "
                        "variables and cd do not. No automatic retry, browser connection or interpretation.",
            kind="tool", provenance="new_observation",
            permission_description="Runs with the supplied analysis environment's OS permissions. "
                                   "The caller owns isolation, allowed operations and file registration. "
                                   "cwd is not a filesystem boundary; no implicit host env or AWS access.",
            prepare=prepare, invoke=self.execute,
        )
