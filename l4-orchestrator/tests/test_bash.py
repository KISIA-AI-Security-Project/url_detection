from sdk_tool_checks import run_native_steps
"""Real Bash/process checks in test-owned folders, not an AWS/SDK deployment."""
import asyncio
import base64
from copy import deepcopy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import threading
import time

import pytest
from pydantic import ValidationError

from l4_orchestrator.bash_process import CommandProcesses, _WindowsJob
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.bash import BashCleanupError, BashEnvironment, BashInput, BashTool
from l4_orchestrator.tools.bash import _Output
from l4_orchestrator.tools.record_reader import RecordReader, RecordSource


@pytest.fixture(scope="session")
def bash_path():
    # Discovery belongs to this local test setup; the Tool has no default path.
    configured = os.environ.get("L4_TEST_BASH")
    if configured:
        path = Path(configured).resolve(strict=True)
    elif os.name == "nt":
        path = Path("C:/Program Files/Git/bin/bash.exe")
    else:
        installed = shutil.which("bash")
        path = Path(installed) if installed else None
    if path is None or not path.is_file():
        pytest.skip("Provide a real Bash through L4_TEST_BASH")
    return path


def make_tool(bash_path, folder, *, output_limit=4096, cleanup_ms=2000, environment=None):
    if environment is None:
        if os.name == "nt":
            environment = {"PATH": str(bash_path.parent.parent / "usr/bin"),
                           "SystemRoot": os.environ["SystemRoot"],
                           "TEMP": str(folder), "TMP": str(folder)}
        else:
            environment = {"PATH": "/usr/bin:/bin"}
        environment.update(TEST_PYTHON=sys.executable, PYTHONIOENCODING="utf-8",
                           TEST_VALUE="explicit", LC_ALL="C.UTF-8")
    return BashTool(BashEnvironment(bash_path, folder, environment),
                    max_timeout_ms=5000, max_output_bytes=output_limit,
                    cleanup_timeout_ms=cleanup_ms)


def execute(tool, command, timeout_ms=5000):
    return asyncio.run(tool.execute({"command": command, "timeout_ms": timeout_ms}))


def python_command(code):
    return '"$TEST_PYTHON" -c ' + shlex.quote(code)


def running(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    dll.OpenProcess.restype = ctypes.c_void_p
    dll.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    dll.WaitForSingleObject.restype = ctypes.c_uint32
    dll.CloseHandle.argtypes = [ctypes.c_void_p]
    dll.CloseHandle.restype = ctypes.c_int
    handle = dll.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE; never terminate.
    if not handle:
        return False
    try:
        return dll.WaitForSingleObject(handle, 0) == 0x102  # WAIT_TIMEOUT.
    finally:
        dll.CloseHandle(handle)


def sleeper_command():
    return python_command(
        "import os, time; from pathlib import Path; "
        "Path('child.pid').write_text(str(os.getpid())+'\\n'); "
        "print('started', flush=True); time.sleep(30); "
        "Path('survived.txt').write_text('unexpected')"
    ) + " & wait"


async def wait_for_child(folder):
    deadline = asyncio.get_running_loop().time() + 4
    while True:
        try:
            content = (folder / "child.pid").read_text()
        except OSError:
            content = ""
        if content.endswith("\n") and content.strip().isdecimal():
            return int(content)
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("The real child did not start")
        await asyncio.sleep(0.01)


def test_actual_stdout_stderr_unicode_and_exit_code(bash_path, tmp_path):
    tool = make_tool(bash_path, tmp_path)
    reply = execute(tool, "printf '한글 문구\\n'; printf 'error text\\n' >&2")
    assert reply["status"] == "success" and reply["exit_code"] == 0
    assert reply["stdout"] == "한글 문구\n" and reply["stderr"] == "error text\n"
    assert reply["stdout_bytes"] == len(reply["stdout"].encode("utf-8"))
    assert reply["cleanup_confirmed"] is True and reply["error"] is None
    assert reply["started_at"] and reply["finished_at"] and reply["duration_ms"] > 0
    assert reply["cwd"] == str(tmp_path)


def test_shell_quoting_pipeline_and_multiline_command(bash_path, tmp_path):
    reply = execute(make_tool(bash_path, tmp_path),
                    "printf '%s\\n' 'a b' '$(literal)' | tr '[:lower:]' '[:upper:]'\n"
                    "printf '%s' 'quote: \" and single quote follows'\n")
    assert reply["status"] == "success"
    assert reply["stdout"] == 'A B\n$(LITERAL)\nquote: " and single quote follows'


def test_nonzero_exit_keeps_partial_outputs_and_does_not_retry(bash_path, tmp_path):
    reply = execute(make_tool(bash_path, tmp_path),
                    "printf run >> counter.txt; printf partial; printf reason >&2; exit 7")
    assert reply["status"] == "failed" and reply["exit_code"] == 7
    assert reply["stdout"] == "partial" and reply["stderr"] == "reason"
    assert reply["error"]["code"] == "COMMAND_FAILED"
    assert (tmp_path / "counter.txt").read_text() == "run"


@pytest.mark.parametrize("code", [1, 125, 126, 127])
def test_real_command_exit_codes_are_not_misclassified_as_start_failures(bash_path, tmp_path, code):
    reply = execute(make_tool(bash_path, tmp_path), f"printf ran; exit {code}")
    assert reply["status"] == "failed" and reply["exit_code"] == code
    assert reply["error"]["code"] == "COMMAND_FAILED"
    assert reply["stdout"] == "ran" and reply["stderr"] == ""
    assert reply["cleanup_confirmed"] is True


def test_files_persist_but_shell_variables_and_cd_do_not(bash_path, tmp_path):
    tool = make_tool(bash_path, tmp_path)
    assert execute(tool, "printf '자료' > '분석 결과.txt'; mkdir inside; cd inside; "
                        "export SESSION_VALUE=kept")["status"] == "success"
    reply = execute(tool, "cat '분석 결과.txt'; printf '\\n%s' \"$SESSION_VALUE\"")
    assert reply["status"] == "success" and reply["stdout"] == "자료\n"
    cwd = execute(tool, python_command("import os; print(os.getcwd())"))
    assert Path(cwd["stdout"].strip()).resolve() == tmp_path


def test_environment_is_explicit_copied_and_not_host_inherited(bash_path, tmp_path, monkeypatch):
    tool = make_tool(bash_path, tmp_path)
    original = dict(tool._environment.env)
    environment = BashEnvironment(bash_path, tmp_path, original)
    original["TEST_VALUE"] = "mutated"
    with pytest.raises(TypeError):
        environment.env["TEST_VALUE"] = "mutated"
    monkeypatch.setenv("L4_HOST_ONLY", "not-for-command")
    isolated = BashTool(environment, max_timeout_ms=5000,
                        max_output_bytes=4096, cleanup_timeout_ms=2000)
    reply = execute(isolated, "printf '%s|%s' \"$TEST_VALUE\" \"$L4_HOST_ONLY\"")
    assert reply["stdout"] == "explicit|"


def test_output_cap_drains_both_streams_without_retaining_whole_body(bash_path, tmp_path):
    reply = execute(make_tool(bash_path, tmp_path, output_limit=257), python_command(
        "import os; os.write(1, b'a' * 200000); os.write(2, b'b' * 220000)"
    ))
    assert reply["status"] == "success"
    assert reply["stdout"] == "a" * 257 and reply["stderr"] == "b" * 257
    assert reply["stdout_bytes"] == 200000 and reply["stderr_bytes"] == 220000
    assert reply["stdout_truncated"] is True and reply["stderr_truncated"] is True


@pytest.mark.parametrize("command,limit,raw,total", [
    (r"printf '\377\000x'", 4096, b"\xff\x00x", 3),
    ("printf '한글'", 2, "한글".encode("utf-8")[:2], 6),
])
def test_non_utf8_or_split_character_preserves_exact_prefix_as_base64(
    bash_path, tmp_path, command, limit, raw, total
):
    reply = execute(make_tool(bash_path, tmp_path, output_limit=limit), command)
    assert reply["status"] == "success" and reply["stdout"] is None
    assert base64.b64decode(reply["stdout_base64"]) == raw
    assert reply["stdout_bytes"] == total
    assert reply["stdout_truncated"] is (total > len(raw))


def test_timeout_stops_real_child_and_preserves_observed_output(bash_path, tmp_path):
    reply = execute(make_tool(bash_path, tmp_path), sleeper_command(), timeout_ms=1000)
    pid = int((tmp_path / "child.pid").read_text())
    assert reply["status"] == "timeout" and reply["error"]["code"] == "COMMAND_TIMEOUT"
    assert reply["exit_code"] is None and reply["stdout"] == "started" + os.linesep
    assert reply["timed_out"] is True
    assert reply["cleanup_confirmed"] is True and not running(pid)
    assert not (tmp_path / "survived.txt").exists()
    assert reply["duration_ms"] < 4000


def test_normal_shell_exit_also_stops_unfinished_background_child(bash_path, tmp_path):
    child = sleeper_command().removesuffix(" & wait")
    command = child + " &\nwhile [ ! -f child.pid ]; do sleep 0.01; done\nexit 0"
    reply = execute(make_tool(bash_path, tmp_path), command)
    assert reply["status"] == "success" and reply["exit_code"] == 0
    assert reply["cleanup_confirmed"] is True
    assert not running(int((tmp_path / "child.pid").read_text()))
    assert not (tmp_path / "survived.txt").exists()


@pytest.mark.parametrize("repeat", [False, True])
def test_cancellation_waits_for_real_cleanup_even_when_cancelled_again(
    bash_path, tmp_path, monkeypatch, repeat
):
    started, finished = threading.Event(), threading.Event()
    original_stop = CommandProcesses.stop

    def slow_stop(scope):
        original_stop(scope)
        started.set()
        time.sleep(0.15)
        finished.set()

    monkeypatch.setattr(CommandProcesses, "stop", slow_stop)

    async def scenario():
        task = asyncio.create_task(make_tool(bash_path, tmp_path).execute({
            "command": sleeper_command(), "timeout_ms": 5000}))
        try:
            pid = await wait_for_child(tmp_path)
            task.cancel()
            if repeat:
                assert await asyncio.to_thread(started.wait, 2)
                task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert finished.is_set() and not running(pid)
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    asyncio.run(scenario())
    assert not (tmp_path / "survived.txt").exists()


def test_cancellation_during_slow_launch_does_not_abandon_created_process(
    bash_path, tmp_path, monkeypatch
):
    original_start = CommandProcesses.start

    def slow_start(scope, *arguments):
        process = original_start(scope, *arguments)
        time.sleep(0.25)
        return process

    monkeypatch.setattr(CommandProcesses, "start", slow_start)

    async def scenario():
        task = asyncio.create_task(make_tool(bash_path, tmp_path).execute({
            "command": sleeper_command(), "timeout_ms": 5000}))
        pid = await wait_for_child(tmp_path)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not running(pid)

    asyncio.run(scenario())


def test_timeout_includes_slow_launch(bash_path, tmp_path, monkeypatch):
    original_start = CommandProcesses.start

    def slow_start(scope, *arguments):
        process = original_start(scope, *arguments)
        time.sleep(0.10)
        return process

    monkeypatch.setattr(CommandProcesses, "start", slow_start)
    reply = execute(make_tool(bash_path, tmp_path), "printf fast", timeout_ms=30)
    assert reply["status"] == "timeout" and reply["cleanup_confirmed"] is True


def test_unconfirmed_cleanup_never_returns_success(bash_path, tmp_path, monkeypatch):
    monkeypatch.setattr(CommandProcesses, "empty", lambda scope: False)
    reply = execute(make_tool(bash_path, tmp_path, cleanup_ms=50), "printf observed")
    assert reply["status"] == "failed" and reply["cleanup_confirmed"] is False
    assert reply["error"]["code"] == "CLEANUP_NOT_CONFIRMED"
    assert reply["stdout"] == "observed"


def test_unfinished_output_readers_are_not_reported_as_confirmed_cleanup(
    bash_path, tmp_path, monkeypatch
):
    release = threading.Event()
    readers = []
    original_drain = _Output.drain

    def delayed_drain(output, pipe):
        readers.append(threading.current_thread())
        release.wait(2)
        original_drain(output, pipe)

    monkeypatch.setattr(_Output, "drain", delayed_drain)
    try:
        reply = execute(make_tool(bash_path, tmp_path, cleanup_ms=50), "printf buffered")
        assert reply["status"] == "failed" and reply["cleanup_confirmed"] is False
        assert reply["error"]["code"] == "CLEANUP_NOT_CONFIRMED"
    finally:
        release.set()
        for reader in readers:
            reader.join(2)
            assert not reader.is_alive()


def test_cancellation_exposes_unconfirmed_cleanup_instead_of_hiding_it(
    bash_path, tmp_path, monkeypatch
):
    monkeypatch.setattr(CommandProcesses, "empty", lambda scope: False)

    async def scenario():
        task = asyncio.create_task(make_tool(bash_path, tmp_path, cleanup_ms=50).execute({
            "command": sleeper_command(), "timeout_ms": 5000}))
        pid = await wait_for_child(tmp_path)
        task.cancel()
        with pytest.raises(BashCleanupError) as failure:
            await task
        assert failure.value.reply["error"]["code"] == "CLEANUP_NOT_CONFIRMED"
        assert failure.value.reply["cancelled"] is True
        assert not running(pid)  # Only the confirmation was replaced in this counterexample.

    asyncio.run(scenario())


def test_timeout_remains_explicit_when_cleanup_confirmation_fails(bash_path, tmp_path, monkeypatch):
    monkeypatch.setattr(CommandProcesses, "empty", lambda scope: False)
    reply = execute(make_tool(bash_path, tmp_path, cleanup_ms=50), sleeper_command(), 1000)
    assert reply["status"] == "failed" and reply["timed_out"] is True
    assert reply["error"]["code"] == "CLEANUP_NOT_CONFIRMED"
    assert reply["exit_code"] is None
    assert not running(int((tmp_path / "child.pid").read_text()))


def test_excess_timeout_is_rejected_before_start(bash_path, tmp_path):
    reply = execute(make_tool(bash_path, tmp_path), "printf bad > should-not-exist", 5001)
    assert reply["error"]["code"] == "TIMEOUT_LIMIT_EXCEEDED"
    assert reply["started_at"] is None and reply["cleanup_confirmed"] is None
    assert not (tmp_path / "should-not-exist").exists()


@pytest.mark.parametrize("arguments", [
    {"command": "", "timeout_ms": 10}, {"command": " \n", "timeout_ms": 10},
    {"command": "x\0y", "timeout_ms": 10}, {"command": "\ud800", "timeout_ms": 10},
    {"command": "true", "timeout_ms": True}, {"command": "true", "timeout_ms": "10"},
    {"command": "true", "timeout_ms": 0}, {"command": "true"},
    {"command": "true", "timeout_ms": 10, "cwd": "/other-analysis"},
])
def test_invalid_or_environment_switching_input_is_rejected(arguments):
    with pytest.raises(ValidationError):
        BashInput.model_validate(arguments)


def test_configuration_requires_explicit_paths_environment_and_limits(bash_path, tmp_path):
    with pytest.raises(ValueError):
        BashEnvironment(bash_path, Path("relative-folder"), {})
    with pytest.raises(ValueError):
        BashEnvironment(Path("bash"), tmp_path, {})
    for env in [None, {"BAD=NAME": "x"}, {"name": 1}, {"name": "x\0y"}]:
        with pytest.raises(ValueError):
            BashEnvironment(bash_path, tmp_path, env)
    for name in ("max_timeout_ms", "max_output_bytes", "cleanup_timeout_ms"):
        limits = {"max_timeout_ms": 100, "max_output_bytes": 100, "cleanup_timeout_ms": 100}
        limits[name] = True
        with pytest.raises(ValueError):
            BashTool(BashEnvironment(bash_path, tmp_path, {}), **limits)


def test_unavailable_working_directory_is_a_start_failure(bash_path, tmp_path):
    folder = tmp_path / "removed"
    folder.mkdir()
    tool = make_tool(bash_path, folder)
    folder.rmdir()
    reply = execute(tool, "printf should-not-run")
    assert reply["status"] == "failed" and reply["error"]["code"] == "START_FAILED"
    assert reply["stdout"] == "" and reply["exit_code"] is None


def test_executable_removed_after_configuration_is_a_start_failure(tmp_path):
    executable = tmp_path / "removed-bash.exe"
    executable.write_bytes(b"Placeholder that will be removed before execution")
    tool = make_tool(executable, tmp_path, environment={"SystemRoot": os.environ["SystemRoot"]}
                     if os.name == "nt" else {})
    executable.unlink()
    reply = execute(tool, "printf should-not-run > marker.txt")
    assert reply["status"] == "failed" and reply["error"]["code"] == "START_FAILED"
    assert reply["exit_code"] is None and reply["cleanup_confirmed"] is True
    assert reply["stdout"] == "" and reply["stderr"] == ""
    assert not (tmp_path / "marker.txt").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows launch-before-assignment counterexample")
def test_failed_job_assignment_does_not_start_bash_or_leave_launcher(
    bash_path, tmp_path, monkeypatch
):
    def denied(job, pid):
        raise OSError("Test job assignment failure")
    monkeypatch.setattr(_WindowsJob, "assign", denied)
    reply = execute(make_tool(bash_path, tmp_path), "printf bad > should-not-exist")
    assert reply["status"] == "failed" and reply["error"]["code"] == "START_FAILED"
    assert reply["cleanup_confirmed"] is True
    assert reply["exit_code"] is None
    assert not (tmp_path / "should-not-exist").exists()


def test_real_saved_record_extraction_through_sdk_and_following_manager_input(bash_path, tmp_path):
    root = Path(__file__).resolve().parents[2]
    ref = "records/a5091407d4c2c2f5b8cb95a3acc6ee59/1/l3/l3.json"
    source = root / "docs/l4-first-investigation-20260928/sources/s3" / ref
    original = source.read_bytes()
    sha = hashlib.sha256(original).hexdigest()
    expected = RecordReader({ref: RecordSource(source, sha)}, max_data_bytes=4096).read({
        "record_ref": ref, "pointer": "/observation/raw/html/document"})
    assert expected["status"] == "ok"
    (tmp_path / "input.json").write_bytes(original)
    command = python_command(
        "import json; data=json.load(open('input.json', encoding='utf-8')); "
        "print(json.dumps(data['observation']['raw']['html']['document'], ensure_ascii=True))")
    arguments = {"command": command, "timeout_ms": 5000}
    proof = asyncio.run(run_native_steps({"bash": make_tool(bash_path, tmp_path)}, [("bash", arguments)]))
    assert proof.prepared_inputs[0] == arguments
    assert proof.results[0]["status"] == "success"
    assert json.loads(proof.results[0]["stdout"]) == expected["data"]
    assert source.read_bytes() == original and (tmp_path / "input.json").read_bytes() == original
