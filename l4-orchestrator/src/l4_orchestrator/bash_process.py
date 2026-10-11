"""Own only the processes started by one Bash call, not its analysis sandbox."""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
        ("flags", ctypes.c_uint32), ("min_working_set", ctypes.c_size_t),
        ("max_working_set", ctypes.c_size_t), ("active_limit", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t), ("priority", ctypes.c_uint32),
        ("scheduling", ctypes.c_uint32),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits), ("io_counters", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t),
    ]


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("times", ctypes.c_int64 * 4), ("page_faults", ctypes.c_uint32),
        ("total", ctypes.c_uint32), ("active", ctypes.c_uint32),
        ("terminated", ctypes.c_uint32),
    ]


class _WindowsJob:
    def __init__(self):
        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, ctypes.c_wchar_p], ctypes.c_void_p),
            "SetInformationJobObject": ([ctypes.c_void_p, ctypes.c_int,
                                        ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int),
            "QueryInformationJobObject": ([ctypes.c_void_p, ctypes.c_int,
                                          ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.c_void_p], ctypes.c_int),
            "OpenProcess": ([ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32], ctypes.c_void_p),
            "AssignProcessToJobObject": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
            "TerminateJobObject": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int),
            "CloseHandle": ([ctypes.c_void_p], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = arguments, result
        self._dll = dll
        self._handle = dll.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not dll.SetInformationJobObject(self._handle, 9, ctypes.byref(limits),
                                          ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def assign(self, pid):
        process = self._dll.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE.
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self._dll.AssignProcessToJobObject(self._handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._dll.CloseHandle(process)

    def stop(self):
        if not self._dll.TerminateJobObject(self._handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def empty(self):
        accounting = _Accounting()
        if not self._dll.QueryInformationJobObject(
            self._handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return accounting.active == 0

    def close(self):
        if self._handle:
            self._dll.CloseHandle(self._handle)
            self._handle = None


# The launcher waits before it can start Bash. Assigning it to the Windows job
# first avoids the race where a fast Bash starts children before job assignment.
_WINDOWS_LAUNCHER = """
import sys
if sys.stdin.buffer.read(1) != b'G':
    sys.exit(1)
import msvcrt
import os
import subprocess
fd = msvcrt.open_osfhandle(int(sys.argv[1]), os.O_WRONLY | os.O_BINARY)
os.set_inheritable(fd, False)
with os.fdopen(fd, 'wb', buffering=0) as report:
    try:
        child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL,
                                 creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
    except OSError as exc:
        report.write(b'F' + str(exc)[:512].encode('utf-8', errors='replace'))
        sys.exit(1)
    report.write(b'S')
sys.exit(child.wait())
"""


class CommandProcesses:
    """One Windows job or POSIX process group. A working directory is no sandbox."""
    def __init__(self):
        self._job = _WindowsJob() if os.name == "nt" else None
        self.process = None
        self._startup_pipe = None

    def start(self, bash_path: Path, cwd: Path, env, command: str):
        arguments = [str(bash_path), "--noprofile", "--norc", "-c", command]
        options = {"cwd": cwd, "env": env, "stdout": subprocess.PIPE,
                   "stderr": subprocess.PIPE, "stdin": subprocess.DEVNULL}
        write_fd = None
        try:
            if self._job:
                import msvcrt
                read_fd, write_fd = os.pipe()
                self._startup_pipe = os.fdopen(read_fd, "rb", buffering=0)
                handle = msvcrt.get_osfhandle(write_fd)
                os.set_handle_inheritable(handle, True)
                startup = subprocess.STARTUPINFO()
                startup.lpAttributeList = {"handle_list": [handle]}
                arguments = [sys.executable, "-I", "-S", "-c", _WINDOWS_LAUNCHER,
                             str(handle), *arguments]
                options.update(stdin=subprocess.PIPE, startupinfo=startup, close_fds=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                options["start_new_session"] = True
            self.process = subprocess.Popen(arguments, **options)
        finally:
            if write_fd is not None:
                os.close(write_fd)
        if self._job:
            self._job.assign(self.process.pid)
            self.process.stdin.write(b"G")
            self.process.stdin.close()
        return self.process

    def start_error(self):
        if self._startup_pipe is None:  # POSIX Popen reports start errors directly.
            return None
        if self.process is None or self.process.poll() is None:
            return "Bash startup could not be confirmed."
        # Only the launcher inherits the write end, and it has now exited.
        # The bounded report never shares stdout/stderr or reserves an exit code.
        report = self._startup_pipe.read(4096)
        if report == b"S":
            return None
        if report.startswith(b"F"):
            return report[1:].decode("utf-8", errors="replace")
        return "Bash startup could not be confirmed."

    def stop(self):
        if self.process is None:
            return
        if self._job:
            self._job.stop()
            # If job assignment failed, the waiting launcher is not in the job.
            if self.process.poll() is None:
                self.process.kill()
        else:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def empty(self):
        if self.process is None:
            return True
        if self.process.poll() is None:
            return False
        if self._job:
            return self._job.empty()
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return True
        return False

    def close(self):
        if self._job:
            self._job.close()
        if self._startup_pipe is not None:
            self._startup_pipe.close()
        if self.process is not None and self.process.stdin is not None:
            self.process.stdin.close()
