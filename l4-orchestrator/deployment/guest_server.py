"""Browser and native Bash host; this container receives no AWS/model secret."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading

import playwright
from playwright._impl._driver import compute_driver_executable

from l4_orchestrator.tools.bash import BashEnvironment, BashTool


def main():
    cfg = json.loads(Path("/opt/l4/runtime-config.json").read_text(encoding="utf-8"))["tool_settings"]
    Path("/tmp/l4-bash").mkdir(exist_ok=True)
    native = BashTool(BashEnvironment(bash_path=Path("/bin/bash"), cwd=Path("/work/artifacts"),
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/l4-bash", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}),
        max_timeout_ms=cfg["bash_max_timeout_ms"], max_output_bytes=cfg["bash_max_output_bytes"],
        cleanup_timeout_ms=cfg["bash_cleanup_timeout_ms"])
    node, _ = compute_driver_executable()
    browser_env = dict(os.environ)
    browser_env["L4_PLAYWRIGHT_PACKAGE"] = str(Path(playwright.__file__).parent / "driver" / "package")
    browser = subprocess.Popen([str(node), "/opt/l4/browser_server.cjs"], env=browser_env)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/health":
                self.send_error(404)
                return
            payload = json.dumps({"native_bash": True, "browser_process_running": browser.poll() is None}).encode()
            self.reply(payload)

        def do_POST(self):
            if self.path != "/execute":
                self.send_error(404)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1024 * 1024:
                self.send_error(413)
                return
            try:
                arguments = json.loads(self.rfile.read(size))
                result = asyncio.run(native.execute(arguments))
            except (ValueError, TypeError):
                self.send_error(400)
                return
            self.reply(json.dumps(result, ensure_ascii=False).encode())

        def reply(self, payload):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", 9100), Handler)
    def watch_browser():
        browser.wait()
        server.shutdown()
    threading.Thread(target=watch_browser, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if browser.poll() is None:
            browser.terminate()
            browser.wait(timeout=15)
    if browser.returncode:
        raise SystemExit(browser.returncode)


if __name__ == "__main__":
    main()
