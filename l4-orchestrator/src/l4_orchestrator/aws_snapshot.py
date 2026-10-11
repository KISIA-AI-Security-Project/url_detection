"""Read the existing Store contract for continuous backend/SSE delivery."""
import json


def display_body(value, source_prefix):
    """Keep public evidence links; Fast record keys remain in the Store only."""
    if isinstance(value, dict):
        return {key: [ref for ref in item if not isinstance(ref, str) or not ref.startswith(source_prefix)]
                if key == "refs" and isinstance(item, list) else display_body(item, source_prefix)
                for key, item in value.items()}
    if isinstance(value, list):
        return [display_body(item, source_prefix) for item in value]
    return value


async def build_snapshot(reader, run, *, file_url, execution_status=None):
    """One complete display snapshot; detail clicks need no record query."""
    rows = await reader.list_items(run["run_id"], "")
    groups = {name: [] for name in ("works", "tasks", "actions", "managers", "results", "files")}
    names = {"WORK": "works", "TASK": "tasks", "ACTION": "actions", "MANAGER": "managers"}
    meta = next((row for row in rows if row["record_key"] == "META"), None)
    source_prefix = "records/" + run["input"]["job_id"] + "/"
    final = None
    for row in rows:
        kind, _, identity = row["record_key"].partition("#")
        if kind in names:
            # Store bodies hold display records, not SDK/model wire history.
            groups[names[kind]].append(display_body(await reader.body(row), source_prefix))
        elif kind == "RESULT":
            body = display_body(await reader.body(row), source_prefix)
            groups["results"].append({"result_ref": identity,
                "kind": "final" if identity == "final" else "agent_report" if identity.startswith("report:") else "tool_result",
                "data": body})
            if identity == "final":
                final = body
        elif kind == "FILE":
            value = {name: row[name] for name in ("file_ref", "content_type", "size_bytes", "sha256")}
            value["source_metadata"] = json.loads(row["source_metadata_json"])
            value.update(file_url(row))
            groups["files"].append(value)
    # Store issues W/T/ACT in numeric sequence; DynamoDB key order is lexical.
    groups["works"].sort(key=lambda row: int(row["id"][1:]))
    groups["tasks"].sort(key=lambda row: int(row["id"][1:]))
    groups["actions"].sort(key=lambda row: int(row["action_id"][3:]))
    groups["managers"].sort(key=lambda row: row["started_at"])
    status = meta["status"] if meta else "starting"
    error = None
    # Preserve Store's finalizing status after a model call error. The worker's
    # actual SSM outcome distinguishes an ended process from an active one.
    if execution_status in {"Failed", "Cancelled", "TimedOut", "Cancelling"} and status != "completed":
        status, error = "failed", {"code": "l4_execution_error", "execution_status": execution_status,
            "message": "심층분석 실행이 중단되었습니다. 확보된 기록은 아래에서 확인할 수 있습니다."}
    progress = [{"text": row["situation"], "manager_call_id": row["id"], "status": row["status"],
                 "review_work_ids": row["review_work_ids"], "query_count": row["query_count"]}
                for row in groups["managers"]]
    return {"run_id": run["run_id"], "scan_id": run["input"]["job_id"], "input": run["input"],
        "status": status, "store_status": meta["status"] if meta else None,
        "updated_at": meta["updated_at"] if meta else run["created_at"],
        "publish_seq": meta["last_saved_seq"] if meta else 0,
        "progress": progress, "result": final, "error": error, **groups}
