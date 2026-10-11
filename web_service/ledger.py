"""Web ownership and optional-provider state; never a Builder input."""
from __future__ import annotations
import time
from copy import deepcopy
from decimal import Decimal
import math


def _dynamo_numbers(value):
    """Adapt JSON numbers only at the DynamoDB resource boundary."""
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite_ledger_number")
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: _dynamo_numbers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dynamo_numbers(item) for item in value]
    return value


def _json_numbers(value):
    """DynamoDB has one numeric type; return finite JSON numbers, never Decimal."""
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("nonfinite_ledger_number")
        if value == value.to_integral_value():
            return int(value)
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite_ledger_number")
        return result
    if isinstance(value, dict):
        return {key: _json_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_numbers(item) for item in value]
    return value

class Ledger:
    def __init__(self, table):
        self.table = table

    @staticmethod
    def key(owner, kind, value):
        return {"pk": "USER#" + owner, "sk": kind + "#" + value}

    def get(self, owner, kind, value):
        item = _json_numbers(self.table.get_item(Key=self.key(owner, kind, value), ConsistentRead=True).get("Item"))
        if item is not None and item.get("model_selection"):
            # DynamoDB may return N="120" for the stored timeout 120.0. Restore
            # the existing execution-profile numeric schema before hash checks.
            from evidence_pipeline.model_choices import validate_selection
            selection = item["model_selection"]
            if type(selection.get("profile", {}).get("timeout")) is int:
                selection["profile"]["timeout"] = float(selection["profile"]["timeout"])
            item["model_selection"] = validate_selection(selection, current=False)
        return item

    def put_new(self, owner, kind, value, item):
        value = {**deepcopy(item), **self.key(owner, kind, value),
                 "ttl": int(time.time()) + 30 * 86400}
        try:
            self.table.put_item(Item=_dynamo_numbers(value), ConditionExpression="attribute_not_exists(pk)")
            return True
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def replace(self, owner, kind, value, item, *, request_id=None):
        value = {**deepcopy(item), **self.key(owner, kind, value),
                 "ttl": int(time.time()) + 30 * 86400}
        args = {"Item": _dynamo_numbers(value)}
        if request_id is not None:
            args.update(ConditionExpression="request_id = :request",
                        ExpressionAttributeValues={":request": request_id})
        self.table.put_item(**args)

    def jobs(self, owner):
        from boto3.dynamodb.conditions import Key
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq("USER#" + owner) & Key("sk").begins_with("JOB#"),
            Limit=100, ConsistentRead=True)
        items = sorted(result.get("Items", []), key=lambda row: row.get("created_at", ""), reverse=True)
        return [{"scanId": row["scan_id"], "url": row["url"], "created_at": row["created_at"],
                 "virustotal_requested": bool(row.get("virustotal_requested"))}
                for row in items[:20]]

    def reserve_vt_quota(self, now, day, month):
        key = {"pk": "PROVIDER#VIRUSTOTAL", "sk": "QUOTA"}
        for _ in range(5):
            row = self.table.get_item(Key=key, ConsistentRead=True).get("Item") or {}
            daily = int(row.get("daily", 0)) if row.get("day") == day else 0
            monthly = int(row.get("monthly", 0)) if row.get("month") == month else 0
            if daily >= 500 or monthly >= 15500:
                return {"allowed": False, "exhausted": True, "wait_seconds": 0}
            wait = int(row.get("next_at", 0)) - now
            if wait > 0:
                return {"allowed": False, "exhausted": False, "wait_seconds": wait}
            version = int(row.get("version", 0))
            value = {**key, "day": day, "month": month, "daily": daily + 1,
                     "monthly": monthly + 1, "next_at": now + 16,
                     "version": version + 1, "ttl": now + 40 * 86400}
            args = {"Item": value, "ConditionExpression": "attribute_not_exists(pk)"}
            if row:
                args.update(ConditionExpression="#version = :version",
                            ExpressionAttributeNames={"#version": "version"},
                            ExpressionAttributeValues={":version": version})
            try:
                self.table.put_item(**args)
                return {"allowed": True, "exhausted": False, "wait_seconds": 0}
            except Exception as error:
                if getattr(error, "response", {}).get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
        return {"allowed": False, "exhausted": False, "wait_seconds": 16}
