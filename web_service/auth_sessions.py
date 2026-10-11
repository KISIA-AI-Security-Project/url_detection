"""Server-only authentication records. Integer clocks; conditional transactions."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
import re
import secrets


class Conflict(Exception):
    pass


class AuthError(Exception):
    def __init__(self, status, code, message, retry_after=None):
        self.status, self.code, self.message, self.retry_after = status, code, message, retry_after


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def opaque():
    return secrets.token_urlsafe(32)


def key(kind, value):
    return kind + "#" + digest(value)


def next_row(row, **values):
    return {**deepcopy(row), **values, "version": row["version"] + 1}


def public_error(error):
    result = {"code": error.code, "message": error.message}
    if error.retry_after is not None:
        result["retry_after_seconds"] = error.retry_after
    return result


def email_address(value):
    if not isinstance(value, str):
        raise AuthError(400, "invalid_email", "이메일 주소를 확인해 주세요.")
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value):
        raise AuthError(400, "invalid_email", "이메일 주소를 확인해 주세요.")
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in value or any(not x or x.startswith("-") or x.endswith("-") for x in domain.split(".")):
        raise AuthError(400, "invalid_email", "이메일 주소를 확인해 주세요.")
    return value


SYMBOLS = frozenset('^$*.[]{}()?"!@#%&/\\,><\':;|_~`=+-')


def password(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 256 or any(c.isspace() for c in value) or not any(c in SYMBOLS for c in value):
        raise AuthError(400, "invalid_password", "비밀번호는 8~256자, 특수문자 1개 이상이며 공백 없이 입력해 주세요.")
    return value


class DynamoAuthStore:
    """No scan/query path. All writes compare an exact version or absent key."""
    def __init__(self, client, table):
        from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
        self.client, self.table = client, table
        self.serializer, self.deserializer = TypeSerializer(), TypeDeserializer()

    def encode(self, row):
        return {k: self.serializer.serialize(v) for k, v in row.items()}

    def read(self, pk):
        result = self.client.get_item(TableName=self.table, Key={"pk": {"S": pk}}, ConsistentRead=True)
        if "Item" not in result:
            return None
        # Auth rows only contain integer numbers; floats are deliberately absent.
        from decimal import Decimal
        def convert(value):
            if isinstance(value, Decimal):
                if value != value.to_integral_value():
                    raise ValueError("noninteger_auth_record")
                return int(value)
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items()}
            if isinstance(value, list):
                return [convert(v) for v in value]
            return value
        return convert({k: self.deserializer.deserialize(v) for k, v in result["Item"].items()})

    def commit(self, changes, checks=()):
        transactions = []
        for row, expected_version in changes:
            value = {"TableName": self.table, "Item": self.encode(row),
                     "ConditionExpression": "attribute_not_exists(pk)"}
            if expected_version is not None:
                value.update(ConditionExpression="#v = :v", ExpressionAttributeNames={"#v": "version"},
                             ExpressionAttributeValues={":v": {"N": str(expected_version)}})
            transactions.append({"Put": value})
        for pk, expected_version in checks:
            transactions.append({"ConditionCheck": {"TableName": self.table, "Key": {"pk": {"S": pk}},
                "ConditionExpression": "#v = :v", "ExpressionAttributeNames": {"#v": "version"},
                "ExpressionAttributeValues": {":v": {"N": str(expected_version)}}}})
        try:
            self.client.transact_write_items(TransactItems=transactions)
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if code == "TransactionCanceledException":
                reasons = error.response.get("CancellationReasons", [])
                if any(x.get("Code") == "ConditionalCheckFailed" for x in reasons):
                    raise Conflict() from None
            if code == "ConditionalCheckFailedException":
                raise Conflict() from None
            raise


def expired(row, now):
    return not row or row.get("expires_at", 0) <= now


def redact_session(row, status):
    return {k: v for k, v in next_row(row, status=status).items()
            if k not in {"access_token", "refresh_token", "placeholder", "verifier"}}
