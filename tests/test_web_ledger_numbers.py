"""Real boto3 wire serialization, without any AWS call."""
from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
import json

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from evidence_pipeline.model_choices import select_model, validate_selection
from web_service.api import WebApi
from web_service.ledger import Ledger


class DynamoRoundTripTable:
    def __init__(self):
        self.rows = {}
        self.writes = []
        self.serializer, self.deserializer = TypeSerializer(), TypeDeserializer()

    def put_item(self, **kwargs):
        item = kwargs['Item']
        wire = {key: self.serializer.serialize(value) for key, value in item.items()}
        self.writes.append(deepcopy(kwargs))
        self.rows[(item['pk'], item['sk'])] = wire
        return {}

    def get_item(self, **kwargs):
        wire = self.rows.get((kwargs['Key']['pk'], kwargs['Key']['sk']))
        return {'Item': {key: self.deserializer.deserialize(value) for key, value in wire.items()}} if wire else {}


def configured(monkeypatch):
    monkeypatch.delenv('FAST_MODEL_CHOICES_JSON', raising=False)
    monkeypatch.setenv('JUDGMENT_PROVIDER', 'bedrock')
    monkeypatch.setenv('JUDGMENT_MODEL', 'global.anthropic.claude-sonnet-5-5')
    monkeypatch.setenv('ANTHROPIC_OUTPUT_EFFORT', 'high')
    return select_model('configured')


def test_real_serializer_profile_round_trip_and_replace_preserve_hash_and_json(monkeypatch):
    selection = configured(monkeypatch)
    assert type(selection['profile']['timeout']) is float
    with pytest.raises(TypeError, match='Float types are not supported'):
        TypeSerializer().serialize(selection)
    table = DynamoRoundTripTable()
    ledger = Ledger(table)
    item = {'model_selection': selection, 'nested': [0.125, True, None, {'n': -3.5}], 'count': 2}
    before = deepcopy(item)
    assert ledger.put_new('owner', 'REQUEST', 'request', item)
    assert item == before
    assert table.writes[-1]['Item']['model_selection']['profile']['timeout'] == Decimal('120.0')
    # DynamoDB is free to normalize the textual representation of its N type.
    wire = table.rows[('USER#owner', 'REQUEST#request')]
    wire['model_selection']['M']['profile']['M']['timeout'] = {'N': '120'}
    loaded = ledger.get('owner', 'REQUEST', 'request')
    assert type(loaded['model_selection']['profile']['timeout']) is float
    assert validate_selection(loaded['model_selection']) == selection
    assert loaded['model_selection']['profile_sha256'] == selection['profile_sha256']
    canonical = json.dumps(loaded['model_selection']['profile'], ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    assert sha256(canonical.encode()).hexdigest() == selection['profile_sha256']
    assert json.loads(json.dumps(loaded))['nested'] == item['nested']
    assert type(loaded['nested'][1]) is bool
    loaded['response'] = {'wait_seconds': 1.25, 'attempt': 1, 'accepted': True}
    ledger.replace('owner', 'REQUEST', 'request', loaded)
    cached = ledger.get('owner', 'REQUEST', 'request')
    assert cached['response'] == loaded['response']
    assert type(cached['response']['attempt']) is int
    assert json.loads(json.dumps(cached))['response']['wait_seconds'] == 1.25


def test_actual_api_acceptance_then_cached_response_uses_real_dynamo_codec(monkeypatch):
    configured(monkeypatch)
    table = DynamoRoundTripTable()
    calls = []
    scan = 'a' * 32
    def invoke(role, event):
        calls.append(event)
        request = json.loads(event['body'])
        selected = request['model_selection']
        return 202, {'scanId': scan, 'pollUrl': '/analyses/' + scan, 'status': 'PENDING',
                     'model_choice': selected['choice'], 'model_profile_sha256': selected['profile_sha256'],
                     'reasoning_effort': selected['profile']['output_effort'],
                     'wait_seconds': 0.25}
    app = WebApi(Ledger(table), invoke, lambda _: None)
    event = {'rawPath': '/api/analyses', 'requestContext': {'http': {'method': 'POST'},
             'authorizer': {'jwt': {'claims': {'sub': 'owner', 'token_use': 'access'}}}},
             'body': json.dumps({'url': 'https://example.com/', 'request_id': '1' * 32,
                                 'model_choice': 'configured'})}
    first = app.handle(event)
    second = app.handle(event)
    assert first['statusCode'] == second['statusCode'] == 202
    assert json.loads(first['body']) == json.loads(second['body'])
    assert json.loads(second['body'])['wait_seconds'] == 0.25
    assert len(calls) == 1


@pytest.mark.parametrize('number', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_numbers_fail_before_dynamo_write(number):
    table = DynamoRoundTripTable()
    ledger = Ledger(table)
    with pytest.raises(ValueError, match='nonfinite_ledger_number'):
        ledger.put_new('owner', 'REQUEST', 'request', {'nested': [number]})
    assert table.writes == []
