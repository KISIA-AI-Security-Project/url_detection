"""Brand comparison grounds survive selection and the actual Messages boundary."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from L3_SCANNER.policies import DetectionPolicy
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline import build_text_context
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway
from evidence_pipeline.l3_html_text import assemble
from evidence_pipeline.model_text import call_text_messages
from test_l3_html_text import capture, document, transport
from test_model_text import capture_l012


SIDS = ('L3-H-05', 'L3-H-06')
CONFIDENCE = 'brand_identification_confidence'
GROUND_LABEL = '브랜드 선택 근거로 기록된 위치'
SHARED_LABEL = '문서·리소스 대조에 선택된 브랜드'


def configured_policy(path):
    config = json.loads((Path(__file__).resolve().parents[1] /
                         'L3_SCANNER/policies/operational.v1.json').read_text(encoding='utf-8'))
    config['brands'] = {'ExampleBrand': {
        'title_tokens': ['ExampleBrand'], 'site_name_tokens': ['ExampleBrand'],
        'hostname_tokens': ['examplebrand'], 'expected_domains': ['example.com'],
        'resource_domains': ['example.net'],
    }}
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return operational_detection_policy(path)


def callback_policy(*identities):
    calls = iter(identities) if len(identities) > 1 else None
    return DetectionPolicy(
        brand_identifier=lambda context: deepcopy(next(calls) if calls else identities[0]),
        brand_expected_domains={'ExampleBrand': ('example.com',)},
        brand_resource_rules={'evaluator': lambda evidence: False})


def identity(**overrides):
    return {'brand': 'ExampleBrand', 'sources': ['title'], 'confidence': 'high',
            'provider': 'controlled-catalog', 'provider_entity_id': 'entry-one', **overrides}


def assert_preserved(a, doc, *, native_supplied=True):
    assert doc.source_context['html_native'] == (a['native'] if native_supplied else None)
    assert doc.source_context['html_record'] == a['record']
    assert doc.source_context['html_raw'] == a['raw']
    for i, signal in enumerate(a['record']['signals']):
        if signal['id'] in SIDS and CONFIDENCE in signal['evidence']:
            pointer = f'/signals/{i}/evidence/{CONFIDENCE}'
            omissions = [item for item in doc.source_context['model_omissions']
                         if item['source'] == 'record' and item['pointer'] == pointer]
            assert len(omissions) == 1
            assert 'uncalibrated producer label' in omissions[0]['reason']
    assert not any(source['pointer'].endswith('/' + CONFIDENCE)
                   for row in doc.source_context['line_map'] for source in row['sources'])
    transport(doc)


@pytest.mark.parametrize('source,confidence,phrase', [
    ('title', 'high', '문서 제목'),
    ('og_site_name', 'high', 'HTML의 사이트 이름(og:site_name)'),
    ('hostname', 'low', '문서 주소의 호스트 이름'),
    ('callback', None, '위치가 기록되지 않음'),
])
def test_producer_labels_stay_internal_and_recorded_grounds_reach_messages(tmp_path, source, confidence, phrase):
    html = {'title': '<title>ExampleBrand 사용 후기</title>',
            'og_site_name': '<meta property="og:site_name" content="ExampleBrand">',
            'hostname': '<p>Account access</p>', 'callback': '<p>No recorded match location</p>'}[source]
    policy = callback_policy('ExampleBrand') if source == 'callback' else configured_policy(tmp_path / 'policy.json')
    url = 'https://examplebrand-login.example.net/' if source == 'hostname' else 'https://pages.example.net/'
    a = capture(html + '<img src="/logo">', policy=policy, url=url)
    before = deepcopy(a)
    doc = document(a)
    for values in (a['native']['signals'], a['record']['signals']):
        for signal in values:
            if signal['id'] in SIDS:
                assert signal['evidence'][CONFIDENCE] == confidence
                assert signal['evidence']['brand_identification_sources'] == ([] if source == 'callback' else [source])
    assert GROUND_LABEL + ': ' + phrase in doc.body
    assert '정책이 기록한 식별 확신:' not in doc.body
    assert CONFIDENCE not in doc.body
    assert '실제 운영자나 사칭 여부가 확인되지는 않음' in doc.body
    assert doc.version == 'l3-html-text-2'
    assert_preserved(a, doc)
    assert a == before


def test_only_confidence_differs_share_grounds_with_both_source_occurrences():
    a = capture('<title>ExampleBrand</title><img src="/logo">',
                policy=callback_policy(identity(), identity(confidence='low')))
    doc = document(a)
    for label, key in [(SHARED_LABEL, 'detected_brand'),
                       (GROUND_LABEL, 'brand_identification_sources'),
                       ('분석에 기록된 브랜드 정보 출처', 'brand_policy_provider')]:
        rows = [r for r in doc.source_context['line_map'] if r['text'].startswith(label + ':')]
        assert len(rows) == 1
        row = rows[0]
        expected = [{'source': 'record', 'pointer': f'/signals/{i}/evidence/{key}'}
                    for i, s in enumerate(a['record']['signals']) if s['id'] in SIDS]
        assert row['sources'] == expected
        assert tuple(a['record']['signals'][int(p['pointer'].split('/')[2])]['id'] for p in row['sources']) == SIDS
        assert set(SIDS) <= set(next(b for b in doc.blocks if b.title == row['title']).evidence_ids)
    assert [s['evidence'][CONFIDENCE] for s in a['record']['signals'] if s['id'] in SIDS] == ['high', 'low']
    assert_preserved(a, doc)


@pytest.mark.parametrize('difference', [
    {'sources': ['hostname']}, {'provider': 'other-catalog'}, {'provider_entity_id': 'entry-two'},
])
def test_different_recorded_identity_evidence_is_not_merged(difference):
    a = capture('<title>ExampleBrand</title><img src="/logo">',
                policy=callback_policy(identity(), identity(**difference)))
    doc = document(a)
    assert SHARED_LABEL not in doc.body
    assert '문서 도메인 대조에 선택된 브랜드: ExampleBrand' in doc.body
    assert '리소스 묶음 대조에 선택된 브랜드: ExampleBrand' in doc.body
    assert doc.body.count(GROUND_LABEL + ':') == 2
    for row in doc.source_context['line_map']:
        if row['text'].startswith(GROUND_LABEL + ':'):
            assert len(row['sources']) == 1
    assert_preserved(a, doc)


def test_unknown_recorded_source_is_literal_and_not_reinterpreted():
    a = capture('<title>ExampleBrand</title>', policy=callback_policy(
        identity(sources=['title', 'custom_source', 'og_site_name', 'hostname'])))
    doc = document(a)
    assert GROUND_LABEL + ': 문서 제목, custom_source (근거 종류 미해석), HTML의 사이트 이름(og:site_name), 문서 주소의 호스트 이름' in doc.body
    assert_preserved(a, doc)


def test_confidence_words_in_original_html_are_preserved_as_data():
    literal = '정책이 기록한 식별 확신: high low confidence'
    source = f'<title>{literal}</title><p>{literal}</p><img src="/logo" alt="{literal}"><input onkeyup="{literal}">'
    a = capture(source, policy=callback_policy(identity()))
    doc = document(a)
    assert a['raw']['html']['source'] == source
    assert doc.body.count(literal) == 4
    assert_preserved(a, doc)


@pytest.mark.parametrize('mutation', ['coordinated_reinsertion', 'v1', 'unknown', 'downgrade_remove_marker'])
def test_unreviewed_confidence_or_version_is_rejected_before_provider(mutation):
    a = capture('<title>ExampleBrand</title>', policy=callback_policy(identity()))
    doc = document(a)
    if mutation == 'coordinated_reinsertion':
        block = next(b for b in doc.blocks if b.title == '브랜드 정책·리소스 관계')
        block.lines.append('정책이 기록한 식별 확신: high')
        doc.body, doc.source_map = assemble(doc.blocks)
    else:
        doc.version = {'v1': 'l3-html-text-1', 'unknown': 'unknown-html',
                       'downgrade_remove_marker': 'layer-text-1'}[mutation]
        if mutation == 'downgrade_remove_marker':
            doc.source_context.pop('html_review_input')
    calls = []
    def forbidden(request, **kwargs):
        calls.append(request)
        pytest.fail('Unreviewed document reached the provider')
    gateway = JudgmentV2Gateway('https://offline.example', 'offline-key', 'offline-model', view=None, opener=forbidden)
    with pytest.raises(ValueError):
        call_text_messages(doc, gateway, 'Offline boundary verification only.')
    assert calls == []


def test_combined_l012_html_omits_confidence_and_preserves_all_selected_layers(monkeypatch):
    records, raws, _ = capture_l012(monkeypatch)
    base = build_text_context(records, raws)
    a = capture('<title>ExampleBrand</title><img src="/logo">',
                policy=callback_policy(identity()), url=records[0]['target']['original_url'],
                request=records[0]['request_id'])
    doc = build_text_context(records + [a['record']], {**raws, 'l3': a['raw']}, l3_scope='html')
    assert doc.body.startswith(base.body.rstrip('\n') + '\n\n')
    assert '정책이 기록한 식별 확신:' not in doc.body
    assert GROUND_LABEL + ': 문서 제목' in doc.body
    assert_preserved(a, doc, native_supplied=False)
