/* Render the same fast-result-1 payload for any input URL. No site dictionary. */
(function (global) {
  'use strict';
  const labels = {BENIGN: '정상', LIKELY_BENIGN: '정상 가능성 높음', LIKELY_MALICIOUS: '악성 가능성 높음', MALICIOUS: '악성', UNKNOWN: '판단불가', SUSPICIOUS: '의심'};
  const states = {pending: ['분석 중', '결과를 준비하고 있습니다.'], not_requested: ['판정 전', '아직 판정을 요청하지 않았습니다.'], failed: ['분석을 완료하지 못했습니다', '다시 시도해 주세요.'], invalid: ['결과를 표시하지 못했습니다', '다시 시도해 주세요.']};
  function node(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }
  function button(text, action, className) {
    const el = node('button', className || 'more', text);
    el.type = 'button'; el.addEventListener('click', action); return el;
  }
  function render(root, result, options = {}) {
    if (!result || result.schema_version !== 'fast-result-1') throw new Error('unsupported_result');
    const facts = new Map(result.details.facts.map(f => [f.fact_id, f]));
    root.replaceChildren();
    const panel = node('section', 'result');
    panel.setAttribute('aria-label', '빠른 분석 결과');
    if (options.url) panel.append(node('p', 'eyebrow', options.url));
    const state = result.judgment_status, judgment = result.judgment;
    const accepted = state === 'accepted' && judgment && labels[judgment.verdict];
    const title = accepted ? labels[judgment.verdict] : (states[state] || states.invalid)[0];
    const badge = node('span', 'badge', accepted ? '빠른 분석 완료' : '빠른 분석');
    badge.dataset.verdict = accepted ? judgment.verdict : state;
    panel.append(badge, node('h1', null, title), node('p', 'lead', accepted ? judgment.summary : (states[state] || states.invalid)[1]));
    const evidence = node('section', 'evidence'); evidence.hidden = true;
    evidence.setAttribute('aria-label', '확인된 내용');
    const heading = node('div', 'evidence-heading'), evidenceTitle = node('h2');
    heading.append(evidenceTitle, button('접기', () => {evidence.hidden = true; moreFacts.focus();}, 'subtle'));
    const cards = node('div', 'factCards'); evidence.append(heading, cards);
    function showFacts(requested, all) {
      const ids = new Set();
      function add(id) {if (ids.has(id) || !facts.has(id)) return; ids.add(id); (facts.get(id).condition_fact_ids || []).forEach(add);}
      requested.forEach(add);
      cards.replaceChildren();
      result.details.facts.filter(f => ids.has(f.fact_id)).forEach(f => {
        const card = node('article', 'fact'); card.dataset.factId = f.fact_id; card.tabIndex = -1;
        const plain = f.plain;
        card.append(node('h3', null, plain ? plain.title : f.title));
        if (plain) card.append(node('p', null, plain.text));
        const details = node('details'), technical = node('pre', null, f.text);
        details.append(node('summary', null, '기술 정보 보기'), technical); card.append(details); cards.append(card);
      });
      evidenceTitle.textContent = all ? '확인된 내용' : '이유의 근거';
      evidence.hidden = false;
      const first = cards.querySelector('.fact');
      if (first) {first.classList.add('focused'); first.focus({preventScroll: true}); evidence.scrollIntoView({behavior: 'smooth', block: 'start'});}
    }
    if (accepted && judgment.reasons.length) {
      panel.append(node('hr', 'divider'), node('h2', null, '왜 이렇게 판단했나요?'));
      const list = node('ul', 'reasons'); let expanded = false;
      function renderReasons() {
        list.replaceChildren();
        (expanded ? judgment.reasons : judgment.reasons.slice(0, 3)).forEach((reason, index) => {
          const li = node('li'); li.append(node('p', 'reason-text', reason.text));
          const ids = reason.related_fact_ids.filter(id => facts.has(id));
          if (ids.length) {
            const b = button('이유의 근거 보기', () => showFacts(ids, false), 'link');
            b.setAttribute('aria-label', `${index + 1}번째 이유의 근거 보기`); li.append(b);
          }
          list.append(li);
        });
      }
      renderReasons(); panel.append(list);
      if (judgment.reasons.length > 3) {
        const moreReasons = button(`판정 이유 더 보기 (${judgment.reasons.length - 3}개)`, () => {
          expanded = !expanded; moreReasons.textContent = expanded ? '판정 이유 접기' : `판정 이유 더 보기 (${judgment.reasons.length - 3}개)`;
          moreReasons.setAttribute('aria-expanded', String(expanded)); renderReasons();
        });
        moreReasons.setAttribute('aria-expanded', 'false'); panel.append(moreReasons);
      }
    }
    const moreFacts = button('확인된 내용 더 보기', () => showFacts([...facts.keys()], true));
    if (facts.size) panel.append(moreFacts);
    root.append(panel, evidence);
    return {showFacts: ids => showFacts(ids, false)};
  }
  global.FastResult = Object.freeze({render});
})(window);
