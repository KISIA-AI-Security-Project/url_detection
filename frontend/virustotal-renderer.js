// VT is a separate report. This module never changes the service's verdict or evidence.
const categoryLabels={
  malicious:'위험 표시',suspicious:'의심 표시',harmless:'위험 없음 표시',undetected:'탐지 없음',
  timeout:'응답 시간 초과','confirmed-timeout':'응답 시간 초과',failure:'검사 실패',
  'type-unsupported':'검사 대상 아님'
};
function node(tag,className,text) {const element=document.createElement(tag);if(className)element.className=className;if(text!==undefined)element.textContent=text;return element;}
function time(value) {const date=new Date(value);return Number.isNaN(date.getTime())?'자료 시각 없음':date.toLocaleString('ko-KR');}
export function renderVirusTotal(root,result) {
  root.replaceChildren();
  const section=node('section','provider-result');section.setAttribute('aria-label','VirusTotal 별도 결과');
  section.append(node('h2',null,'VirusTotal 별도 결과'),
    node('p','subtle-copy','여러 보안 검사 제공사의 결과입니다. 우리 서비스의 판정에는 사용하지 않습니다.'));
  const messages={
    queued:'VirusTotal 결과를 조회하고 있습니다. 다른 요청이 있으면 호출 한도에 맞춰 순서대로 처리합니다.',
    not_requested:'VirusTotal 조회를 선택하지 않았습니다.',
    not_found:'VirusTotal에 이 주소의 기존 검사 결과가 없습니다.',
    quota_exhausted:'VirusTotal 호출 한도에 도달했습니다. 우리 분석 결과는 계속 확인할 수 있습니다.',
    failed:'VirusTotal 결과를 가져오지 못했습니다. 우리 분석 결과는 계속 확인할 수 있습니다.'
  };
  if (result.status!=='completed') {section.append(node('p','provider-status',messages[result.status]||messages.failed));root.append(section);return;}
  const stats=result.stats;
  if (!stats || typeof stats.malicious!=='number' || typeof stats.suspicious!=='number') throw new Error('unexpected_vt_stats');
  const total=Object.values(stats).reduce((sum,count)=>sum+count,0);
  section.append(node('p','provider-summary',total+'개 검사 중 위험 표시 '+stats.malicious+'개 · 의심 표시 '+stats.suspicious+'개'));
  if (result.report_at) section.append(node('p','subtle-copy','검사 자료 시각: '+time(result.report_at)));
  section.append(node('p','subtle-copy','조회 시각: '+time(result.checked_at)));
  const details=node('details','provider-details');details.append(node('summary',null,'검사별 결과 보기'));
  const list=node('ul','provider-engines');
  for (const engine of result.engines||[]) {
    const li=node('li');li.append(node('strong',null,engine.name),node('span',null,' — '+(categoryLabels[engine.category]||'기타 결과')));
    if(engine.result) li.append(node('span','provider-engine-detail',' ('+engine.result+')'));
    list.append(li);
  }
  details.append(list);section.append(details);
  if (result.report_url && /^https:\/\/www\.virustotal\.com\/gui\/url\/[a-f0-9]{64}\/detection$/.test(result.report_url)) {
    const link=node('a','link','VirusTotal에서 결과 보기');link.href=result.report_url;link.target='_blank';link.rel='noopener noreferrer';section.append(link);
  }
  root.append(section);
}

