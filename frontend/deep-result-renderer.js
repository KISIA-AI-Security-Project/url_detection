// The complete authorized L4 snapshot arrives through SSE. Expanding details is local.
const stateNames={queued:'대기 중',assigned:'작업 배정',starting:'준비 중',running:'진행 중',waiting:'다른 작업을 기다리는 중',
 preparing:'입력 준비 중',returned:'보고 도착',answered:'업무 답변 완료',completed:'전체 완료',finalizing:'기록 전송 마무리 중',
 success:'실행 완료',failed:'실패',error:'오류',skipped:'건너뜀',ended_by_manager:'총괄이 조사를 종료해 더 수행하지 않음'};
const toolPhrases={
 navigate:['페이지 여는 중','페이지 이동 결과 도착'],get_page_state:['화면 살펴보는 중','페이지 상태 조회 완료'],
 capture_screenshot:['화면 캡처 중','화면 캡처 완료'],click:['화면 요소 클릭 중','화면 요소 클릭 결과 도착'],
 type_text:['화면에 입력 중','입력 결과 도착'],press_key:['키 입력 중','키 입력 결과 도착'],
 scroll:['화면 스크롤 중','스크롤 결과 도착'],get_network_requests:['페이지 통신 기록 확인 중','페이지 통신 목록 조회 완료'],
 get_network_request:['통신 요청 확인 중','통신 요청 조회 완료'],get_network_response_body:['통신 응답 확인 중','통신 응답 본문 조회 완료'],
 export_page:['페이지 자료 저장 중','페이지 자료 저장 완료'],read_result:['기존 결과 확인 중','기존 결과 조회 완료'],
 record_reader:['기록 자료 확인 중','기록 자료 조회 완료'],bash:['명령 실행 중','명령 실행 결과 도착']};
const numericId=value=>Number(String(value).match(/\d+$/)?.[0]||0);
const timeValue=value=>typeof value==='string'?Date.parse(value):NaN;
function toolPhrase(action,finished=false) {
 if(finished&&action.status!=='success')return (action.tool_name||'도구')+' 실행 오류';
 return toolPhrases[action.tool_name]?.[finished?1:0]||((action.tool_name||'도구')+(finished?' 결과 도착':' 실행 중'));
}
export function workProgress(work,snapshot) {
 const tasks=list(snapshot.tasks).filter(t=>t.work_id===work.id),actions=list(snapshot.actions).filter(a=>a.work_id===work.id);
 const active=tasks.filter(t=>['running','queued','waiting'].includes(t.status));
 const running=active.filter(t=>t.status==='running');
 const latest=rows=>[...rows].sort((a,b)=>timeValue(a.finished_at||a.started_at||a.assigned_at)-timeValue(b.finished_at||b.started_at||b.assigned_at)||numericId(a.id||a.action_id)-numericId(b.id||b.action_id)).at(-1);
 let now;
 if(running.length>1)now=running.length+'개 작업 진행 중';
 else if(running.length) {
  const task=running[0],invoked=latest(actions.filter(a=>a.task_id===task.id&&a.status==='running'));
  const preparing=actions.some(a=>a.task_id===task.id&&a.status==='preparing');
  now=invoked?toolPhrase(invoked):preparing?'도구 입력 준비 중':task.execution?.kind==='agent'?'실행 Agent 조사 중':'작업 준비 중';
 } else if(active.some(t=>t.status==='waiting'))now='다른 작업을 기다리는 중';
 else if(active.length)now='확인 작업 준비 중';
 else {
  const task=latest(tasks);
  now=task?.status==='returned'?'보고 도착':task?.status==='failed'?'작업 실행 오류':task?.status==='ended_by_manager'?stateNames.ended_by_manager:task?.status==='skipped'?'작업 종료':
   task?.status==='success'?toolPhrase(latest(actions.filter(a=>a.task_id===task.id))||{tool_name:task.execution?.name,status:'success'},true):'확인 작업 준비 중';
  const continued=latest(list(snapshot.managers).filter(m=>list(m.review_work_ids).includes(work.id)));
  if(task?.status==='returned'&&continued?.status==='returned'&&continued.registration_status==='registered'&&
   continued.decision_summary?.finish===false&&timeValue(task.finished_at)>=timeValue(continued.started_at)&&
   timeValue(task.finished_at)<=timeValue(continued.finished_at))now='다음 판단 대기';
 }
 if(work.status==='answered')now='업무 답변 완료'+(running.length?' · '+now:'');
 else if(snapshot.status==='completed')now='조사 종료';
 const reviewing=list(snapshot.managers).filter(m=>m.status==='running'&&list(m.review_work_ids).includes(work.id));
 if(reviewing.length)now+=(reviewing.some(m=>m.query_count>0)?' · 총괄이 자료 확인 중':' · 총괄 검토 중');
 if(snapshot.status==='finalizing')now+=' · 기록 전송 마무리 중';
 return now;
}
export function overallProgress(snapshot) {
 if(snapshot.status==='completed')return '전체 완료';
 if(snapshot.status==='finalizing')return '기록 전송 마무리 중';
 if(snapshot.status==='failed')return '심층분석 실행이 중단되었습니다.';
 if(['queued','starting'].includes(snapshot.status))return '심층분석 준비 중';
 const manager=list(snapshot.managers).findLast(m=>m.status==='running');
 if(!list(snapshot.works).length)return manager?.situation||'자료 확인 중';
 return '추가 확인 진행 중';
}
export function workActivity(work,snapshot) {
 const events=[];
 const add=(id,at,label,ref,kind,number)=>{if(Number.isFinite(timeValue(at)))events.push({id,at,label,ref,kind,number});};
 add(work.id+':assigned',work.assigned_at,'확인 업무 배정',null,0,numericId(work.id));
 for(const task of list(snapshot.tasks).filter(t=>t.work_id===work.id)) {
  const title=task.title||'확인 작업',number=numericId(task.id);
  add(task.id+':assigned',task.assigned_at,title+' · 작업 배정',task.id,1,number);
  add(task.id+':started',task.started_at,title+' · 작업 시작',task.id,2,number);
  if(task.finished_at) {
   const label=task.status==='returned'?'실행 Agent 보고 도착':task.status==='success'?'작업 실행 완료':task.status==='ended_by_manager'?stateNames.ended_by_manager:task.status==='skipped'?'작업 종료':'작업 실행 오류';
   add(task.id+':finished',task.finished_at,title+' · '+label,task.result_ref||task.id,4,number);
  }
 }
 for(const action of list(snapshot.actions).filter(a=>a.work_id===work.id)) {
  add(action.action_id+':started',action.started_at,toolPhrase(action),action.action_id,2,numericId(action.action_id));
  add(action.action_id+':finished',action.finished_at,toolPhrase(action,true),action.result_ref||action.action_id,3,numericId(action.action_id));
 }
 for(const [index,manager] of list(snapshot.managers).entries()) {
  if(!list(manager.review_work_ids).includes(work.id))continue;
  add(manager.id+':started',manager.started_at,'총괄 검토 시작','manager:'+manager.id,2,index+1);
  add(manager.id+':finished',manager.finished_at,manager.status==='failed'?'총괄 호출 오류':manager.decision_summary?.finish?'총괄 조사 종료 결정':'총괄 판단 도착','manager:'+manager.id,5,index+1);
 }
 add(work.id+':answered',work.answered_at,'총괄의 업무 답변 도착',work.id,6,numericId(work.id));
 return events.sort((a,b)=>timeValue(a.at)-timeValue(b.at)||a.number-b.number||a.kind-b.kind||a.id.localeCompare(b.id));
}
function displayTime(value) {
 return Number.isFinite(timeValue(value))?new Date(value).toLocaleString('ko-KR',{hour12:false}):value;
}
function node(tag,className,text) {
 const value=document.createElement(tag);if(className)value.className=className;
 if(text!==undefined)value.textContent=text;return value;
}
function text(parent,label,value) {
 if(typeof value==='string'&&value)parent.append(node('p','deep-field',label?label+' · '+value:value));
}
function technical(parent,label,value,openKeys) {
 if(value===undefined||value===null||value==='')return;
 const details=node('details','deep-technical');details.dataset.deepKey=parent.dataset.deepKey+'/technical:'+label;
 details.open=openKeys.has(details.dataset.deepKey);details.append(node('summary','',label));
 details.append(node('pre','',typeof value==='string'?value:JSON.stringify(value,null,2)));parent.append(details);
}
function list(value) {return Array.isArray(value)?value:[];}
function report(parent,value,{concise=false,openKeys=new Set()}={}) {
 if(!value||typeof value!=='object')return;
 text(parent,'',value.summary);
 const findings=list(value.findings),limits=list(value.limits);
 for(const finding of concise?findings.slice(0,3):findings)text(parent,'',finding?.statement);
 if(concise&&(findings.length>3||limits.length)) {
  const more=record(parent,'report-extra','추가 확인 내용과 범위',openKeys);
  for(const finding of findings.slice(3))text(more,'',finding?.statement);
  for(const limit of limits)text(more,'확인 범위',limit);
 } else for(const limit of limits)text(parent,'확인 범위',limit);
}
function record(parent,key,title,openKeys) {
 const details=node('details','deep-record');details.dataset.deepKey=key;details.open=openKeys.has(key);
 details.append(node('summary','',title));parent.append(details);return details;
}
function status(value) {return stateNames[value]||value||'';}
function safeFileUrl(value) {
 if(typeof value!=='string')return null;
 try {const url=new URL(value);return url.protocol==='https:'?url.href:null;}catch{return null;}
}
export function renderDeep({status:statusRoot,progress:progressRoot,result:resultRoot},snapshot) {
 statusRoot.textContent=overallProgress(snapshot);
 const openKeys=new Set([...progressRoot.querySelectorAll('details[data-deep-key][open]'),...resultRoot.querySelectorAll('details[data-deep-key][open]')].map(row=>row.dataset.deepKey));
 const tech=(parent,label,value)=>technical(parent,label,value,openKeys);
 progressRoot.replaceChildren();resultRoot.replaceChildren();
 if(typeof snapshot.updated_at==='string')text(progressRoot,'최근 저장',displayTime(snapshot.updated_at));
 if(snapshot.result)report(resultRoot,snapshot.result,{concise:true,openKeys});
 if(snapshot.status==='failed')text(resultRoot,'','심층분석 중 문제가 발생했습니다. 아래에서 그동안 확인한 내용을 볼 수 있습니다.');
 const works=list(snapshot.works),tasks=list(snapshot.tasks),actions=list(snapshot.actions),
  results=list(snapshot.results).filter(row=>row.kind!=='final'),files=list(snapshot.files),managers=list(snapshot.managers);
 if(!works.length&&!tasks.length&&!actions.length&&!results.length&&!files.length&&!managers.length)return;
 const details=record(resultRoot,'all','전체 결과와 파일',openKeys);
 const refs=new Map(),workCards=new Map(),taskCards=new Map(),actionCards=new Map();
 const reference=(parent,ref,label)=>{
  if(typeof ref!=='string')return;
  const button=node('button','link',label);button.type='button';
  button.addEventListener('click',()=>{const target=refs.get(ref);if(!target)return;
   for(let ancestor=target;ancestor;ancestor=ancestor.parentElement)if(ancestor.tagName==='DETAILS')ancestor.open=true;
   target.scrollIntoView({behavior:'smooth',block:'center'});});parent.append(button);
 };
 if(works.length)progressRoot.append(node('h3','deep-work-heading','확인 업무와 현재 상황'));
 for(const work of works) {
  const card=record(progressRoot,'work:'+work.id,'',openKeys);card.classList.add('deep-work');
  const summary=card.querySelector(':scope > summary');summary.className='deep-work-summary';
  summary.append(node('span','deep-work-title',work.title||work.question||'확인 항목'),node('span','deep-work-now',workProgress(work,snapshot)));
  refs.set(work.id,card);workCards.set(work.id,card);
  card.append(node('h4','deep-work-heading','진행 내역'));
  const timeline=node('ol','deep-activity');card.append(timeline);
  for(const event of workActivity(work,snapshot)) {
   const item=node('li','deep-activity-event');item.dataset.eventId=event.id;
   item.append(node('time','deep-activity-time',displayTime(event.at)),node('span','deep-activity-label',event.label));
   reference(item,event.ref,'해당 기록 보기');timeline.append(item);
  }
  const context=record(card,'work-context:'+work.id,'업무 질문·답변·확인 범위',openKeys);
  text(context,'확인 질문',work.question);text(context,'확인하는 이유',work.reason);
  text(context,'상태',status(work.status));text(context,'확인 내용',work.answer);
  if(list(work.scope?.restrictions).length)text(context,'확인 범위',work.scope.restrictions.join('\n'));
  if(list(work.scope?.target_refs).length)tech(context,'확인 대상 자료',work.scope.target_refs);
  if(list(work.scope?.allowed_tools).length)tech(context,'사용할 수 있는 도구',work.scope.allowed_tools);
  for(const ref of list(work.answer_refs))reference(card,ref,'관련 결과 보기');
 }
 for(const task of tasks) {
  const card=record(workCards.get(task.work_id)||details,'task:'+task.id,'작업 · '+(task.title||'확인 작업'),openKeys);
  refs.set(task.id,card);taskCards.set(task.id,card);
  text(card,'상태',status(task.status));text(card,'대기 이유',task.waiting_reason);
  text(card,'시작',displayTime(task.started_at));text(card,'종료',displayTime(task.finished_at));
  text(card,'작업 지시',task.execution?.instruction);
  if(task.execution?.kind==='tool') {
   text(card,'사용한 도구',task.execution.name);tech(card,'작업에서 요청한 도구 입력',task.execution.arguments_json);
  } else if(task.execution?.kind==='agent') {
   if(list(task.execution.allowed_tools).length)tech(card,'작업자가 사용할 수 있는 도구',task.execution.allowed_tools);
   if(list(task.execution.input_refs).length)tech(card,'작업자가 참고할 자료',task.execution.input_refs);
  }
  for(const ref of list(task.after))reference(card,ref,'먼저 진행한 작업 보기');
  reference(card,task.result_ref,'작업 결과 보기');tech(card,'오류 내용',task.error);
 }
 for(const action of actions) {
  const card=record(taskCards.get(action.task_id)||workCards.get(action.work_id)||details,'action:'+action.action_id,'도구 실행 · '+(action.tool_name||'확인 도구'),openKeys);
  refs.set(action.action_id,card);actionCards.set(action.action_id,card);text(card,'상태',status(action.status));text(card,'도구 응답 상태',action.native_status);
  text(card,'시작',displayTime(action.started_at));text(card,'종료',displayTime(action.finished_at));
  tech(card,'처음 요청한 도구 입력',action.arguments_json);
  tech(card,'실제로 전달한 도구 입력',action.prepared_input_json);
  reference(card,action.result_ref,'도구 결과 보기');tech(card,'오류 내용',action.error);
 }
 for(const result of results) {
  const task=tasks.find(t=>t.result_ref===result.result_ref),action=actions.find(a=>a.result_ref===result.result_ref);
  const parent=actionCards.get(action?.action_id)||taskCards.get(task?.id)||details;
  const card=record(parent,'result:'+result.result_ref,result.kind==='agent_report'?'작업자의 확인 보고':'도구가 반환한 결과',openKeys);
  refs.set(result.result_ref,card);
  if(result.kind==='agent_report')report(card,result.data);
  else tech(card,'반환 내용',result.data);
 }
 for(const [index,file] of files.entries()) {
  const image=typeof file.content_type==='string'&&file.content_type.startsWith('image/');
  const network=typeof file.file_ref==='string'&&file.file_ref.startsWith('network://');
  const card=record(details,'file:'+file.file_ref,(image?'캡처 화면':network?'페이지 통신 기록':'확인 자료')+' '+(index+1),openKeys);refs.set(file.file_ref,card);
  text(card,'파일 형식',file.content_type);
  if(Number.isFinite(file.size_bytes))text(card,'크기',(file.size_bytes/1024).toFixed(1)+' KB');
  const url=safeFileUrl(file.url);
  if(url) {const link=node('a','link',image?'이미지 열기':'파일 열기');link.href=url;link.target='_blank';link.rel='noopener noreferrer';card.append(link);}
  else text(card,'','파일 링크를 준비하고 있습니다.');
 }
 if(managers.length) {
  const card=record(details,'progress','분석 진행 기록',openKeys);
  for(const manager of managers) {
   const step=node('section','deep-step');refs.set('manager:'+manager.id,card);text(step,'',manager.summary||manager.situation);
   text(step,'상태',status(manager.status));text(step,'시작',displayTime(manager.started_at));text(step,'종료',displayTime(manager.finished_at));card.append(step);
  }
 }
}
