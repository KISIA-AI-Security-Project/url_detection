import {WebAuth} from './auth.js';
import {ServiceClient} from './service-client.js';
import {renderVirusTotal} from './virustotal-renderer.js';
import {renderDeep} from './deep-result-renderer.js';
const $=selector=>document.querySelector(selector);
const ui={
 form:$('#analysis-form'),url:$('#target-url'),vt:$('#vt-option'),submit:$('#submit'),
 login:$('#login'),logout:$('#logout'),hint:$('#access-hint'),status:$('#request-status'),
 error:$('#service-error'),analysis:$('#analysis'),history:$('#history-panel'),
 historyList:$('#history-list'),vtResult:$('#virustotal'),deepAction:$('#deep-action'),
 deepButton:$('#start-deep'),deepPanel:$('#deep-panel'),deepStatus:$('#deep-status'),
 deepProgress:$('#deep-progress'),deepResult:$('#deep-result')
};
let auth,service,activeTask,activeResult,activeScan,activeUrl,startedAt,timer;
function error(error) {
 if(error?.name==='AbortError') return;
 ui.error.textContent=error.message||'요청을 처리하지 못했습니다.';ui.error.hidden=false;
 if(error.status===401) {ui.submit.disabled=true;ui.login.hidden=false;ui.hint.hidden=false;ui.hint.textContent='로그인이 만료됐습니다. 다시 로그인해 주세요.';}
}
function reset() {
 clearInterval(timer);activeResult=null;activeScan=null;startedAt=null;activeUrl=null;
 ui.error.hidden=true;ui.analysis.replaceChildren();ui.vtResult.hidden=true;
 ui.deepAction.hidden=true;ui.deepPanel.hidden=true;ui.deepProgress.replaceChildren();ui.deepResult.replaceChildren();
 ui.deepButton.disabled=false;ui.deepButton.textContent='심층분석';
}
function node(tag,className,text) {const e=document.createElement(tag);if(className)e.className=className;if(text!==undefined)e.textContent=text;return e;}
async function loadHistory() {
 const response=await service.request('/analyses');ui.historyList.replaceChildren();
 for(const row of response.analyses) {
  const li=node('li'),button=node('button','history-item',row.url);button.type='button';
  button.addEventListener('click',()=>open(row).catch(error));li.append(button);ui.historyList.append(li);
 }
 if(!response.analyses.length) ui.historyList.append(node('li','subtle-copy','아직 분석 기록이 없습니다.'));
 ui.history.hidden=false;return response.analyses;
}
function applyFast(result,task) {
 if(!service.current(task)) return;
 const previous=activeResult;activeResult=result;
 if(!previous || previous.result_revision!==result.result_revision || previous.judgment_status!==result.judgment_status)
  window.FastResult.render(ui.analysis,result,{url:activeUrl});
 if(result.judgment_status==='pending') return;
 clearInterval(timer);ui.submit.disabled=false;
 if(startedAt) {
  const duration=performance.now()-startedAt;ui.status.textContent='빠른 분석 결과 수신까지 '+(duration/1000).toFixed(2)+'초';
  ui.status.dataset.durationMs=String(Math.round(duration));
 } else ui.status.textContent='저장된 빠른 분석 결과입니다.';
 ui.deepAction.hidden=!(result.judgment_status==='accepted' && result.deep_analysis?.available);
}
async function monitor(scan,attempt,task,vtSelected,startVt=false) {
 if(vtSelected) {
  ui.vtResult.hidden=false;renderVirusTotal(ui.vtResult,{status:'queued'});
  (async()=>{
   if(startVt)await service.startVt(scan,task);
   if(service.current(task))await service.streamVt(scan,task,value=>renderVirusTotal(ui.vtResult,value));
  })().catch(e=>{if(service.current(task)&&e.name!=='AbortError')renderVirusTotal(ui.vtResult,{status:'failed'});});
 }
 try {await service.streamFast(scan,attempt,task,value=>applyFast(value,task));}
 catch(e) {if(service.current(task)) {clearInterval(timer);ui.submit.disabled=false;error(e);}}
}
async function open(row) {
 activeTask=service.begin();const task=activeTask;reset();activeScan=row.scanId;activeUrl=row.url;ui.url.value=row.url;
 ui.status.textContent='분석 결과를 불러오고 있습니다.';ui.submit.disabled=false;sessionStorage.setItem('web.activeScan',activeScan);
 await monitor(activeScan,undefined,task,Boolean(row.virustotal_requested));
}
async function submit(event) {
 event.preventDefault();if(!auth?.tokens) return error(new Error('로그인 후 이용해 주세요.'));
 activeTask=service.begin();const task=activeTask;reset();activeUrl=ui.url.value.trim();ui.submit.disabled=true;startedAt=performance.now();
 ui.status.textContent='분석 요청을 접수하고 있습니다.';
 timer=setInterval(()=>{if(service.current(task)) ui.status.textContent='빠른 분석 중 · '+((performance.now()-startedAt)/1000).toFixed(1)+'초';},100);
 try {
  const accepted=await service.start(activeUrl,ui.vt.checked,task);
  if(!service.current(task)) return;activeScan=accepted.scanId;sessionStorage.setItem('web.activeScan',activeScan);
  await Promise.all([loadHistory().catch(()=>{}),monitor(activeScan,accepted.expectedAttempt,task,Boolean(accepted.virustotal),true)]);
 } catch(e) {if(service.current(task)) {clearInterval(timer);ui.submit.disabled=false;error(e);}}
}
function showDeep(value) {
 renderDeep({status:ui.deepStatus,progress:ui.deepProgress,result:ui.deepResult},value);
}
async function deep() {
 if(!activeResult || !service.current(activeTask) || ui.deepButton.disabled) return;
 const task=activeTask,identity={job_id:activeResult.job_id,attempt:activeResult.attempt,
 context_revision:activeResult.context_revision,result_revision:activeResult.result_revision};
 ui.deepButton.disabled=true;ui.deepButton.textContent='심층분석 요청 중';ui.deepPanel.hidden=false;ui.deepStatus.textContent='심층분석을 접수하고 있습니다.';
 try {
  const run=await service.deep(identity,task);if(!service.current(task)) return;
  ui.deepButton.textContent='심층분석 진행 중';await service.streamDeep(run,task,showDeep);
  if(service.current(task)) ui.deepButton.textContent='심층분석 요청 완료';
 } catch(e) {if(service.current(task)) {ui.deepButton.disabled=false;ui.deepButton.textContent='심층분석';ui.deepStatus.textContent='심층분석 요청을 처리하지 못했습니다.';error(e);}}
}
async function initialize() {
 const response=await fetch('config.json',{cache:'no-store'});if(!response.ok) throw new Error('서비스 설정을 불러오지 못했습니다.');
 const config=await response.json();if(!config.auth || typeof config.api_base!=='string') throw new Error('서비스 설정을 확인하지 못했습니다.');
 auth=new WebAuth(config.auth);service=new ServiceClient(config.api_base,auth);
 ui.login.addEventListener('click',()=>auth.login().catch(error));ui.logout.addEventListener('click',()=>{service.stop();auth.logout();});
 ui.form.addEventListener('submit',submit);ui.deepButton.addEventListener('click',deep);
 if(!await auth.initialize()) return;
 ui.login.hidden=true;ui.logout.hidden=false;ui.hint.hidden=true;ui.submit.disabled=false;
 const list=await loadHistory(),saved=sessionStorage.getItem('web.activeScan');
 const row=list.find(row=>row.scanId===saved);if(row) await open(row);
}
window.addEventListener('pagehide',()=>{clearInterval(timer);service?.stop();});
initialize().catch(error);
