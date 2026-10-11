import test from 'node:test';
import assert from 'node:assert/strict';
import {workProgress,workActivity,overallProgress} from '../frontend/deep-result-renderer.js';

const at=n=>`2026-10-06T04:00:${String(n).padStart(2,'0')}.000Z`;
const work={id:'W1',title:'현재 화면 확인',status:'assigned',assigned_at:at(0)};
const task={id:'T1',work_id:'W1',title:'페이지 열기',status:'queued',assigned_at:at(1),execution:{kind:'tool',name:'navigate'}};
const snapshot={status:'running',works:[work],tasks:[task],actions:[],managers:[]};

test('before assignment, the actual manager situation remains visible',()=>{
 assert.equal(overallProgress({status:'starting'}),'심층분석 준비 중');
 assert.equal(overallProgress({status:'running',works:[],managers:[{status:'running',situation:'자료 확인 중'}]}),'자료 확인 중');
 assert.equal(overallProgress({status:'running',works:[],managers:[{status:'returned',situation:'판단 반환'}]}),'자료 확인 중');
});

test('assignment and input preparation are distinct from invoked navigation',()=>{
 assert.equal(workProgress(work,snapshot),'확인 작업 준비 중');
 const running={...snapshot,tasks:[{...task,status:'running',started_at:at(2)}],actions:[{action_id:'ACT1',work_id:'W1',task_id:'T1',tool_name:'navigate',status:'preparing'}]};
 assert.equal(workProgress(work,running),'도구 입력 준비 중');
 assert.equal(workProgress(work,{...running,actions:[{...running.actions[0],status:'running',started_at:at(3)}]}),'페이지 여는 중');
});

test('a returned tool or Agent report does not imply an answered work',()=>{
 const tool={...snapshot,tasks:[{...task,status:'success',finished_at:at(5)}],actions:[{action_id:'ACT1',work_id:'W1',task_id:'T1',tool_name:'navigate',status:'success',finished_at:at(5)}]};
 assert.equal(workProgress(work,tool),'페이지 이동 결과 도착');
 assert.equal(workProgress(work,{...tool,tasks:[{...task,status:'returned',finished_at:at(6)}]}),'보고 도착');
 assert.equal(workProgress({...work,status:'answered'},{...tool,status:'completed'}),'업무 답변 완료');
 assert.equal(workProgress(work,{...tool,status:'completed'}),'조사 종료');
});

test('running observation and manager review are both shown without changing the finished task',()=>{
 const value={...snapshot,tasks:[{...task,status:'success',finished_at:at(5)},{...task,id:'T2',status:'running',started_at:at(6),execution:{kind:'agent'}}],
  actions:[{action_id:'ACT2',work_id:'W1',task_id:'T2',tool_name:'get_page_state',status:'running',started_at:at(7)}],
  managers:[{id:'M2',status:'running',review_work_ids:['W1'],query_count:1,started_at:at(8)}]};
 const before=JSON.stringify(value);
 assert.equal(workProgress(work,value),'화면 살펴보는 중 · 총괄이 자료 확인 중');
 assert.equal(workProgress(work,{...value,managers:[{...value.managers[0],query_count:0}]}),'화면 살펴보는 중 · 총괄 검토 중');
 assert.equal(JSON.stringify(value),before);
});

test('parallel tasks are counted within their own work',()=>{
 const value={...snapshot,tasks:[{...task,status:'running'},{...task,id:'T2',status:'running'},{...task,id:'T3',work_id:'W2',status:'running'}]};
 assert.equal(workProgress(work,value),'2개 작업 진행 중');
});

test('the Notion-defined report arriving during review waits after the manager continues',()=>{
 const report={...task,id:'T2',status:'returned',started_at:at(6),finished_at:at(9),result_ref:'report:T2',execution:{kind:'agent'}};
 const manager={id:'M2',status:'running',review_work_ids:['W1'],query_count:0,started_at:at(8)};
 const value={...snapshot,tasks:[{...task,status:'success',finished_at:at(5)},report],managers:[manager]};
 assert.equal(workProgress(work,value),'보고 도착 · 총괄 검토 중');
 const continued={...manager,status:'returned',finished_at:at(10),decision_summary:{finish:false},registration_status:'registered'};
 assert.equal(workProgress(work,{...value,managers:[continued]}),'다음 판단 대기');
 assert.equal(workProgress(work,{...value,managers:[continued,{...manager,id:'M3',started_at:at(11)}]}),'보고 도착 · 총괄 검토 중');
 assert.equal(workProgress(work,{...value,status:'finalizing',managers:[{...continued,decision_summary:{finish:true}}]}),'보고 도착 · 기록 전송 마무리 중');
 assert.equal(workActivity(work,{...value,managers:[continued]}).find(e=>e.id==='T2:finished').label,'페이지 열기 · 실행 Agent 보고 도착');
});

test('activity uses actual timestamps across record kinds and numeric tie ordering',()=>{
 const value={...snapshot,tasks:[{...task,status:'success',started_at:at(2),finished_at:at(8)}],actions:[
  {action_id:'ACT10',task_id:'T1',work_id:'W1',tool_name:'get_page_state',status:'success',started_at:at(4),finished_at:at(6),result_ref:'result:ACT10'},
  {action_id:'ACT2',task_id:'T1',work_id:'W1',tool_name:'navigate',status:'success',started_at:at(3),finished_at:at(6),result_ref:'result:ACT2'}],
  managers:[{id:'M2',review_work_ids:['W1'],status:'returned',started_at:at(7),finished_at:at(9),decision_summary:{finish:false}}]};
 const events=workActivity(work,value);
 assert.deepEqual(events.map(e=>e.id),['W1:assigned','T1:assigned','T1:started','ACT2:started','ACT10:started','ACT2:finished','ACT10:finished','M2:started','T1:finished','M2:finished']);
 assert.equal(events.find(e=>e.id==='ACT10:finished').ref,'result:ACT10');
 assert.equal(new Set(events.map(e=>e.id)).size,events.length);
});

test('transmission finalization remains separate from saved completion',()=>{
 assert.equal(overallProgress({...snapshot,status:'finalizing'}),'기록 전송 마무리 중');
 assert.match(workProgress(work,{...snapshot,status:'finalizing'}),/기록 전송 마무리 중$/);
 assert.equal(overallProgress({...snapshot,status:'completed'}),'전체 완료');
});

test('the existing manager-ended state explains why further work was not performed',()=>{
 const value={...snapshot,tasks:[{...task,status:'ended_by_manager',finished_at:at(4)}]};
 assert.equal(workProgress(work,value),'총괄이 조사를 종료해 더 수행하지 않음');
 assert.match(workActivity(work,value).at(-1).label,/총괄이 조사를 종료해 더 수행하지 않음/);
 assert.doesNotMatch(workActivity(work,value).at(-1).label,/실행 오류|실행 완료/);
});
