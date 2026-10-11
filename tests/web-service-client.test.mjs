import test from 'node:test';
import assert from 'node:assert/strict';
import {ServiceClient,validateFast} from '../frontend/service-client.js';
const result={schema_version:'fast-result-1',job_id:'a'.repeat(32),attempt:1,judgment_status:'accepted',
  details:{facts:[],sections:[]},judgment:{verdict:'UNKNOWN',summary:'현재 정보로 판단하기 어렵습니다.',reasons:[]}};
test('wrong job and stale attempts cannot replace current result',()=>{
  assert.throws(()=>validateFast(result,'b'.repeat(32),1));
  assert.equal(validateFast(result,result.job_id,2),null);
  assert.throws(()=>validateFast({...result,attempt:3},result.job_id,2));
});
test('UNKNOWN with empty reasons remains a received judgment',()=>{
  assert.equal(validateFast(result,result.job_id,1).judgment.verdict,'UNKNOWN');
});
test('five verdicts and stored SUSPICIOUS history retain their exact verdict',()=>{
  for(const verdict of ['BENIGN','LIKELY_BENIGN','LIKELY_MALICIOUS','MALICIOUS','UNKNOWN','SUSPICIOUS']) {
    const value={...result,judgment:{verdict,summary:'저장된 설명.',reasons:verdict==='UNKNOWN'?[]:[{reason_id:'r1',text:'저장된 이유.',related_fact_ids:[]}]}};
    assert.equal(validateFast(value,result.job_id,1).judgment.verdict,verdict);
  }
  assert.throws(()=>validateFast({...result,judgment:{...result.judgment,verdict:'SAFE'}},result.job_id,1));
});
test('new task aborts all old fast, VT and deep polling',()=>{
  const service=new ServiceClient('/api',{}),first=service.begin(),second=service.begin();
  assert.equal(first.signal.aborted,true);assert.equal(service.current(first),false);assert.equal(service.current(second),true);
  service.stop();assert.equal(second.signal.aborted,true);
});
