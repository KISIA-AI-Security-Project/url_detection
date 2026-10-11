// Product data and asynchronous request ownership are fixed here; design changes use CSS.
export class ApiFailure extends Error {
  constructor(message,status,code) {super(message);this.status=status;this.code=code;}
}
export function parseSse(frame) {
  let type='message';const data=[];
  for(const line of frame.split('\n')) {
    if(line.startsWith('event:')) type=line.slice(6).trim();
    if(line.startsWith('data:')) data.push(line.slice(5).trimStart());
  }
  return data.length?{type,value:JSON.parse(data.join('\n'))}:null;
}
export function validateFast(value,scan,expectedAttempt) {
  if (!value || value.schema_version!=='fast-result-1' || value.job_id!==scan ||
      !Number.isInteger(value.attempt) || !value.details || !Array.isArray(value.details.facts) ||
      !Array.isArray(value.details.sections)) throw new ApiFailure('결과 형식을 확인하지 못했습니다.',502,'unexpected_result');
  expectedAttempt ??= value.attempt;
  if (value.attempt < expectedAttempt) return null;
  if (value.attempt > expectedAttempt) throw new ApiFailure('새 재분석 결과가 있습니다. 분석 기록에서 다시 열어 주세요.',409,'attempt_changed');
  if (!['pending','accepted','not_requested','failed','invalid'].includes(value.judgment_status))
    throw new ApiFailure('결과 상태를 확인하지 못했습니다.',502,'unexpected_result');
  const ids=new Set();
  for (const fact of value.details.facts) {
    if (!fact || typeof fact.fact_id!=='string' || ids.has(fact.fact_id) ||
        typeof fact.text!=='string') throw new ApiFailure('상세 결과를 확인하지 못했습니다.',502,'unexpected_facts');
    ids.add(fact.fact_id);
  }
  if (value.judgment_status==='accepted' &&
      (!value.judgment || !['BENIGN','LIKELY_BENIGN','LIKELY_MALICIOUS','MALICIOUS','UNKNOWN','SUSPICIOUS'].includes(value.judgment.verdict) ||
       typeof value.judgment.summary!=='string' || !Array.isArray(value.judgment.reasons)))
    throw new ApiFailure('판정 결과를 확인하지 못했습니다.',502,'unexpected_judgment');
  return value;
}
export class ServiceClient {
  constructor(base,auth) {this.base=base.replace(/\/$/,'');this.auth=auth;this.sequence=0;this.controller=null;}
  begin() {
    this.controller?.abort();this.controller=new AbortController();
    return {sequence:++this.sequence,signal:this.controller.signal};
  }
  current(task) {return task.sequence===this.sequence && !task.signal.aborted;}
  stop() {this.controller?.abort();this.sequence++;}
  async request(path,{method='GET',body,signal}={}) {
    if (!path.startsWith('/')) throw new Error('invalid_service_path');
    const token=await this.auth.accessToken();
    const response=await fetch(this.base+path,{
      method,headers:{Authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{}),signal,cache:'no-store',credentials:'omit'
    });
    let data;try {data=await response.json();} catch {throw new ApiFailure('서비스 응답을 읽지 못했습니다.',response.status,'invalid_response');}
    if (!response.ok) throw new ApiFailure(data.message||'요청을 처리하지 못했습니다.',response.status,data.error);
    return data;
  }
  async start(url,vt,task,{scanId,previousAttempt}={}) {
    const request_id=crypto.randomUUID().replaceAll('-','');
    const accepted=await this.request('/analyses',{
      method:'POST',body:{url,virustotal:vt,request_id,...(scanId?{scanId}:{})},signal:task.signal});
    if (!/^[0-9a-f]{32}$/.test(accepted.scanId) ||
        accepted.pollUrl!=='/api/analyses/'+accepted.scanId) throw new ApiFailure('접수 결과를 확인하지 못했습니다.',502,'unexpected_acceptance');
    return {...accepted,expectedAttempt:scanId?previousAttempt+1:1};
  }
  wait(milliseconds,signal) {
    return new Promise((resolve,reject)=>{
      if (signal.aborted) return reject(new DOMException('Aborted','AbortError'));
      const done=()=>{signal.removeEventListener('abort',abort);resolve();};
      const timer=setTimeout(done,milliseconds);
      const abort=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);reject(new DOMException('Aborted','AbortError'));};
      signal.addEventListener('abort',abort,{once:true});
    });
  }
  async events(path,task,onEvent,isDone) {
    while (this.current(task)) {
      const token=await this.auth.accessToken();
      let response;
      try {response=await fetch(this.base+path,{headers:{Authorization:'Bearer '+token,Accept:'text/event-stream'},
        signal:task.signal,cache:'no-store',credentials:'omit'});}
      catch(error){if(error.name==='AbortError')throw error;await this.wait(1500,task.signal);continue;}
      if(!response.ok)throw new ApiFailure(response.status===401?'로그인 후 이용해 주세요.':'진행 정보를 불러오지 못했습니다.',response.status,'stream_unavailable');
      if(!response.headers.get('content-type')?.startsWith('text/event-stream') || !response.body)
        throw new ApiFailure('진행 응답을 확인하지 못했습니다.',502,'unexpected_stream');
      const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='',interrupted=false;
      try {while(this.current(task)) {
        const chunk=await reader.read();if(chunk.done)break;
        buffer=(buffer+decoder.decode(chunk.value,{stream:true})).replaceAll('\r\n','\n');
        if(buffer.length>2000000)throw new ApiFailure('진행 응답을 확인하지 못했습니다.',502,'unexpected_stream');
        let at;
        while((at=buffer.indexOf('\n\n'))>=0) {
          const frame=buffer.slice(0,at);buffer=buffer.slice(at+2);const event=parseSse(frame);
          if(!event || !this.current(task))continue;
          if(event.type==='service-error'){interrupted=true;break;}
          onEvent(event.type,event.value);
          if(isDone())return;
        }
        if(interrupted)break;
      }}catch(error){if(error.name==='AbortError'||error instanceof ApiFailure)throw error;}
      finally{await reader.cancel().catch(()=>{});}
      if(isDone())return;await this.wait(1500,task.signal);
    }
  }
  streamFast(scan,attempt,task,onFast) {
    let fastDone=false;
    return this.events('/analyses/'+scan+'/events',task,(type,raw)=>{
      if(type==='fast') {const value=validateFast(raw,scan,attempt);if(value){onFast(value);fastDone=value.judgment_status!=='pending';}}
    },()=>fastDone);
  }
  startVt(scan,task) {return this.request('/analyses/'+scan+'/virustotal',{method:'POST',body:{},signal:task.signal});}
  streamVt(scan,task,onVt) {
    let vtDone=false;
    return this.events('/analyses/'+scan+'/virustotal/events',task,(type,raw)=>{
      if(type==='virustotal') {
        if(raw.schema_version!=='virustotal-url-report-1')throw new ApiFailure('VirusTotal 응답을 확인하지 못했습니다.',502,'unexpected_vt');
        onVt(raw);vtDone=raw.status!=='queued';
      }
    },()=>vtDone);
  }
  deep(identity,task) {
    return this.request('/analyses/'+identity.job_id+'/deep',{method:'POST',body:identity,signal:task.signal});
  }
  streamDeep(run,task,onResult) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(run.run_id) || run.events_url!=='/api/deep/'+run.run_id+'/events')
      throw new ApiFailure('심층분석 접수 결과를 확인하지 못했습니다.',502,'unexpected_deep');
    let done=false;return this.events('/deep/'+run.run_id+'/events',task,(type,value)=>{
      if(type!=='deep')return;
      if(value.run_id!==run.run_id)throw new ApiFailure('심층분석 결과를 확인하지 못했습니다.',502,'unexpected_deep');
      onResult(value);done=['completed','failed'].includes(value.status);
    },()=>done);
  }
}
