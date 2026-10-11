// Server reads stored public results. The browser receives updates through one SSE connection.
export const VT_FIELDS=['schema_version','status','source','url','requested_at','checked_at','report_at','stats','engines','report_url','error','retry_after'];
export function principal(event,clientId,loginClientId) {
  const a=event.requestContext?.authorizer||{},c=a.claims||a.jwt?.claims||{};
  // Issuer/signature and required scope are verified by the API Gateway authorizer.
  const clients=[clientId,loginClientId].filter(Boolean);
  if(typeof c.sub!=='string' || !/^[A-Za-z0-9_-]{1,128}$/.test(c.sub) || c.token_use!=='access' ||
     (clients.length && !clients.includes(c.client_id)))
    throw Object.assign(new Error('로그인 후 이용해 주세요.'),{status:401});
  return {owner:c.sub,expires:Number(c.exp)||0};
}
export function publicVt(row) {
  return row ? Object.fromEntries(VT_FIELDS.filter(k=>k in row).map(k=>[k,row[k]])) :
    {schema_version:'virustotal-url-report-1',source:'VirusTotal',status:'not_requested'};
}
export async function authorizedTarget(event,env) {
  const user=principal(event,env.clientId,env.loginClientId),path=event.path||event.rawPath||'';
  let match=path.match(/^\/api\/analyses\/([0-9a-f]{32})\/events$/),kind='fast';
  if(!match){match=path.match(/^\/api\/analyses\/([0-9a-f]{32})\/virustotal\/events$/);kind='vt';}
  if(!match){match=path.match(/^\/api\/deep\/([A-Za-z0-9_-]{1,128})\/events$/);kind='deep';}
  if(!match) throw Object.assign(new Error('요청한 분석을 찾을 수 없습니다.'),{status:404});
  const id=match[1],row=await env.get(user.owner,kind==='deep'?'RUN':'JOB',id);
  if(!row) throw Object.assign(new Error('이 계정의 분석을 찾을 수 없습니다.'),{status:404});
  return {...user,kind,id,row};
}
export async function pushSnapshots(target,env,emit,{deadline,wait=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
  const previous=new Map();
  const publish=(type,value)=>{const text=JSON.stringify(value);if(previous.get(type)!==text){previous.set(type,text);emit(type,value);}};
  const active=()=>Date.now()<deadline && (!target.expires || Date.now()<target.expires*1000-5000);
  if(target.kind==='deep') {
    while(active()) {
      const value=await env.deep(target.owner,target.id);
      if(value.run_id!==target.id) throw new Error('unexpected_deep_result');
      publish('deep',value);if(['completed','failed'].includes(value.status)) return;
      emit('heartbeat',{at:new Date().toISOString()});await wait(1000);
    }
  } else if(target.kind==='vt') {
    while(active()) {
      const vt=publicVt(await env.get(target.owner,'VT',target.id));publish('virustotal',vt);
      if(vt.status!=='queued')return;
      emit('heartbeat',{at:new Date().toISOString()});await wait(2000);
    }
  } else {
    while(active()) {
        const value=await env.fast(target.id);
        if(value.schema_version!=='fast-result-1'||value.job_id!==target.id) throw new Error('unexpected_fast_result');
        publish('fast',value);if(value.judgment_status!=='pending')return;
        emit('heartbeat',{at:new Date().toISOString()});await wait(500);
    }
  }
  emit('reconnect',{after_ms:1000});
}
