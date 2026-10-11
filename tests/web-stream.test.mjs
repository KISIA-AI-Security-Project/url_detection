import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizedTarget,principal,pushSnapshots} from '../web_service/stream-core.mjs';
import {ServiceClient} from '../frontend/service-client.js';
const scan='a'.repeat(32),owner='one-user';
const final={schema_version:'fast-result-1',job_id:scan,attempt:1,judgment_status:'accepted',
 details:{facts:[],sections:[]},judgment:{verdict:'UNKNOWN',summary:'현재 자료로 판단하기 어렵습니다.',reasons:[]}};
const publicClient='11v9bek84i6fakpvhtk5nk4sth',loginClient='71ggi5bjgkgbfpb44ojcjhuebs';
function clientEvent(client=loginClient,changes={},jwt=false) {
 const claims={sub:owner,token_use:'access',client_id:client,exp:2000000000,
  iss:'https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_dlm4zCq7C',scope:'team5-web/analysis',...changes};
 return {path:'/api/analyses/'+scan+'/events',requestContext:{authorizer:jwt?{jwt:{claims}}:{claims}}};
}
test('SSE accepts only configured public/native clients and still checks owner for all stream kinds',async()=>{
 const reads=[],env={clientId:publicClient,loginClientId:loginClient,
  get:async(sub,kind,id)=>{reads.push({sub,kind,id});return sub===owner?{url:'https://example.com/'}:null;}};
 for(const client of [publicClient,loginClient])for(const jwt of [false,true]) {
  for(const [path,kind,id] of [['/api/analyses/'+scan+'/events','fast',scan],
   ['/api/analyses/'+scan+'/virustotal/events','vt',scan],['/api/deep/run-1/events','deep','run-1']]) {
   const result=await authorizedTarget({...clientEvent(client,{},jwt),path},env);
   assert.equal(result.owner,owner);assert.equal(result.id,id);assert.equal(result.kind,kind);
   assert.equal(result.expires,2000000000);
  }
 }
 assert.equal(reads.length,12);
 await assert.rejects(authorizedTarget(clientEvent(loginClient,{sub:'other-user'}),env),{status:404});
});
test('SSE rejects absent/other client, ID token and invalid subject before storage access',async()=>{
 let reads=0;const env={clientId:publicClient,loginClientId:loginClient,get:async()=>{reads++;return {};}};
 const invalid=[...([undefined,null,'','other-client',loginClient+'x',[loginClient]].map(client_id=>({client_id}))),
  {token_use:'id'},{token_use:undefined},{sub:''},{sub:123},{sub:'bad/subject'}];
 for(const changes of invalid)await assert.rejects(authorizedTarget(clientEvent(loginClient,changes),env),{status:401});
 assert.equal(reads,0);
});
test('SSE optional native config preserves legacy single client and unconfigured fixture behavior',()=>{
 assert.equal(principal(clientEvent(publicClient),publicClient).owner,owner);
 assert.throws(()=>principal(clientEvent(),publicClient),{status:401});
 assert.equal(principal(clientEvent(),undefined,loginClient).owner,owner);
 assert.throws(()=>principal(clientEvent(publicClient),undefined,loginClient),{status:401});
 assert.equal(principal(clientEvent(null)).owner,owner);
});
test('SSE verifies access token and user ownership before query',async()=>{
 const env={clientId:'client',get:async(sub)=>sub===owner?{url:'https://example.com/'}:null};
 const event={path:'/api/analyses/'+scan+'/events',requestContext:{authorizer:{claims:{sub:owner,token_use:'access',client_id:'client'}}}};
 assert.equal((await authorizedTarget(event,env)).id,scan);
 await assert.rejects(authorizedTarget({...event,requestContext:{authorizer:{claims:{sub:'other',token_use:'access',client_id:'client'}}}},env),{status:404});
 await assert.rejects(authorizedTarget({...event,requestContext:{authorizer:{claims:{sub:owner,token_use:'id',client_id:'client'}}}},env),{status:401});
});
test('slow optional VT store cannot delay Fast SSE result',async()=>{
 const events=[];
 const pending=pushSnapshots({kind:'fast',id:scan,owner,row:{virustotal_requested:true}},
  {fast:async()=>final,get:()=>new Promise(()=>{})},(type,value)=>events.push({type,value}),{deadline:Date.now()+1000});
 await pending;assert.equal(events[0].type,'fast');assert.deepEqual(events[0].value,final);assert.equal(events.length,1);
});
test('SSE client parses split UTF8 and CRLF, no polling or key URL',async()=>{
 const originalFetch=globalThis.fetch;
 const bytes=new TextEncoder().encode('event: fast\r\ndata: '+JSON.stringify(final)+'\r\n\r\n');let calls=0;
 globalThis.fetch=async(url,options)=>{calls++;assert.equal(url,'/api/analyses/'+scan+'/events');
  assert.equal(options.headers.Authorization,'Bearer in-memory');assert.equal(url.includes('in-memory'),false);
  return new Response(new ReadableStream({start(controller){for(let i=0;i<bytes.length;i+=3)controller.enqueue(bytes.slice(i,i+3));controller.close();}}),
   {headers:{'content-type':'text/event-stream; charset=utf-8'}});};
 try{const service=new ServiceClient('/api',{accessToken:async()=> 'in-memory'}),task=service.begin(),received=[];
  await service.streamFast(scan,1,task,x=>received.push(x),()=>assert.fail('no VT'));
  assert.deepEqual(received,[final]);assert.equal(calls,1);
 }finally{globalThis.fetch=originalFetch;}
});
