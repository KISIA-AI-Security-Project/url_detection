import {DynamoDBClient,GetItemCommand} from '@aws-sdk/client-dynamodb';
import {LambdaClient,InvokeCommand} from '@aws-sdk/client-lambda';
import {authorizedTarget,pushSnapshots} from './stream-core.mjs';
const db=new DynamoDBClient({maxAttempts:1}),lambda=new LambdaClient({maxAttempts:1});
function decode(v){if('S'in v)return v.S;if('N'in v)return Number(v.N);if('BOOL'in v)return v.BOOL;if('NULL'in v)return null;
 if('L'in v)return v.L.map(decode);if('M'in v)return Object.fromEntries(Object.entries(v.M).map(([k,v])=>[k,decode(v)]));return null;}
async function invoke(arn,event){const response=await lambda.send(new InvokeCommand({FunctionName:arn,
 InvocationType:'RequestResponse',Payload:Buffer.from(JSON.stringify(event))}));
 if(response.FunctionError)throw new Error('upstream_function_error');
 const result=JSON.parse(Buffer.from(response.Payload).toString('utf8'));
 if(result.statusCode>=400)throw new Error('upstream_unavailable');return JSON.parse(result.body);}
const env={clientId:process.env.WEB_CLIENT_ID,loginClientId:process.env.WEB_LOGIN_CLIENT_ID,
 async get(owner,kind,id){const r=await db.send(new GetItemCommand({TableName:process.env.WEB_JOBS_TABLE,
   Key:{pk:{S:'USER#'+owner},sk:{S:kind+'#'+id}},ConsistentRead:true}));
   return r.Item?Object.fromEntries(Object.entries(r.Item).map(([k,v])=>[k,decode(v)])):null;},
 fast(scan){return invoke(process.env.FAST_RESULT_ARN,{pathParameters:{scanId:scan},requestContext:{http:{method:'GET'}}});},
 deep(owner,runId){return invoke(process.env.DEEP_QUERY_ARN,{pathParameters:{runId},requestContext:{
   authorizer:{jwt:{claims:{sub:owner,token_use:'access'}}},http:{method:'GET'}}});}
};
export const handler=awslambda.streamifyResponse(async(event,responseStream,context)=>{
 let stream=responseStream,target;
 try{target=await authorizedTarget(event,env);}catch(error){
   stream=awslambda.HttpResponseStream.from(responseStream,{statusCode:error.status||503,
    headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
   stream.end(JSON.stringify({error:'stream_unavailable',message:error.status?error.message:'진행 정보를 불러오지 못했습니다.'}));return;
 }
 stream=awslambda.HttpResponseStream.from(responseStream,{statusCode:200,headers:{
  'content-type':'text/event-stream; charset=utf-8','cache-control':'no-store, no-transform','x-content-type-options':'nosniff'}});
 const emit=(type,value)=>stream.write('event: '+type+'\ndata: '+JSON.stringify(value)+'\n\n');
 try{await pushSnapshots(target,env,emit,{deadline:Date.now()+Math.min(240000,context.getRemainingTimeInMillis()-5000)});
 }catch {emit('service-error',{message:'진행 정보를 잠시 불러오지 못했습니다.'});}
 finally{stream.end();}
});
