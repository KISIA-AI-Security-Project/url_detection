"""실험용 파이프라인 CLI. 저장된 운영 Lambda나 상태 머신을 수정하지 않는다."""
from pathlib import Path
import argparse,json,os,sys
ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT),str(ROOT/'L0_SCANNER/src'),str(ROOT/'L1'),str(ROOT/'L2_SCANNER')]
from evidence_pipeline import FastPipeline
from evidence_pipeline.gateway import AnthropicGateway, OpenAICompatibleGateway

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('url');p.add_argument('--output',required=True);p.add_argument('--request-id');p.add_argument('--attempt',default='1')
    p.add_argument('--judge',action='store_true',help='Use configured API; key is read from environment, never a command argument')
    args=p.parse_args();judge=None
    if args.judge:
        names=['JUDGMENT_BASE_URL','JUDGMENT_API_KEY','JUDGMENT_MODEL']
        missing=[name for name in names if not os.environ.get(name)]
        if missing:p.error('Missing environment settings: '+', '.join(missing))
        provider=os.environ.get('JUDGMENT_API_STYLE','anthropic')
        if provider not in {'anthropic','openai'}:p.error('JUDGMENT_API_STYLE must be anthropic or openai')
        gateway=OpenAICompatibleGateway if provider=='openai' else AnthropicGateway
        options={'disable_thinking':os.environ.get('JUDGMENT_DISABLE_THINKING')=='1',
                 'structured_output':os.environ.get('JUDGMENT_STRUCTURED_OUTPUT')=='1'} if provider=='openai' else {}
        try:
            options.update(max_tokens=int(os.environ.get('JUDGMENT_MAX_TOKENS','1600')),
                           timeout=float(os.environ.get('JUDGMENT_TIMEOUT_SECONDS','90')))
            if options['max_tokens']<=0 or not 0<options['timeout']<=3600:raise ValueError()
            if provider=='openai' and os.environ.get('JUDGMENT_MAX_CONTEXT_TOKENS'):
                options['max_context_tokens']=int(os.environ['JUDGMENT_MAX_CONTEXT_TOKENS'])
                if options['max_context_tokens']<=0:raise ValueError()
        except ValueError:p.error('Judgment output budget and timeout must be positive; timeout must not exceed 3600 seconds')
        judge=gateway(*(os.environ[name] for name in names),**options)
    result=FastPipeline(judgment=judge).run(args.url,output_root=args.output,request_id=args.request_id,attempt=args.attempt)
    print(json.dumps({'request_id':result['request_id'],'attempt':result['attempt'],'context_status':result['context_status'],'judgment_status':result['judgment_status'],
                      'judgment':result.get('judgment'),'output_directory':str(Path(args.output).resolve()/result['request_id']/result['attempt'])},ensure_ascii=False,indent=2))
    return 0 if result['context_status']=='completed' and result['judgment_status'] in {'completed','not_requested'} else 1

if __name__=='__main__':raise SystemExit(main())
