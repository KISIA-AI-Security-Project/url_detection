import json
import os
import unittest
from copy import deepcopy
from unittest.mock import patch
from web_service.api import ApiError, WebApi, principal
from web_service.virustotal import Worker, ProviderError, normalize_report
from web_service.ledger import Ledger

OWNER = "00000000-0000-0000-0000-000000000001"
SCAN = "a50914" + "1" * 26
OTHER = "a50914" + "2" * 26
PUBLIC_CLIENT = "11v9bek84i6fakpvhtk5nk4sth"
LOGIN_CLIENT = "71ggi5bjgkgbfpb44ojcjhuebs"


class ClientBoundaryTests(unittest.TestCase):
    @staticmethod
    def event(client=LOGIN_CLIENT, *, jwt=False, **changes):
        claims = {"sub": OWNER, "token_use": "access", "client_id": client,
                  "iss": "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_dlm4zCq7C",
                  "scope": "team5-web/analysis"}
        claims.update(changes)
        auth = {"jwt": {"claims": claims}} if jwt else {"claims": claims}
        return {"httpMethod": "GET", "path": "/api/analysis-models",
                "requestContext": {"authorizer": auth}}

    def test_both_exact_clients_reach_catalog_with_rest_or_jwt_authorizer(self):
        catalog = {"default_model_choice": "fixture", "models": [{"id": "fixture"}]}
        with patch.dict(os.environ, {"WEB_CLIENT_ID": PUBLIC_CLIENT, "WEB_LOGIN_CLIENT_ID": LOGIN_CLIENT}, clear=True):
            for client in (PUBLIC_CLIENT, LOGIN_CLIENT):
                for jwt in (False, True):
                    with self.subTest(client=client, jwt=jwt), patch("web_service.api.public_model_choices", return_value=catalog):
                        event = self.event(client, jwt=jwt)
                        self.assertEqual(principal(event), OWNER)
                        result = WebApi(None, None, None).handle(event)
                        self.assertEqual(result["statusCode"], 200)
                        self.assertEqual(json.loads(result["body"]), catalog)

    def test_bad_client_token_or_subject_rejected_before_catalog(self):
        with patch.dict(os.environ, {"WEB_CLIENT_ID": PUBLIC_CLIENT, "WEB_LOGIN_CLIENT_ID": LOGIN_CLIENT}, clear=True):
            invalid = [{"client_id": value} for value in (None, "", "other-client", LOGIN_CLIENT + "x", [LOGIN_CLIENT])]
            invalid += [{"token_use": "id"}, {"token_use": None}, {"sub": ""}, {"sub": 123}, {"sub": "bad/subject"}]
            for changes in invalid:
                with self.subTest(changes=changes), patch("web_service.api.public_model_choices") as catalog:
                    event = self.event(**changes)
                    with self.assertRaises(ApiError) as caught:
                        WebApi(None, None, None).handle(event)
                    self.assertEqual(caught.exception.status, 401)
                    catalog.assert_not_called()
            event = self.event()
            del event["requestContext"]["authorizer"]["claims"]["client_id"]
            with self.assertRaises(ApiError):
                principal(event)

    def test_native_env_is_optional_without_disabling_existing_client_guard(self):
        with patch.dict(os.environ, {"WEB_CLIENT_ID": PUBLIC_CLIENT}, clear=True):
            self.assertEqual(principal(self.event(PUBLIC_CLIENT)), OWNER)
            with self.assertRaises(ApiError):
                principal(self.event(LOGIN_CLIENT))
        with patch.dict(os.environ, {"WEB_LOGIN_CLIENT_ID": LOGIN_CLIENT}, clear=True):
            self.assertEqual(principal(self.event()), OWNER)
            with self.assertRaises(ApiError):
                principal(self.event(PUBLIC_CLIENT))
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(principal(self.event(None)), OWNER)

class MemoryLedger:
    def __init__(self):
        self.rows = {}
        self.quota = {"allowed": True, "exhausted": False, "wait_seconds": 0}
    def get(self, owner, kind, value):
        return deepcopy(self.rows.get((owner,kind,value)))
    def put_new(self, owner, kind, value, item):
        key=(owner,kind,value)
        if key in self.rows:return False
        self.rows[key]=deepcopy(item);return True
    def replace(self, owner, kind, value, item, *, request_id=None):
        key=(owner,kind,value)
        if request_id and self.rows[key]["request_id"]!=request_id:raise RuntimeError("stale")
        self.rows[key]=deepcopy(item)
    def reserve_vt_quota(self,*args):return self.quota

def fast():
    return {"schema_version":"fast-result-1","job_id":SCAN,"attempt":1,
            "judgment_status":"accepted","context_revision":"c"*64,"result_revision":"d"*64,
            "judgment":{"verdict":"UNKNOWN","summary":"현재 정보로 판단하기 어렵습니다.","reasons":[]},
            "details":{"facts":[],"sections":[]},"deep_analysis":{"available":True}}

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.ledger=MemoryLedger();self.calls=[];self.vt=[];self.deep=[]
        self.result=fast()
        def invoke(role,event):
            self.calls.append((role,deepcopy(event)))
            return (202,{"scanId":SCAN,"pollUrl":"/analyses/"+SCAN,"status":"PENDING","rescan":False}) if role=="gate" else (200,deepcopy(self.result))
        def deep_start(owner,value):
            self.deep.append((owner,value))
            self.ledger.put_new(owner,"RUN","test-run",{"identity":deepcopy(value)})
            return 202,{"run_id":"test-run","status":"queued"}
        self.app=WebApi(self.ledger,invoke,self.vt.append,deep_start=deep_start)
    def submit(self,vt=False,request="1"*32,**kwargs):
        return self.app.submit(OWNER,{"url":"https://example.com/","virustotal":vt,"request_id":request,**kwargs})
    def test_opt_in_removed_from_gate_and_independent_result(self):
        self.submit(True)
        gate_body=json.loads(self.calls[0][1]["body"])
        self.assertEqual(gate_body,{"url":"https://example.com/"})
        before=self.app.fast(SCAN)
        self.app.request_vt(OWNER,SCAN,self.app.owned(OWNER,SCAN))
        item=self.ledger.get(OWNER,"VT",SCAN);item.update(status="failed",error="quota_exhausted")
        self.ledger.replace(OWNER,"VT",SCAN,item)
        self.assertEqual(self.app.fast(SCAN),before)
        self.assertEqual(len(self.vt),1)
        self.assertNotIn("virustotal",before)
    def test_unselected_provider_not_started(self):
        self.submit(False);self.assertEqual(self.vt,[])
        self.assertIsNone(self.ledger.get(OWNER,"VT",SCAN))
    def test_optional_vt_failure_cannot_erase_fast_acceptance(self):
        original_get=self.ledger.get
        def fail_vt_get(owner,kind,value):
            if kind=="VT":raise RuntimeError("optional store unavailable")
            return original_get(owner,kind,value)
        self.ledger.get=fail_vt_get
        status,accepted=self.submit(True)
        self.assertEqual(status,202);self.assertEqual(accepted["scanId"],SCAN)
        self.assertTrue(accepted["virustotal"])
        self.assertEqual(original_get(OWNER,"REQUEST","1"*32)["status"],"accepted")
        self.assertEqual(self.app.fast(SCAN),self.result)
    def test_request_replay_does_not_start_analysis_twice(self):
        first=self.submit(True);second=self.submit(True)
        self.assertEqual(first,second);self.assertEqual(len(self.calls),1);self.assertEqual(len(self.vt),0)
    def test_other_account_cannot_read_or_start_deep(self):
        self.submit()
        with self.assertRaises(ApiError) as caught:self.app.owned("another-user",SCAN)
        self.assertEqual(caught.exception.status,404)
    def test_rescan_changed_target_rejected_before_gate(self):
        self.submit();before=len(self.calls)
        with self.assertRaises(ApiError):
            self.app.submit(OWNER,{"url":"https://other.example/","request_id":"2"*32,"scanId":SCAN})
        self.assertEqual(len(self.calls),before)
    def test_deep_identity_and_vt_not_forwarded(self):
        self.submit(True)
        identity={key:self.result[key] for key in ("job_id","attempt","context_revision","result_revision")}
        _,response=self.app.start_deep(OWNER,SCAN,identity)
        self.assertEqual(self.deep,[(OWNER,identity)])
        self.assertEqual(response["poll_url"],"/api/deep/test-run")
        self.assertIsNotNone(self.ledger.get(OWNER,"RUN","test-run"))
        identity["result_revision"]="f"*64
        with self.assertRaises(ApiError) as caught:self.app.start_deep(OWNER,SCAN,identity)
        self.assertEqual(caught.exception.status,409);self.assertEqual(len(self.deep),1)
    def test_unverified_or_id_tokens_rejected(self):
        for event in ({},{"requestContext":{"authorizer":{"jwt":{"claims":{"sub":OWNER,"token_use":"id"}}}}}):
            with self.assertRaises(ApiError):principal(event)

class VtTests(unittest.TestCase):
    def setUp(self):
        self.ledger=MemoryLedger()
        self.ledger.put_new(OWNER,"JOB",SCAN,{"url":"https://example.com/"})
        self.ledger.put_new(OWNER,"VT",SCAN,{"url":"https://example.com/","status":"queued","request_id":"request"})
        self.event={"owner_sub":OWNER,"job_id":SCAN,"request_id":"request","tries":0}
    def test_quota_wait_has_no_provider_call(self):
        class Provider:
            def lookup(self,url):raise AssertionError("must not query")
        self.ledger.quota={"allowed":False,"exhausted":False,"wait_seconds":16}
        value=Worker(self.ledger,Provider()).run(self.event)
        self.assertFalse(value["done"]);self.assertEqual(value["wait_seconds"],16)
        self.assertEqual(value["tries"],0)
    def test_404_is_report_not_found_and_not_a_verdict(self):
        class Provider:
            def lookup(self,url):raise ProviderError("not_found")
        value=Worker(self.ledger,Provider()).run(self.event)
        self.assertTrue(value["done"])
        item=self.ledger.get(OWNER,"VT",SCAN)
        self.assertEqual(item["status"],"not_found");self.assertNotIn("verdict",item)
    def test_provider_counts_preserved(self):
        report=normalize_report({"data":{"id":"a"*64,"type":"url","attributes":{
            "last_analysis_date":1700000000,"last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":30,"undetected":12},
            "last_analysis_results":{"A":{"engine_name":"A","category":"malicious","result":"malware"}}}}})
        self.assertEqual(report["stats"]["malicious"],2);self.assertEqual(report["stats"]["undetected"],12)
        self.assertIn("/gui/url/",report["report_url"]);self.assertNotIn("verdict",report)
    def test_day_and_month_limits(self):
        class Table:
            row={"pk":"PROVIDER#VIRUSTOTAL","sk":"QUOTA","day":"2026-10-06","month":"2026-10","daily":500,"monthly":501,"version":1}
            def get_item(self,**kwargs):return {"Item":self.row}
            def put_item(self,**kwargs):raise AssertionError("quota exhausted")
        self.assertTrue(Ledger(Table()).reserve_vt_quota(0,"2026-10-06","2026-10")["exhausted"])
        Table.row["daily"]=1;Table.row["monthly"]=15500
        self.assertTrue(Ledger(Table()).reserve_vt_quota(0,"2026-10-06","2026-10")["exhausted"])
    def test_spacing_prevents_fifth_call_in_one_minute(self):
        class Table:
            row=None
            def get_item(self,**kwargs):return {"Item":self.row} if self.row else {}
            def put_item(self,**kwargs):self.row=kwargs["Item"]
        ledger=Ledger(Table())
        for moment in (0,16,32,48):self.assertTrue(ledger.reserve_vt_quota(moment,"day","month")["allowed"])
        self.assertFalse(ledger.reserve_vt_quota(60,"day","month")["allowed"])
        self.assertTrue(ledger.reserve_vt_quota(64,"day","month")["allowed"])

class FrontDeploymentTests(unittest.TestCase):
    def test_uploaded_frontend_includes_all_entry_module_imports(self):
        import re
        from pathlib import Path
        from deployment.deploy_web_service import Deployment, ROOT
        uploaded={}
        class S3:
            def put_object(self,**kwargs):uploaded[Path(kwargs["Key"]).name]=kwargs["Body"]
        class SDK:
            def client(self,name):
                self_name=name
                if self_name!="s3":raise AssertionError("static upload should only use S3")
                return S3()
        deployment=Deployment.__new__(Deployment)
        deployment.sdk=SDK()
        deployment.state={"auth_domain":"https://login.example","client_id":"public-client","service_url":"https://front.example/"}
        deployment.save=lambda **kwargs:deployment.state.update(kwargs)
        deployment.log=lambda message:None
        deployment.frontend()
        pending=["app.js"];seen=set()
        while pending:
            name=pending.pop()
            if name in seen:continue
            seen.add(name)
            raw=(ROOT/"frontend"/name).read_bytes()
            self.assertEqual(uploaded.get(name),raw,name+" was not uploaded with the current content")
            pending.extend(re.findall(r"from\s+['\"]\./([^'\"]+)['\"]",raw.decode()))
        self.assertIn("deep-result-renderer.js",seen)

if __name__=="__main__":unittest.main()
