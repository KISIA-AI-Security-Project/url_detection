"""Deploy the approved web boundary from CloudShell; existing Fast resources are read only.

Run from an unpacked kit containing web_service/, frontend/ and deployment/.
State contains public resource IDs, never the VT secret or login credentials.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import mimetypes
import time
import zipfile
from pathlib import Path

REGION = "ap-northeast-2"
ACCOUNT = "998301375101"
BUCKET = "team5-evidence-998301375101-ap-northeast-2-an"
PREFIX = "web/frontend/20261006"
TABLE = "Team5-web-jobs-20261006"
API_FN = "team5-web-api-20261006"
STREAM_FN = "team5-web-stream-20261006"
VT_FN = "team5-web-vt-20261006"
VT_SFN = "team5-web-vt-20261006"
POOL = "team5-web-users-20261006"
SCOPE = "team5-web/analysis"
ROOT = Path(__file__).resolve().parents[1]

def arn(kind, name):
    return f"arn:aws:{kind}:{REGION}:{ACCOUNT}:{name}"

def code_zip():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted((ROOT / "web_service").iterdir()):
            if file.suffix in (".py", ".mjs"):
                archive.writestr(file.relative_to(ROOT).as_posix(), file.read_bytes())
        for name in ("__init__.py", "model_choices.py", "request_options.py"):
            file = ROOT / "evidence_pipeline" / name
            archive.writestr(file.relative_to(ROOT).as_posix(), file.read_bytes())
    return output.getvalue()

def vt_definition():
    worker = arn("lambda", "function:" + VT_FN)
    catch = [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure_detail", "Next": "MarkFailure"}]
    return {"StartAt": "Lookup", "TimeoutSeconds": 86400, "States": {
        "Lookup": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Parameters": {
            "FunctionName": worker, "Payload.$": "$"}, "OutputPath": "$.Payload",
            "Retry": [{"ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"],
                       "IntervalSeconds": 2, "MaxAttempts": 2, "BackoffRate": 2}],
            "Catch": catch, "Next": "Finished"},
        "Finished": {"Type": "Choice", "Choices": [{"Variable": "$.done", "BooleanEquals": True, "Next": "Done"}],
                     "Default": "QuotaWait"},
        "QuotaWait": {"Type": "Wait", "SecondsPath": "$.wait_seconds", "Next": "Lookup"},
        "MarkFailure": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Parameters": {
            "FunctionName": worker, "Payload": {"owner_sub.$": "$.owner_sub", "job_id.$": "$.job_id",
                "request_id.$": "$.request_id", "failure": True}}, "End": True},
        "Done": {"Type": "Succeed"}}}

def openapi(pool_arn, api_arn, stream_arn):
    def operation(fn, stream=False):
        return {"security": [{"Login": [SCOPE]}], "responses": {"200": {"description": "Public result"}},
            "x-amazon-apigateway-integration": {"type": "aws_proxy", "httpMethod": "POST",
                "uri": f"arn:aws:apigateway:{REGION}:lambda:path/" +
                    ("2021-11-15/functions/" + fn + "/response-streaming-invocations" if stream else
                     "2015-03-31/functions/" + fn + "/invocations"),
                "responseTransferMode": "STREAM" if stream else "BUFFERED",
                "timeoutInMillis": 300000 if stream else 29000}}
    routes = {
        "/api/analysis-models": {"get": operation(api_arn)},
        "/api/analyses": {"get": operation(api_arn), "post": operation(api_arn)},
        "/api/analyses/{scanId}": {"get": operation(api_arn)},
        "/api/analyses/{scanId}/virustotal": {"get": operation(api_arn), "post": operation(api_arn)},
        "/api/analyses/{scanId}/deep": {"post": operation(api_arn)},
        "/api/deep/{runId}": {"get": operation(api_arn)},
        "/api/analyses/{scanId}/events": {"get": operation(stream_arn, True)},
        "/api/analyses/{scanId}/virustotal/events": {"get": operation(stream_arn, True)},
        "/api/deep/{runId}/events": {"get": operation(stream_arn, True)}}
    return {"openapi": "3.0.1", "info": {"title": "Team5 authenticated web API", "version": "2026-10-06"},
        "paths": routes, "components": {"securitySchemes": {"Login": {
            "type": "apiKey", "name": "Authorization", "in": "header",
            "x-amazon-apigateway-authtype": "cognito_user_pools",
            "x-amazon-apigateway-authorizer": {"type": "cognito_user_pools", "providerARNs": [pool_arn]}}}}}

class Deployment:
    def __init__(self, path):
        import boto3
        self.path = path
        self.state = json.loads(path.read_text()) if path.exists() else {}
        self.sdk = boto3.Session(region_name=REGION)
        if self.sdk.client("sts").get_caller_identity()["Account"] != ACCOUNT:
            raise RuntimeError("wrong_aws_account")

    def save(self, **values):
        self.state.update(values)
        self.path.write_text(json.dumps(self.state, ensure_ascii=False, indent=2))

    def log(self, phase):
        print("WEB_DEPLOY " + phase, flush=True)

    def roles(self):
        iam = self.sdk.client("iam")
        plan = json.loads((ROOT / "deployment/web-permissions.json").read_text())
        for name, role in plan["roles"].items():
            trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"Service": role["trust"]}, "Action": "sts:AssumeRole"}]}
            try: iam.get_role(RoleName=name)
            except iam.exceptions.NoSuchEntityException:
                iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                    Tags=[{"Key": "Project", "Value": "team5-web-20261006"}])
            iam.put_role_policy(RoleName=name, PolicyName="team5-web-boundary", PolicyDocument=json.dumps(role["policy"]))
        self.log("scoped_roles_ready")

    def storage(self):
        db = self.sdk.client("dynamodb")
        try: db.describe_table(TableName=TABLE)
        except db.exceptions.ResourceNotFoundException:
            db.create_table(TableName=TABLE, BillingMode="PAY_PER_REQUEST",
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}])
        db.get_waiter("table_exists").wait(TableName=TABLE)
        ttl = db.describe_time_to_live(TableName=TABLE)["TimeToLiveDescription"].get("TimeToLiveStatus")
        if ttl == "DISABLED": db.update_time_to_live(TableName=TABLE, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"})
        secret = self.sdk.client("secretsmanager").describe_secret(SecretId="team5/web/virustotal")["ARN"]
        self.save(vt_secret_arn=secret)
        logs = self.sdk.client("logs")
        for name in (API_FN, VT_FN):
            group = "/aws/lambda/" + name
            try: logs.create_log_group(logGroupName=group)
            except logs.exceptions.ResourceAlreadyExistsException: pass
            logs.put_retention_policy(logGroupName=group, retentionInDays=14)
        self.log("ownership_store_and_logs_ready")

    def authentication(self):
        cog = self.sdk.client("cognito-idp")
        if not self.state.get("pool_id"):
            found = next((x for x in cog.list_user_pools(MaxResults=60)["UserPools"] if x["Name"] == POOL), None)
            pool = found or cog.create_user_pool(PoolName=POOL, UsernameAttributes=["email"],
                AutoVerifiedAttributes=["email"], MfaConfiguration="OFF",
                Policies={"PasswordPolicy": {"MinimumLength": 8, "RequireUppercase": False,
                    "RequireLowercase": False, "RequireNumbers": False, "RequireSymbols": True, "TemporaryPasswordValidityDays": 1}},
                AccountRecoverySetting={"RecoveryMechanisms": [{"Priority": 1, "Name": "verified_email"}]},
                UserPoolTags={"Project": "team5-web-20261006"})["UserPool"]
            self.save(pool_id=pool["Id"])
        pool_id = self.state["pool_id"]
        try: cog.create_resource_server(UserPoolId=pool_id, Identifier="team5-web", Name="Team5 web analysis",
                Scopes=[{"ScopeName": "analysis", "ScopeDescription": "Use own URL analysis jobs"}])
        except cog.exceptions.InvalidParameterException:
            cog.describe_resource_server(UserPoolId=pool_id, Identifier="team5-web")
        if not self.state.get("client_id"):
            clients = cog.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]
            client = next((x for x in clients if x["ClientName"] == "team5-web-front-20261006"), None)
            client = client or cog.create_user_pool_client(UserPoolId=pool_id, ClientName="team5-web-front-20261006",
                GenerateSecret=False, SupportedIdentityProviders=["COGNITO"], AllowedOAuthFlows=["code"],
                AllowedOAuthScopes=["openid", "email", SCOPE], AllowedOAuthFlowsUserPoolClient=True,
                CallbackURLs=["https://example.invalid/"], LogoutURLs=["https://example.invalid/"],
                PreventUserExistenceErrors="ENABLED", EnableTokenRevocation=True,
                AccessTokenValidity=60, IdTokenValidity=60, RefreshTokenValidity=1,
                TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"})["UserPoolClient"]
            self.save(client_id=client["ClientId"])
        domain = "team5-web-20261006-" + ACCOUNT
        try: cog.describe_user_pool_domain(Domain=domain)["DomainDescription"]["UserPoolId"]
        except KeyError: cog.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        self.save(auth_domain=f"https://{domain}.auth.{REGION}.amazoncognito.com")
        self.log("cognito_code_pkce_ready")

    def functions(self):
        lam = self.sdk.client("lambda")
        code = code_zip()
        digest = base64.b64encode(hashlib.sha256(code).digest()).decode()
        common = {"WEB_JOBS_TABLE": TABLE, "WEB_CLIENT_ID": self.state["client_id"],
            "FAST_GATE_ARN": self.state.get("fast_gate_arn", arn("lambda", "function:Team5-gate:2")),
            "FAST_RESULT_ARN": self.state.get("fast_result_arn", arn("lambda", "function:Team5-result:4")),
            "DEEP_START_ARN": arn("lambda", "function:team5-l4-start-20261006"),
            "DEEP_QUERY_ARN": arn("lambda", "function:team5-l4-query-20261006"),
            "VT_STATE_MACHINE_ARN": arn("states", "stateMachine:" + VT_SFN)}
        choices = self.state.get("fast_model_choices")
        if choices is not None:
            from evidence_pipeline.model_choices import model_configuration
            configured = model_configuration({"FAST_MODEL_CHOICES_JSON": json.dumps(choices)})
            # A catalog must never be enabled against the old pinned Gate, which
            # predates request-level model selection and would discard the value.
            gate_arn = self.state.get("fast_gate_arn", "")
            if (not gate_arn.startswith(arn("lambda", "function:Team5-gate:")) or
                    gate_arn.rsplit(":", 1)[-1] in {"1", "2", "$LATEST"}):
                raise ValueError("reviewed_model_selection_gate_version_required")
            common["FAST_MODEL_CHOICES_JSON"] = json.dumps(configured, ensure_ascii=False, separators=(",", ":"))
        specs = [(API_FN, "python3.12", "web_service.api.handler", "team5-web-api-role-20261006", common, 30, API_FN),
            (STREAM_FN, "nodejs22.x", "web_service/stream.handler", "team5-web-api-role-20261006", common, 300, API_FN),
            (VT_FN, "python3.12", "web_service.virustotal.handler", "team5-web-vt-role-20261006",
             {"WEB_JOBS_TABLE": TABLE, "VT_SECRET_ARN": self.state["vt_secret_arn"]}, 25, VT_FN)]
        for name, runtime, handler, role, variables, timeout, log in specs:
            config = dict(Runtime=runtime, Role=f"arn:aws:iam::{ACCOUNT}:role/{role}", Handler=handler,
                Timeout=timeout, MemorySize=1024, Environment={"Variables": variables},
                LoggingConfig={"LogFormat": "Text", "LogGroup": "/aws/lambda/" + log})
            try: old = lam.get_function_configuration(FunctionName=name)
            except lam.exceptions.ResourceNotFoundException: old = None
            if old is None:
                for attempt in range(12):
                    try:
                        lam.create_function(FunctionName=name, Code={"ZipFile": code}, **config,
                            Tags={"Project": "team5-web-20261006"}); break
                    except lam.exceptions.InvalidParameterValueException as error:
                        if "assumed" not in str(error) or attempt == 11: raise
                        time.sleep(3)
                lam.get_waiter("function_active_v2").wait(FunctionName=name)
            else:
                if old["CodeSha256"] != digest:
                    lam.update_function_code(FunctionName=name, ZipFile=code)
                    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
                lam.update_function_configuration(FunctionName=name, **config)
                lam.get_waiter("function_updated_v2").wait(FunctionName=name)
            self.log("function_ready " + name)
        self.save(code_sha256=digest)
        states = self.sdk.client("stepfunctions")
        role = f"arn:aws:iam::{ACCOUNT}:role/team5-web-vt-states-role-20261006"
        definition = json.dumps(vt_definition())
        machine = arn("states", "stateMachine:" + VT_SFN)
        try: states.describe_state_machine(stateMachineArn=machine)
        except states.exceptions.StateMachineDoesNotExist:
            states.create_state_machine(name=VT_SFN, definition=definition, roleArn=role, type="STANDARD")
        else: states.update_state_machine(stateMachineArn=machine, definition=definition, roleArn=role)
        self.log("independent_vt_wait_ready")

    def api(self):
        api = self.sdk.client("apigateway")
        document = openapi(arn("cognito-idp", "userpool/" + self.state["pool_id"]),
            arn("lambda", "function:" + API_FN), arn("lambda", "function:" + STREAM_FN))
        body = json.dumps(document).encode()
        if not self.state.get("api_id"):
            found = next((x for x in api.get_rest_apis(limit=500)["items"] if x.get("name") == document["info"]["title"]), None)
            if found: self.save(api_id=found["id"])
            else: self.save(api_id=api.import_rest_api(body=body, failOnWarnings=True,
                parameters={"endpointConfigurationTypes": "REGIONAL"})["id"])
        api_id = self.state["api_id"]
        api.put_rest_api(restApiId=api_id, mode="overwrite", body=body, failOnWarnings=True)
        lam = self.sdk.client("lambda")
        for name in (API_FN, STREAM_FN):
            try: lam.add_permission(FunctionName=name, StatementId="team5-web-api", Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com", SourceArn=arn("execute-api", api_id + "/prod/*/api/*"))
            except lam.exceptions.ResourceConflictException: pass
        api.create_deployment(restApiId=api_id, stageName="prod", description="Authenticated web + SSE")
        self.save(api_host=f"{api_id}.execute-api.{REGION}.amazonaws.com")
        self.log("cognito_scope_api_and_sse_ready")

    def cloudfront(self):
        cf = self.sdk.client("cloudfront")
        if not self.state.get("oac_id"):
            found = next((x for x in cf.list_origin_access_controls()["OriginAccessControlList"].get("Items", [])
                          if x["Name"] == "team5-web-static-20261006"), None)
            oac = found or cf.create_origin_access_control(OriginAccessControlConfig={
                "Name": "team5-web-static-20261006", "SigningProtocol": "sigv4", "SigningBehavior": "always",
                "OriginAccessControlOriginType": "s3"})["OriginAccessControl"]
            self.save(oac_id=oac["Id"])
        caches = cf.list_cache_policies(Type="managed")["CachePolicyList"]["Items"]
        cache = next(x["CachePolicy"]["Id"] for x in caches if x["CachePolicy"]["CachePolicyConfig"]["Name"] == "Managed-CachingDisabled")
        requests = cf.list_origin_request_policies(Type="managed")["OriginRequestPolicyList"]["Items"]
        forward = next(x["OriginRequestPolicy"]["Id"] for x in requests
                       if x["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"] == "Managed-AllViewerExceptHostHeader")
        default = {"TargetOriginId": "static", "ViewerProtocolPolicy": "redirect-to-https", "Compress": True,
            "CachePolicyId": cache, "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "TrustedSigners": {"Enabled": False, "Quantity": 0}, "TrustedKeyGroups": {"Enabled": False, "Quantity": 0}}
        behavior = {**default, "PathPattern": "/api/*", "TargetOriginId": "api", "Compress": False,
            "OriginRequestPolicyId": forward, "AllowedMethods": {"Quantity": 7,
                "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}}
        config = {"CallerReference": "team5-web-20261006", "Comment": "Team5 authenticated web draft",
            "Enabled": True, "DefaultRootObject": "index.html", "PriceClass": "PriceClass_All",
            "Origins": {"Quantity": 2, "Items": [
                {"Id": "static", "DomainName": f"{BUCKET}.s3.{REGION}.amazonaws.com", "OriginPath": "/" + PREFIX,
                 "OriginAccessControlId": self.state["oac_id"], "S3OriginConfig": {"OriginAccessIdentity": ""}},
                {"Id": "api", "DomainName": self.state["api_host"], "OriginPath": "/prod", "CustomOriginConfig": {
                    "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}, "OriginReadTimeout": 60,
                    "OriginKeepaliveTimeout": 5}}]},
            "DefaultCacheBehavior": default, "CacheBehaviors": {"Quantity": 1, "Items": [behavior]},
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True}, "HttpVersion": "http2", "IsIPV6Enabled": True}
        if not self.state.get("distribution_id"):
            found = next((x for x in cf.list_distributions()["DistributionList"].get("Items", [])
                          if x.get("Comment") == config["Comment"]), None)
            dist = found or cf.create_distribution(DistributionConfig=config)["Distribution"]
            self.save(distribution_id=dist["Id"], distribution_domain=dist["DomainName"])
        else:
            old = cf.get_distribution_config(Id=self.state["distribution_id"])
            cf.update_distribution(Id=self.state["distribution_id"], IfMatch=old["ETag"], DistributionConfig=config)
        s3 = self.sdk.client("s3")
        try: policy = json.loads(s3.get_bucket_policy(Bucket=BUCKET)["Policy"])
        except s3.exceptions.ClientError as error:
            if error.response["Error"]["Code"] != "NoSuchBucketPolicy": raise
            policy = {"Version": "2012-10-17", "Statement": []}
        if not self.state.get("bucket_policy_backup"):
            self.save(bucket_policy_backup=policy)
        policy["Statement"] = [x for x in policy["Statement"] if x.get("Sid") != "Team5WebStatic20261006"]
        policy["Statement"].append({"Sid": "Team5WebStatic20261006", "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/{PREFIX}/*", "Condition": {"StringEquals": {
                "AWS:SourceArn": f"arn:aws:cloudfront::{ACCOUNT}:distribution/" + self.state["distribution_id"]}}})
        s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
        redirect = "https://" + self.state["distribution_domain"] + "/"
        self.sdk.client("cognito-idp").update_user_pool_client(UserPoolId=self.state["pool_id"],
            ClientId=self.state["client_id"], SupportedIdentityProviders=["COGNITO"], AllowedOAuthFlows=["code"],
            AllowedOAuthScopes=["openid", "email", SCOPE], AllowedOAuthFlowsUserPoolClient=True,
            CallbackURLs=[redirect], LogoutURLs=[redirect], PreventUserExistenceErrors="ENABLED", EnableTokenRevocation=True,
            AccessTokenValidity=60, IdTokenValidity=60, RefreshTokenValidity=1,
            TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"})
        self.save(service_url=redirect)
        self.log("private_static_origin_and_cloudfront_ready")

    def frontend(self):
        s3 = self.sdk.client("s3")
        files = ["index.html", "theme.css", "app.js", "auth.js", "service-client.js",
                 "fast-result-renderer.js", "virustotal-renderer.js", "deep-result-renderer.js"]
        hashes = {}
        for name in files:
            data = (ROOT / "frontend" / name).read_bytes()
            hashes[name] = hashlib.sha256(data).hexdigest()
            s3.put_object(Bucket=BUCKET, Key=PREFIX + "/" + name, Body=data,
                ContentType=mimetypes.guess_type(name)[0] or "application/octet-stream", CacheControl="no-store")
        config = {"api_base": "/api", "auth": {"domain": self.state["auth_domain"],
            "client_id": self.state["client_id"], "redirect_uri": self.state["service_url"],
            "scope": "openid email " + SCOPE}}
        s3.put_object(Bucket=BUCKET, Key=PREFIX + "/config.json", Body=json.dumps(config).encode(),
            ContentType="application/json", CacheControl="no-store")
        self.save(frontend_sha256=hashes)
        self.log("public_config_and_frontend_uploaded")

    def readback(self):
        lam = self.sdk.client("lambda")
        functions = [{k: v for k, v in lam.get_function_configuration(FunctionName=name).items()
                      if k in ("FunctionName", "Runtime", "Handler", "CodeSha256", "Role", "Timeout", "State", "LastUpdateStatus")}
                     for name in (API_FN, STREAM_FN, VT_FN)]
        cf = self.sdk.client("cloudfront").get_distribution(Id=self.state["distribution_id"])["Distribution"]
        self.save(functions=functions, cloudfront_status=cf["Status"])
        self.log("READBACK " + json.dumps({k: self.state[k] for k in (
            "service_url", "api_id", "pool_id", "client_id", "cloudfront_status", "code_sha256")}, ensure_ascii=False))

    def rollback(self):
        # Reversible disable: do not delete evidence or modify the original API/pipeline.
        if self.state.get("distribution_id"):
            cf = self.sdk.client("cloudfront")
            old = cf.get_distribution_config(Id=self.state["distribution_id"])
            old["DistributionConfig"]["Enabled"] = False
            cf.update_distribution(Id=self.state["distribution_id"], IfMatch=old["ETag"], DistributionConfig=old["DistributionConfig"])
        if self.state.get("api_id"):
            api = self.sdk.client("apigateway")
            api.update_rest_api(restApiId=self.state["api_id"],
                patchOperations=[{"op": "replace", "path": "/disableExecuteApiEndpoint", "value": "true"}])
            result = api.create_deployment(restApiId=self.state["api_id"], stageName="prod",
                description="Rollback: disable only new web endpoint")
            if not api.get_rest_api(restApiId=self.state["api_id"]).get("disableExecuteApiEndpoint"):
                raise RuntimeError("rollback_api_configuration_not_applied")
            self.save(rollback_deployment_id=result["id"])
        self.log("new_front_disable_requested_and_api_disable_redeployed")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("/tmp/team5-web-deployment-20261006.json"))
    parser.add_argument("--phase", choices=["all", "readback", "frontend", "functions", "api", "rollback"], default="all")
    args = parser.parse_args()
    deployment = Deployment(args.state)
    if args.phase == "all":
        for step in (deployment.roles, deployment.storage, deployment.authentication, deployment.functions,
                     deployment.api, deployment.cloudfront, deployment.frontend, deployment.readback): step()
    else: getattr(deployment, args.phase)()

if __name__ == "__main__": main()
