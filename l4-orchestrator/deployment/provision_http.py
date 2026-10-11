"""Apply the exact reviewed private start/query adapters after approval."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import time
import zipfile

import boto3
from botocore.exceptions import ClientError


REGION = "ap-northeast-2"
ACCOUNT = "998301375101"
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--lambda-archive", type=Path, required=True)
    parser.add_argument("--lambda-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    runtime, code = args.runtime_archive.read_bytes(), args.lambda_archive.read_bytes()
    if sha256(runtime).hexdigest() != args.runtime_sha256 or sha256(code).hexdigest() != args.lambda_sha256:
        raise ValueError("Archive differs from the reviewed candidate")
    with zipfile.ZipFile(args.runtime_archive) as archive:
        policies = {kind: json.loads(archive.read("deployment/" + kind + "-role-policy.json")) for kind in ("start", "query")}
        document = json.loads(archive.read("deployment/l4-run-document.json"))
    plan = {"account": ACCOUNT, "region": REGION, "functions": ["team5-l4-start-20261006", "team5-l4-query-20261006"],
            "document": "Team5-L4Run-20261006", "policies": policies,
            "public_urls": False, "new_secret_access": False, "ec2_role_change": False}
    if not args.apply:
        print(json.dumps(plan, indent=2))
        return
    session = boto3.Session(region_name=REGION)
    if session.client("sts").get_caller_identity()["Account"] != ACCOUNT:
        raise RuntimeError("Unexpected AWS account")
    iam, functions, ssm, logs = (session.client(name) for name in ("iam", "lambda", "ssm", "logs"))
    name = plan["document"]
    try:
        current = ssm.get_document(Name=name, DocumentFormat="JSON")
        if json.loads(current["Content"]) != document:
            raise RuntimeError("An existing SSM document has different content")
    except ssm.exceptions.InvalidDocument:
        ssm.create_document(Name=name, Content=json.dumps(document), DocumentType="Command", DocumentFormat="JSON",
            Tags=[{"Key": "Project", "Value": "Team5-L4"}])
    receipts = []
    for kind in ("start", "query"):
        name = "team5-l4-" + kind + "-20261006"
        role_arn = "arn:aws:iam::" + ACCOUNT + ":role/" + name
        try:
            role = iam.get_role(RoleName=name)["Role"]
            if role["AssumeRolePolicyDocument"] != TRUST:
                raise RuntimeError("An existing role has different recipients")
        except iam.exceptions.NoSuchEntityException:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(TRUST),
                             Tags=[{"Key": "Project", "Value": "Team5-L4"}])
        iam.put_role_policy(RoleName=name, PolicyName="L4-" + kind, PolicyDocument=json.dumps(policies[kind]))
        if iam.get_role_policy(RoleName=name, PolicyName="L4-" + kind)["PolicyDocument"] != policies[kind]:
            raise RuntimeError("Applied role policy differs from the reviewed candidate")
        try:
            logs.create_log_group(logGroupName="/aws/lambda/" + name)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        environment = {"L4_BUCKET": "team5-evidence-998301375101-ap-northeast-2-an",
                       "WEB_JOBS_TABLE": "Team5-web-jobs-20261006", "L4_TABLE": "Team5-l4DB"}
        if kind == "start":
            environment.update(L4_INSTANCE="i-0e6b3623d0a2055e7", L4_SSM_DOCUMENT=plan["document"])
        configuration = {"Role": role_arn, "Runtime": "python3.12", "Handler": "l4_orchestrator.aws_" + kind + ".handler",
                         "Timeout": 60, "MemorySize": 512, "Environment": {"Variables": environment}}
        try:
            current = functions.get_function(FunctionName=name)["Configuration"]
        except functions.exceptions.ResourceNotFoundException:
            current = None
        if current:
            if current["Role"] != role_arn:
                raise RuntimeError("An existing function belongs to a different role")
            functions.update_function_code(FunctionName=name, ZipFile=code, Publish=False)
            functions.get_waiter("function_updated_v2").wait(FunctionName=name)
            functions.update_function_configuration(FunctionName=name, **configuration)
        else:
            for attempt in range(5):
                try:
                    functions.create_function(FunctionName=name, Code={"ZipFile": code}, **configuration,
                        Architectures=["x86_64"], Tags={"Project": "Team5-L4"})
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "InvalidParameterValueException" or "cannot be assumed" not in str(exc) or attempt == 4:
                        raise
                    time.sleep(3)
        functions.get_waiter("function_active_v2").wait(FunctionName=name)
        functions.get_waiter("function_updated_v2").wait(FunctionName=name)
        version = functions.publish_version(FunctionName=name)
        receipts.append({"function": name, "arn": version["FunctionArn"], "version": version["Version"],
                         "code_sha256": version["CodeSha256"], "role_arn": role_arn})
    print("L4_HTTP_APPLIED " + json.dumps({"runtime_sha256": args.runtime_sha256,
        "lambda_sha256": args.lambda_sha256, "functions": receipts, "document": plan["document"]}))


if __name__ == "__main__":
    main()
