"""Apply the user-reviewed IAM/Secret change from authenticated CloudShell."""
import argparse
import json
from pathlib import Path
import zipfile

import boto3
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential-zip", type=Path, required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name="ap-northeast-2")
    if session.client("sts").get_caller_identity()["Account"] != "998301375101":
        raise RuntimeError("Unexpected AWS account")
    with zipfile.ZipFile(args.credential_zip) as archive:
        options = json.loads(archive.read("opencode (1).json").decode("utf-8-sig"))["provider"]["monorouter-openai"]["options"]
    if options["baseURL"] != "https://monogpt.kr/api/monorouter/v1/openai/v1" or not options["apiKey"]:
        raise RuntimeError("Unexpected credential configuration")
    value = {"base_url": options["baseURL"], "api_key": options["apiKey"]}
    secrets = session.client("secretsmanager")
    name = "team5/l4/monorouter-20261006"
    try:
        created = secrets.create_secret(Name=name, Description="L4 MonoRouter key supplied by the project owner",
                                        SecretString=json.dumps(value))
        secret_arn = created["ARN"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceExistsException":
            raise
        existing = secrets.get_secret_value(SecretId=name)
        if json.loads(existing["SecretString"]) != value:
            raise RuntimeError("Existing L4 secret differs; no credential was changed") from None
        secret_arn = existing["ARN"]
    policy = Path(__file__).with_name("l4-instance-policy.json").read_text(encoding="utf-8")
    session.client("iam").put_role_policy(RoleName="team5-causality-collector-20260911",
                                          PolicyName="team5-l4-runtime-20261006", PolicyDocument=policy)
    args.credential_zip.unlink()
    print(json.dumps({"account": "998301375101", "region": "ap-northeast-2", "secret_arn": secret_arn,
                      "policy": "team5-l4-runtime-20261006", "uploaded_credential_zip_removed": True}))


if __name__ == "__main__":
    main()
