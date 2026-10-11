"""One SDK client per execution environment; no per-job state is retained."""
from threading import Lock
from .performance import span

_S3 = None
_LOCK = Lock()
_BEDROCK = {}
_BEDROCK_LOCK = Lock()


def get_s3_client():
    global _S3
    with span('bootstrap.s3_client', reused=_S3 is not None):
        if _S3 is None:
            with _LOCK:
                if _S3 is None:
                    with span('bootstrap.sdk_import'):
                        import boto3
                    _S3 = boto3.client('s3')
        return _S3


def get_bedrock_client(region=None, timeout=120):
    """Reuse SDK connections; model choice and request state stay in the gateway."""
    key = (region, timeout)
    with span('bootstrap.bedrock_client', reused=key in _BEDROCK):
        if key not in _BEDROCK:
            with _BEDROCK_LOCK:
                if key not in _BEDROCK:
                    with span('bootstrap.sdk_import'):
                        import boto3
                        from botocore.config import Config
                    _BEDROCK[key] = boto3.client('bedrock-runtime', region_name=region,
                        config=Config(connect_timeout=10, read_timeout=timeout,
                                      retries={'total_max_attempts': 1}))
        return _BEDROCK[key]


class LazyS3:
    """Compatibility for inherited fragment.py, without an unused eager client."""
    def __getattr__(self, name):
        return getattr(get_s3_client(), name)
