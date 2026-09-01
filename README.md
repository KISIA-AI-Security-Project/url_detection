# URL Detection

## L3 Scanner development setup

저장소 루트에서 L3 Scanner를 editable package로 설치한다.

```bash
python -m pip install -e .
```

설치 후 작업 디렉터리와 무관하게 `L3_SCANNER`의 절대 import와 모듈 실행을 사용할 수 있다.

```bash
python -m L3_SCANNER.main https://example.com
```

AWS smoke test에서 임시 탐지 정책과 제한된 외부 JavaScript 수집을
모두 활성화하려면 `--all`을 사용한다. 결과는 기본적으로 표준
출력에 쓰며, `--output`을 주면 지정한 기본 이름으로 Raw와 Signal JSON을
분리해 저장한다. 아래 예시는 `results/pettrip_raw.json`과
`results/pettrip_signals.json`을 생성한다.

```bash
python -m L3_SCANNER.main \
  --all \
  --output results/pettrip.json \
  https://api.chapchu.site/docs/index.html
```

`--all`이 사용하는 `aws-smoke-v1` 정책은 Parser·Analyzer 경로 테스트용
임시값이며 운영 악성/정상 판정 정책이 아니다. 임시값은
`L3_SCANNER/policies/experimental.py`에서 관리한다.
