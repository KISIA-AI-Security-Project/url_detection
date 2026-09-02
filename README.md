# URL Detection

## L3 Scanner development setup

저장소 루트에서 L3 Scanner를 editable package로 설치한다.

```bash
python -m pip install -e .
```

설치 후 작업 디렉터리와 무관하게 `L3_SCANNER`의 절대 import와 모듈 실행을 사용할 수 있다. CLI는 기본적으로 버전 관리되는 `operational-v1` 정책을 사용한다.

```bash
python -m L3_SCANNER.main https://example.com
```

외부 JavaScript 수집은 명시적으로 활성화한다. `--output`을 주면 지정한 기본
이름으로 Raw와 Signal JSON을 분리해 저장한다. 아래 예시는
`results/l3_raw.json`과 `results/l3_signals.json`을 생성한다.

```bash
python -m L3_SCANNER.main \
  --fetch-external-scripts \
  --output results/l3.json \
  https://example.com
```

기본 정책은 `L3_SCANNER/policies/operational.v1.json`에서 관리한다. 브랜드·공식
도메인은 Wikidata를 단일 외부 공급원으로 사용하며 명시적인 동기화 명령으로 로컬
캐시를 생성한다.

```bash
export CLOUDFLARE_API_TOKEN="..."

python -m L3_SCANNER.brands.main \
  --cloudflare-top-domains 100 \
  --output L3_SCANNER/brands/data/wikidata-brands.json

# 또는 직접 관리하는 브랜드명 목록 사용
python -m L3_SCANNER.brands.main \
  --brand-file /path/to/brands.txt \
  --output L3_SCANNER/brands/data/wikidata-brands.json

python -m L3_SCANNER.main \
  --wikidata-brand-cache L3_SCANNER/brands/data/wikidata-brands.json \
  https://example.com
```

URL Feed CSV 또는 단일 CSV가 든 ZIP은 먼저 네트워크 접속 없이 검사한다.

```bash
python -m L3_SCANNER.dataset_main /path/to/dataset.zip
```

실제 수집은 `--scan`, `--limit`, `--output-dir`을 모두 명시해야 한다. 다음 명령은
활성 HTTP(S) URL 중 최대 10건만 순차 스캔하고 URL별 Raw/Signal JSON과
`manifest.json`을 저장한다.

```bash
python -m L3_SCANNER.dataset_main /path/to/dataset.zip \
  --scan \
  --limit 10 \
  --fetch-external-scripts \
  --output-dir results/dataset-smoke
```
