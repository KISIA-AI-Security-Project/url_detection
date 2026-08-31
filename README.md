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
