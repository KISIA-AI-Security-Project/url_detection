# Brand data

이 디렉터리는 `L3_SCANNER.brands.main`이 생성하는 버전형 브랜드 정책 캐시와 선택적
브랜드명 입력 파일을 보관한다.

- `wikidata-brands.json`: Cloudflare 후보를 Wikidata `P856`으로 검증한 운영 캐시
- `brands.txt`: 수동 시드 모드를 사용할 때의 선택적 브랜드명 목록

API Token이나 기타 Credential은 이 디렉터리에 저장하지 않는다.
