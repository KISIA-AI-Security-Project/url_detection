"""로컬 실행용 데모 - 테스트 URL들을 L2 Scanner에 통과시켜 결과 JSON을 출력·저장한다."""
import json

from l2_scanner import scan
from l2_scanner.storage import save_record

test_urls = [
    "http://httpbin.org/redirect/3",
    "http://httpbin.org/redirect-to?url=http://93.184.216.34/",
    "https://tinyurl.com/4s4mpsj6",   # 실제 tinyurl.com shortener 링크 (안전한 목적지로 연결되는 공개 링크)
    "http://httpbin.org/response-headers?Refresh=5%3B%20url%3Dhttps%3A%2F%2Fexample.com", # http refresh
    "http://httpbin.org/response-headers?Content-Disposition=attachment%3B%20filename%3D%22report.exe%22", # 강제 다운로드
    "http://httpbin.org/response-headers?Content-Type=image%2Fpng",   # 불일치 재현
    "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",  # SSRF 차단 게이트 확인
    "https://self-signed.badssl.com/",   # 자체 서명 인증서 (L2-C-04, 05 재현용 공개 테스트 사이트)
    "https://expired.badssl.com/",       # 만료 인증서 (L2-C-02 재현)
    "https://wrong.host.badssl.com/",    # 호스트명 불일치 (L2-C-03 재현)
]

if __name__ == "__main__":
    for url in test_urls:
        print("=" * 60)
        print("대상:", url)
        result = scan(url)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        saved = save_record(result)   # Analysis Record 파일 저장 (기본: records/)
        print("저장:", saved)
