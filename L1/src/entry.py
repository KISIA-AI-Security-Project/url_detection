from ada_url import URL

__all__ = ["extract_fqdn", "EmptyHostError"]


# 파싱은 됐는데 호스트 이름이 빈 문자열일 때 입구 처리가 직접 던지는 예외. 
# ada-url이 파싱에 실패할 때 던지는 것도 ValueError라서, 이름을 갈라 두지 않으면 로그에서 두 경우가 구별되지 않는다. 
class EmptyHostError(Exception):
    pass


def extract_fqdn(url_raw: str) -> str:
    # try로 잡지 않는다. 파싱이 실패하면 프로그램이 여기서 죽고 결과 JSON도 안 만들어진다.
    # 그게 설계에서 정한 처리다. 잡아서 계속 돌리면 안 된다.   
    parsed = URL(url_raw)

    # 호스트는 .host가 아니라 .hostname에서 꺼낸다. .host는 기본 포트가 아닌 포트를 뒤에 붙여 주는데
    # (예 "212.164.115.235:53007"), 여기서 필요한 것은 DNS·RDAP·URLhaus에 넣을 이름이라 포트가 없어야
    # 한다. .hostname은 포트 없이 이름만 주고, IPv6 주소는 "[::1]"처럼 대괄호를 포함해 준다.
    hostname: str = parsed.hostname

    # mailto:, javascript:, data:, file:/// 같은 스킴은 파싱에는 성공하면서 호스트 이름이 빈 문자열이다.
    # 빈 이름을 그대로 내보내면 빈 이름으로 조회 일곱 건이 나가 기록 일곱 개가 전부 오류 상태로 채워진다.
    # 이런 URL이 악성일 수는 있으나 인프라를 조회해 알아낼 종류가 아니라 문자열 분석 계층(L0)이 다룰 대상이므로, 여기서 실행을 멈춘다.
    if hostname == "":
        raise EmptyHostError(f"호스트 이름이 빈 문자열: {url_raw}")

    # 이 값이 fqdn이다. handler가 받아 2 도메인 단위 계산 · 3 DNS · 4 URLhaus FQDN 조회에 넘긴다.
    return hostname
