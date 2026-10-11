"""Names and guidance for the ten retained L0 checks."""
GROUP_A_IP_HOST = "IP_호스트"
GROUP_A_SUSPICIOUS_TLD = "피싱_빈발_TLD_목록_일치"
GROUP_A_FREE_ISSUED_DOMAIN = "무료_발급_도메인"
GROUP_B_WORD_SPLIT = "호스트_단어_분리"
GROUP_B_IDN_CONVERSION = "IDN_문자_변환"
GROUP_C_DOUBLE_EXTENSION = "이중_확장자"
GROUP_C_SHORT_URL = "단축_서비스_목록_일치"
GROUP_D_EXTERNAL_QUERY = "쿼리의_외부_주소"
GROUP_E_HOST_SPOOFING = "접속_호스트_교란"
GROUP_E_SUBDOMAIN_ANOMALY = "서브도메인_구조_이상"

JUDGMENT_HINTS = {
    GROUP_A_IP_HOST: "정상적인 사이트 URL은 도메인 이름을 호스트로 사용한다. 이 URL은 도메인 이름이 아닌 IP 주소를 호스트로 사용한다.",
    GROUP_A_SUSPICIOUS_TLD: "이 TLD는 피싱 도메인 비율을 기준으로 선정한 참조 목록에 포함되어 있다. 다른 관찰 결과와 함께 판단한다.",
    GROUP_A_FREE_ISSUED_DOMAIN: "서비스 이용자가 하위 주소를 만들어 콘텐츠를 제공할 수 있는 도메인이다. 이 하위 주소가 내세우는 주체와 실제 관찰된 내용을 함께 판단한다.",
    GROUP_B_WORD_SPLIT: "분리된 단어가 브랜드·서비스 이름과 다른 단어의 조합을 이루는지, 실제 등록 도메인과 대조해 콤보스쿼팅인지 판단한다.",
    GROUP_B_IDN_CONVERSION: "URL을 열면 비교용 표기가 아니라 실제 접속 호스트로 연결된다. 두 표기를 혼동해 다른 사이트에 접속하게 되는 눈속임인지 판단한다.",
    GROUP_C_DOUBLE_EXTENSION: "앞 확장자와 마지막 확장자의 조합을 확인한다. 앞 확장자로 파일 종류를 오인시키려는 표기인지 판단한다.",
    GROUP_C_SHORT_URL: "호스트가 단축 서비스 참조 목록에 있다. 최종 목적지가 URL에 드러나지 않을 수 있으므로, 실제 이동 결과가 확인되면 그 목적지와 함께 판단한다.",
    GROUP_D_EXTERNAL_QUERY: "쿼리 값에 현재 사이트와 다른 주소가 들어 있다. 사이트가 이 값을 이동 주소로 사용한다면 외부 사이트로 유도할 수 있으므로, 실제 처리 방식과 함께 판단한다.",
    GROUP_E_HOST_SPOOFING: "정상적인 사이트 URL이라면 username이 붙지 않는다.",
    GROUP_E_SUBDOMAIN_ANOMALY: "서브도메인에서 발견한 부분은 실제 접속할 등록 도메인이 아니다. 공격자는 이 구조를 이용해 접속처를 눈속임할 수 있다.",
}

JUDGMENT_GUIDANCE = {
    "DGA_패턴": "도메인 문자열이 DGA 패턴에 해당하는지 다른 관찰과 함께 판단한다.",
    "타이포스쿼팅": "도메인 문자열이 브랜드·서비스 이름의 오타나 유사 표기를 이용한 타이포스쿼팅인지 판단한다.",
}
