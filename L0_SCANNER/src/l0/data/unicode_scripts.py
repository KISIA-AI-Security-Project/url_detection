"""
그룹 B-3(퓨니코드 위장)의 혼합 스크립트 판정에 쓰는 유니코드 스크립트 규칙.

[출처] Unicode Technical Standard #39, Unicode Security Mechanisms.
제한 수준(Restriction Level) 6단계 중 3단계 Highly Restrictive를 채택했다.

[왜 3단계인가]
  2단계(Single Script)  — 한 라벨에 스크립트 하나만 허용.
      일본어는 한자와 가나를 섞어 쓰는 것이 정상 표기라(東京ソニー) 일본어 IDN이
      사실상 전부 오탐된다. 그러면서 3단계보다 추가로 잡는 위장은 0건이다.
  3단계(Highly Restrictive) — 단일 스크립트 + 아래 CJK 세 조합.
  4단계(Moderately Restrictive) — 3단계 + "라틴 + 다른 스크립트 하나"(키릴·그리스 제외).
      아르메니아 문자에도 라틴 동형자가 있어(օ->o, ո->n) gօօgle이 그대로 통과한다.
      제외 목록을 스크립트마다 늘려 가는 방식은 유지할 수 없다.

즉 3단계는 정상 CJK 도메인을 살리면서 위장은 막는 최소 지점이다.
한 단계 낮추면 정상을 잡고, 한 단계 올리면 위장을 놓친다.

[갱신 주기] 유니코드 판본 갱신 시 UTS #39 원문과 대조할 것.
판본은 Python 버전에 묶여 있으므로(3.12 = 15.0.0) 런타임 업그레이드 시에도 확인한다.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 정상적으로 한 라벨에 섞일 수 있는 스크립트 조합.
#
# 검출된 스크립트 집합이 아래 셋 중 하나의 "부분집합"이면 정상으로 본다.
#   {HAN, KATAKANA}  -> 일본어 집합의 부분집합       -> 정상 (東京ソニー)
#   {HAN, HANGUL}    -> 한국어 집합의 부분집합       -> 정상 (대한漢字)
#   {CYRILLIC,LATIN} -> 어느 집합에도 속하지 않음    -> 탐지 (аpple)
#   {HANGUL,HIRAGANA}-> 둘 다 정상 스크립트지만 조합이 없음 -> 탐지
#
# LATIN이 셋 다 들어 있는 이유: 도메인에 영문이 섞이는 것은 흔하다(ソニー-japan).
#
# HAN은 한자다. 중국어의 日과 일본어의 日은 같은 코드포인트(U+65E5)라 유니코드가
# 구분하지 않는다. 따라서 일본어 집합에 HAN이 있는 것은 "중국어가 섞였다"는 뜻이
# 아니라 "일본어가 원래 한자를 쓴다"는 뜻이다.
#
# [알려진 차이] UTS #39 원문의 중국어 조합은 Latin + Han + Bopomofo다.
# 주음부호(注音)를 뺀 만큼 표준보다 엄격해, 주음부호를 쓴 대만 도메인은 탐지된다.
# 실제 사례가 드물어 현재는 넣지 않았다.
# ---------------------------------------------------------------------------
ALLOWED_SCRIPT_SETS: tuple[frozenset[str], ...] = (
    frozenset({"LATIN", "HAN"}),                          # 중국어
    frozenset({"LATIN", "HAN", "HANGUL"}),                # 한국어
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),  # 일본어
)

# ---------------------------------------------------------------------------
# unicodedata.name()의 첫 단어를 스크립트로 쓰는데, 한자만 표기가 다르다.
#
#   'а' -> 'CYRILLIC SMALL LETTER A'    -> CYRILLIC   (스크립트 이름)
#   '한' -> 'HANGUL SYLLABLE HAN'        -> HANGUL     (스크립트 이름)
#   '中' -> 'CJK UNIFIED IDEOGRAPH-4E2D' -> CJK        (블록 이름!)
#
# 한자는 블록 이름이 'CJK Unified Ideographs'인데 스크립트 이름은 'Han'이다.
# ALLOWED_SCRIPT_SETS에 HAN이라고 써 두었으므로 보정하지 않으면 부분집합 검사가
# 실패한다 — {'CJK','KATAKANA'}는 {'LATIN','HAN','HIRAGANA','KATAKANA'}의
# 부분집합이 아니어서 東京ソニー가 오탐된다.
#
# 집합 쪽을 CJK로 쓰지 않는 이유: 유니코드 공식 스크립트 이름이 Han이고 UTS #39
# 문서도 Han으로 쓴다. 또 'CJK COMPATIBILITY IDEOGRAPH-F900' 등 CJK로 시작하는
# 블록이 여럿이라 하나로 접어 두는 편이 안전하다.
# ---------------------------------------------------------------------------
SCRIPT_ALIASES: dict[str, str] = {"CJK": "HAN"}

# ---------------------------------------------------------------------------
# 이름의 첫 단어가 스크립트처럼 보이지만 실제로는 어느 스크립트에도 속하지 않는
# 문자. unicodedata.name()의 첫 단어를 스크립트로 쓰는 방식의 부작용을 메운다.
#
#   KATAKANA-HIRAGANA — 일본어 장음부호 'ー'(U+30FC).
#       공식 이름이 KATAKANA-HIRAGANA PROLONGED SOUND MARK다. 가나 어느 쪽에도
#       속하지 않는 공용 기호인데 첫 단어를 뽑으면 가짜 스크립트가 하나 더 생긴다.
#       빼두지 않으면 ソニー가 {KATAKANA, KATAKANA-HIRAGANA} 2개로 세어져
#       혼합으로 오탐된다. コンピューター처럼 장음이 든 단어는 아주 흔하다.
#
#   IDEOGRAPHIC — 한자 반복 기호 '々'(U+3005)와 마감 기호 '〆'(U+3006).
#       々는 앞 한자를 한 번 더 쓴다는 부호라 유니코드가 Han에 넣지 않았지만
#       isalpha()는 True다. 빼두지 않으면 時々·佐々木이 {CJK, IDEOGRAPHIC}
#       2개로 세어져 오탐된다. 일본 성씨·일반 단어에 흔한 형태다.
#       (IDEOGRAPHIC SPACE/COMMA/FULL STOP은 isalpha()가 False라 앞단에서 걸러진다)
#
#   DIGIT, HYPHEN — 숫자와 하이픈은 어느 언어에도 속하지 않는다.
# ---------------------------------------------------------------------------
NEUTRAL_SCRIPTS: frozenset[str] = frozenset(
    {"DIGIT", "HYPHEN", "KATAKANA-HIRAGANA", "IDEOGRAPHIC"}
)
