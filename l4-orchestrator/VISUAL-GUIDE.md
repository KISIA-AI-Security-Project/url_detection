# L4 실행 흐름

현재 코드 기준이다. 호출 인자와 파일별 책임은 [AGENTS_SDK.md](AGENTS_SDK.md), [FILE-MAP.md](FILE-MAP.md)에서 확인한다.

## 조사 진행

~~~mermaid
flowchart TD
    A[호출 프로그램: 앞선 자료·판단·설정] --> B[총괄 Agent / SDK Runner]
    B --> C[업무·작업·다음 판단 시점 등록]
    C --> D[직접 Tool 작업]
    C --> E[실행 Agent 작업]
    E --> F[허용된 Tool 호출]
    D --> G[ACT와 실제 반환 저장]
    F --> G
    E --> H[작업 최종 보고 저장]
    G --> I[Store: 작업 상태·결과]
    H --> I
    I --> J[review_after 성립: 새 결과 선택]
    J --> B
    B --> K[최종 판단]
    K --> L[실행·파일 마감과 AWS 저장 확인]
    L --> M[호출 프로그램에 최종 결과 반환]
~~~

Tool 반환은 `result:ACTn`, 실행 Agent의 작업 보고는 `report:Tn`으로 구분한다. 실행 한도에 도달하면 확보한 자료로 총괄이 마지막 판단을 한다. 총괄 모델 호출 자체가 실패하면 기록과 파일의 전송을 마친 뒤 오류를 호출부에 반환한다.

## 기록과 파일

~~~mermaid
flowchart LR
    T[실제 Tool] --> R[실제 반환]
    T --> F[로컬 PNG·HTML·네트워크 파일]
    R --> S[L4Store 객체]
    F --> C[FileConnections: 완성 파일 등록]
    C --> S
    S --> P[AwsPublisher]
    P --> D[DynamoDB: 진행·참조]
    P --> O[S3: 본문·파일]
    F --> V[실행 Agent의 이미지 입력]
~~~

`FileConnections`는 스크린샷 참조와 해시로 저장된 PNG를 읽어 SDK의 이미지 출력에 넣는다. 별도 재촬영 없이 같은 파일을 전달한다. Store가 AWS 그 자체인 것은 아니며, 실행 중 기록을 소유하는 객체와 외부 전송 코드는 구분된다.

현재 검사는 통제된 모델 응답·메모리 AWS 대역을 사용한다. 위 흐름의 실제 서비스 연결과 실제 모델 판단·AWS 종단 검증은 별도 확인 대상이다.
