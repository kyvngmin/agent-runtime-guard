# Agent Runtime Guard v0.1

사내 LLM / RAG / Agent 실행 흐름에서 **위험한 프롬프트·검색결과·툴호출·egress 연쇄를 감지하고 실행 직전에 차단**하는 보안 게이트웨이.

## 30초 퀵스타트

```bash
# 1. 설치
pip install -e ".[dev]"

# 2. API 서버
uvicorn apps.api.main:app --reload

# 3. 콘솔 (새 터미널)
streamlit run apps/console/streamlit_app.py

# 4. 브라우저에서 Replay 시나리오 실행
#    → Prompt to Egress Block 선택 → Run Replay 클릭
```

## 테스트

```bash
pytest tests/ -q
```

## Smoke Test

API 서버가 떠 있는 상태에서:

```bash
python scripts/smoke_runner.py
```

## 핵심 시나리오 4개

| 시나리오 | 기대 결과 |
|---------|----------|
| Normal Session Allow | `allow` — 정상 질의는 통과 |
| Prompt to Egress Block | `deny` — 인젝션 + 민감조회 + 외부전송 차단 |
| RAG Indirect Injection | `deny` — 문서 안 숨은 명령 감지 |
| Tool Abuse Sequence | `deny` — 민감조회 → 위험툴 → egress 연쇄 차단 |

## 아키텍처

```
이벤트 수집 → 정규화 → 상관분석 → 탐지(룰+시퀀스+LLM보안) → 위험점수 → 정책결정 → 자동대응
                                                                          ↓
                                                              피드백 → 튜닝추천 → 재귀개선
```

## 프로젝트 구조

```
schemas/          이벤트·탐지·위험·정책 스키마
assets/           핵심자산(Crown Jewel) 레지스트리
ingestion/        센서 커넥터 (mock)
fabric/           정규화 + 세션 상관분석
detections/       탐지 엔진 (룰 + LLM보안)
risk/             위험점수 엔진
policy/           정책 엔진 + 툴 정책
response/         자동대응 오케스트레이터
feedback/         분석가 피드백 + 튜닝 추천
storage/          SQLite 저장소
apps/api/         FastAPI 서버
apps/console/     Streamlit 콘솔
scripts/          스모크 테스트 러너
tests/            pytest 테스트
```

## 제품 정의

- **제품명**: Agent Runtime Guard
- **한 줄**: 프롬프트 필터가 아니라 실행 전단 정책 + 시퀀스 기반 차단
- **차별화**: 세션 단위 흐름 분석 → cross-vote 위험점수 → 자동 대응 → 재귀개선 루프
- **오픈소스 범위**: 프록시 서버, 스키마, 룰셋, 리스크 엔진, 정책 엔진, 로컬 대시보드, 테스트 세트

## Claude API 프록시

agent-runtime-guard를 Claude API 앞에 프록시로 배치하여, LLM 클라이언트의 tool_use 요청을 실시간 검사합니다.

### 설치 및 실행

```bash
# 의존성 설치 (httpx 필요)
pip install -e ".[dev]"

# 1. Guard API 서버 (포트 8000)
uvicorn apps.api.main:app --port 8000 &

# 2. 프록시 서버 (포트 8080)
uvicorn apps.proxy.main:app --port 8080
```

### 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `ANTHROPIC_API_KEY` | (필수) | Anthropic API 키 |
| `GUARD_API_URL` | `http://localhost:8000` | Guard API 주소 |
| `ANTHROPIC_API_URL` | `https://api.anthropic.com` | Anthropic API 주소 |

### OpenClaw / Claude Code 연결

클라이언트에서 `ANTHROPIC_BASE_URL`만 프록시로 변경하면 됩니다:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-...
```

### 커스텀 헤더

| 헤더 | 설명 |
|------|------|
| `X-Actor-Id` | 요청자 식별 (없으면 `anonymous`) |
| `X-Session-Id` | 세션 식별 (없으면 자동 생성) |

### 동작 흐름

1. `POST /v1/messages` 요청 수신
2. messages에서 `tool_use` 블록 추출
3. tool_use가 있으면 Guard `/decide` API로 SecurityEvent 전송
4. 결과에 따라:
   - **allow** → Anthropic API로 프록시 (스트리밍 지원)
   - **deny** → `403` 반환 `{"error": "blocked_by_guard", "reason": "..."}`
   - **step_up_mfa** → `202` 반환 `{"action": "require_approval", "reason": "..."}`
5. tool_use가 없는 일반 요청은 Guard 호출 없이 바로 프록시

## v0.2 백로그

- 실제 커넥터 1개 이상 연결
- policy threshold 자동 후보 적용
- findings 테이블 분리 (성능 최적화)
- export / report
- 배포 자동화
"# agent-runtime-guard" 
