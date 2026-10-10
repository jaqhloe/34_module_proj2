# 보고서 엔진 (report_engine)

법적 영향 분석 모듈(module3)이 만든 진단 JSON 하나를 받아, **경영진용 슬라이드 PDF**와 **실무진용 상세 보고서 PDF**를 만든다.
판정과 숫자는 코드가 정하고, 생성형 AI(GPT-4o)는 문장만 쓴다. AI는 진단 한 건당 딱 한 번 호출한다.
과징금·법정 상한 같은 원화 금액은 AI에 아예 넘기지 않고, 템플릿이 원본 데이터에서 직접 채운다.

> 원칙: **판정은 코드, 문장은 AI, 숫자·조문·조치 방법은 원본 데이터.**

---

## 입력과 출력

**입력**: module3 출력 JSON 그대로 (`schema_version`, `scan_id`, `target_system`, `references[]`, `findings[]`)
각 finding에는 `status`(취약/양호/수동확인), `severity`(상/중/하), `asset`, `evidence`, `isms_p[]`, `violated_laws[]`가 붙어 있다.

여기에 보고서 담당이 관리하는 데이터 3개를 함께 읽는다.

| 파일 | 내용 |
|---|---|
| `data/context.json` | 조직명, 회원 수, 처리 개인정보 항목, 표지 안내 문구. `exposure_profile`에 매출·인증 여부 등 과징금 계산용 가정값 |
| `data/cases.json` | 개인정보위 처분 사례 카드 30장 (`cases.xlsx`에서 자동 생성) |
| `data/item_catalog.json` | 점검 항목별 판단 기준·조치 방법 (KISA 2026 상세가이드 웹 21개 항목 원문) |

**출력**: 진단마다 `out/<scan_id>/` 폴더에 생긴다 (`--out`으로 변경 가능).

| 파일 | 내용 |
|---|---|
| `exec_report.pdf` / `.html` | 경영진용 16:9 슬라이드 7장 |
| `tech_report.pdf` / `.html` | 실무진용 A4 상세 보고서 (진단 개요 → 결과 요약 → 취약점 상세 → 부록) |
| `exposure_result.json` | 과징금 노출액 계산 결과 |
| `run_log.json` | LLM 출력 검증 경고 |
| `llm_output.json` | 실제 LLM을 호출했을 때만 저장 (다시 렌더링할 때 재사용) |

**근거 자료**

| 자료 | 버전·규모 |
|---|---|
| 개인정보보호위원회 처분 보도자료 | PDF 15건 (2023~2026) → 사례 카드 30장 |
| KISA 웹 취약점 점검 상세가이드 | 2026, 웹 21개 항목의 판단 기준·조치 방법 |
| 개인정보 보호법 과징금 기준 | 2026-09-11 시행 개정법 제64조의2 (상한 3%, 특례 10%, 감경 40%·30%) |

---

## 실행

```bash
cd vuln_assessment/report_engine
source .venv/bin/activate                              # Homebrew Python 3.12로 만든 venv
export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib    # WeasyPrint가 Pango를 찾게

# 사례 시트를 고쳤을 때만
python convert_cases.py      # data/cases.xlsx → data/cases.json (검사 포함)
python case_kb.py load       # data/cases.json → data/chroma_db (매번 새로 만듦)

# 보고서 만들기
python engine.py --scan data/scans/SCAN-2026-002.json                        # 실제 LLM 1회 호출
python engine.py --scan data/scans/SCAN-2026-002.json \
                 --llm-output out/SCAN-2026-002/llm_output.json              # 저장된 문장 재사용 (템플릿만 고칠 때)
```

API 키는 팀 공용 `vuln_assessment/.env`의 `OPENAI_API_KEY`를 먼저 읽고, 없으면 `report_engine/.env`를 읽는다.

---

## 기술 스택

| 구분 | 사용 기술 | 역할 |
|---|---|---|
| 문장 생성 | OpenAI GPT-4o (temperature 0.2, JSON 모드) | 보고서 문장 작성, 진단당 1회 |
| 사례 검색 | text-embedding-3-small + ChromaDB | 유사 처분 사례 검색 (코사인 유사도 + 메타데이터 필터) |
| 템플릿 | Python 3.12 + Jinja2 | 같은 데이터로 경영진용·실무진용 HTML 조립 |
| PDF | WeasyPrint (+ Pango) | HTML·CSS → PDF, Pretendard 폰트 임베드 |
| 데이터 변환 | openpyxl | 사례 시트 → JSON, 입력값 검사 |
| 금액 계산 | Python (규칙 기반) | 과징금 노출액, 조치 우선순위 |

LLM은 `.env`의 `LLM_PROVIDER`·`LLM_MODEL`로 Claude(Anthropic)로 바꿀 수 있다. 호출 코드는 `engine.py`의 `call_llm()` 하나뿐이다.

---

## 처리 흐름

```
module3 진단 JSON + context.json + cases.json + item_catalog.json
   │
   ├─ ① load      코드    표기 차이 맞추기, 카탈로그에 없는 항목 ID 연결
   ├─ ② facts     코드    통계, 위험 수준 판정, 사례 검색(case_kb), 노출액 계산(exposure)
   ├─ ③ llm       1회     판정이 끝난 사실만 넘겨 문장만 생성 → llm_output.json
   ├─ ④ validate  코드    LLM이 지어낸 ID 제거, 빠진 항목 보완 → run_log.json
   └─ ⑤ render    코드    같은 데이터 → exec.html.j2 / tech.html.j2 → PDF 2종
```

### ① 입력 맞추기

module3 출력의 표기 차이를 엔진에서 흡수한다. `evidence`가 문자열이든 객체든 null이든 읽고, 항(`제3항`)이 지정된 조문은 그 항만 잘라 보여주며, `<개정 …>` 같은 이력 꼬리표는 표시에서만 뗀다. 원문 전체는 `text_full`에 보존한다.

카탈로그에 없는 항목 ID가 와도 멈추지 않는다. **이름 일치 → ID 앞부분 일치** 순으로 KISA 항목에 연결하고, 둘 다 실패하면 판단 기준·조치 방법 칸만 비워 둔다.
예: `W-03 '불충분한 권한 검증'` → `IN`(이름), `IL-COMMENT-01` → `IL`(ID 앞부분)

```python
# engine.py — resolve_catalog()
for f in scan.get("findings", []):
    iid = f.get("item_id")
    if iid not in catalog:
        hit, how = by_title.get(key(f.get("title"))), "이름 일치"
        if not hit:
            prefix = (iid or "").split("-")[0]
            if isinstance(catalog.get(prefix), dict):
                hit, how = prefix, "ID 앞부분 일치"
        if hit:
            catalog[iid] = catalog[hit]
            notes.append(f"{iid} '{f.get('title')}' → 카탈로그 {hit} 항목 사용 ({how})")
        else:
            notes.append(f"{iid} '{f.get('title')}' → 카탈로그에 없음 (실무진용 판단 기준·조치 방법 칸이 비어 나옴)")
```

### ② 판정은 코드가 한다

전체 위험 수준은 규칙으로 정한다. 개인정보를 처리하는 자산에 '상' 취약점이 있으면 **심각**이다.

```python
# engine.py — compute_risk_level()
high = [f for f in vulns if f["severity"] == "상"]
if any(f["asset"].get("handles_personal_data") for f in high):
    return "심각", "개인정보를 처리하는 자산에 '상' 위험 취약점이 있음"
if high:
    return "높음", "'상' 위험 취약점이 있음"
if any(f["severity"] == "중" for f in vulns):
    return "보통", "'중' 위험 취약점이 있음"
return "낮음", "'하' 위험 취약점만 있거나 취약점 없음"
```

### ③ LLM은 문장만 쓴다

LLM에는 판정이 끝난 사실만 골라서 넘긴다. **원화 금액(매출, 사례 과징금, 노출액)은 입력에서 아예 뺀다.** 금액을 보여주면 LLM이 다른 회사 과징금을 이 고객사의 위험처럼 쓰거나 숫자를 옮겨 적다 틀리기 때문이다.

```python
# engine.py — facts_for_llm()
def facts_for_llm(facts):
    """LLM에 넘길 최소한의 사실만 추린다. 판례 금액은 일부러 빼서 LLM이 숫자를 옮겨 적다 틀릴 일을 없앤다."""
    # 로고 경로, 안내 문구, 메모는 문장 생성에 필요 없으니 빼고 넘긴다
    ctx = {k: v for k, v in facts["context"].items()
           if k not in ("logo", "disclaimer", "exposure_profile") and not k.startswith("_")}  # 매출 등 금액은 LLM에 안 넘김
```

프롬프트 설계

- **역할 분리**: 시스템 프롬프트 규칙 16개. "facts에 없는 취약점·법령·사례·금액을 만들지 않는다", "ID로만 참조한다", "reviewed가 false인 법령은 '위반 소지'로 쓴다" 등
- **대조 예시(Few-shot)**: 나쁜 문장과 좋은 문장을 함께 보여 준다 (예: "보안 강화가 시급합니다" ✗ / "주문번호만 알면 남의 배송지를 볼 수 있음" ○)
- **JSON 출력 고정**: `headline`, `summary`, `top_risks`, `roadmap`, `decisions`, `finding_notes` 스키마 + JSON 모드
- **후보 주입(RAG)**: 벡터 검색으로 찾은 사례 후보만 넣고, 그 안에서만 인용하게 한다

### ④ LLM 출력 검증

LLM이 쓴 ID는 그대로 쓰지 않는다. `validate()`가 원본 데이터에 있는 ID만 남기고 나머지는 경고와 함께 버린다.

```python
# engine.py — validate()
def keep(ids, valid, what, where):
    good = [i for i in ids or [] if i in valid]
    for bad in set(ids or []) - set(good):
        warnings.append(f"{where}: 존재하지 않는 {what} '{bad}' 제거")
    return good

for i, r in enumerate(llm.get("top_risks", [])[:3]):
    where = f"top_risks[{i}]"
    r["finding_ids"] = keep(r.get("finding_ids"), vuln_ids, "finding_id", where)
    if not r["finding_ids"]:
        warnings.append(f"{where}: 유효한 취약점이 없어 위험 항목 제거")
        continue
    r["law_codes"] = keep(r.get("law_codes"), facts["laws"], "law_code", where)
```

검사 항목

- 없는 취약점·법령·사례 ID 제거, 유효한 취약점이 없는 위험은 통째로 삭제
- 사례는 그 위험에 묶인 취약점의 검색 후보이면서 '참고 사례'보다 높은 등급일 때만 인정. 하나도 없으면 최상위 후보를 코드가 연결
- 로드맵에서 빠진 취약점은 위험도 기준(상→즉시, 중→단기, 하→중기)으로 코드가 추가
- 문장에 원화 금액이 섞이면 경고 (**자동 삭제는 하지 않으므로 사람이 확인**)

### ⑤ 렌더링

`enrich()`가 LLM이 고른 법령 코드·사례 ID에 원본 데이터(조문 원문, 사례 정보)를 다시 붙이고, 금액은 템플릿이 계산 결과에서 직접 꺼낸다. `krw` 필터는 표기만 바꾼다 (150000000 → `1억 5,000만 원`).

```html
<!-- templates/exec.html.j2 -->
<span class="m-num must">{{ cap.cap_krw|krw }}</span>
```

---

## 유사 사례 검색 — 4단계 등급

유사도만 쓰면 문장은 비슷하지만 결함 종류가 다른 사례가 섞인다. 그래서 Chroma의 메타데이터 필터로 등급을 나누고, 위 등급부터 채운 뒤 모자랄 때만 다음 등급으로 내려간다.

| 등급 | 조건 | 보고서 인용 |
|---|---|---|
| 동일 결함 사례 | ISMS-P 기준 **AND** 팀 취약점 일치 | ○ |
| 같은 취약점 유형 | 팀 취약점 일치 | ○ |
| 관련 통제 사례 | ISMS-P 기준만 일치 | ○ |
| 참고 사례 | 필터 없이 유사도만 | ✗ (인용·과징금 분포 모두 제외) |

Chroma 메타데이터에는 목록을 넣기 어려워서, 적재할 때 태그를 `isms_2_5_3: True` 같은 플래그로 펼친다.

```python
# case_kb.py — search_cases()
isms_f = _flag_filter([f"isms_{slug(i)}" for i in isms_ids])
vuln_f = {f"vuln_{VULN_SLUG[team_vuln]}": True} if team_vuln in VULN_SLUG else None

# 위에서부터 채우고, 모자라면 다음 등급으로 내려간다
tiers = []
if isms_f and vuln_f:
    tiers.append(("동일 결함 사례", {"$and": [isms_f, vuln_f]}))   # ISMS-P 기준 + 팀 취약점 둘 다 일치
if vuln_f:
    tiers.append(("같은 취약점 유형", vuln_f))                      # 팀 취약점만 일치 (같은 결함 종류)
if isms_f:
    tiers.append(("관련 통제 사례", isms_f))                        # ISMS-P 기준만 일치 (같은 통제 영역)
tiers.append(("참고 사례", None))                                   # 필터 없이 유사도만
```

같은 보도자료(`source_file`)에서는 한 건만 고른다. 거의 같은 문장의 쌍둥이 카드가 결과를 독차지하지 않게 하기 위해서다.

**사례 데이터 구축**: 보도자료 PDF 15건 → 엑셀 시트에 사례 카드 30장 정리 (유형·팀 취약점·공격 태그·ISMS-P는 드롭다운으로만 입력) → `convert_cases.py`가 필수값·날짜·ID 형식·중복·원본 PDF 존재 여부를 검사하고, 오류가 하나라도 있으면 JSON을 만들지 않는다 → 카드 1장을 문서 1개로 임베딩 (청크 분할 없음) → 적재할 때마다 지식베이스를 새로 만든다.

---

## 과징금 노출과 우선순위 (`exposure.py`)

금액은 전부 코드가 계산한다.

- **법정 상한**: 위반과 무관한 매출을 뺀 매출의 3% (매출 산정 곤란 시 20억 원)
- **10% 특례 시나리오**: 반복 위반 / 1천만 명 이상 피해 / 시정명령 불이행 유출 중 하나에 해당할 때만. 해당하지 않으면 보고서에 회색으로 "현재 요건 해당 없음"으로 표시
- **감경**: 투자 감경 최대 40%, ISMS-P 인증 감경 최대 30%
- **유사 사례 과징금 분포**: 참고 사례를 뺀 등급의 처분 사례만 집계
- **제외 규칙**: 양호 항목, 관련 법 조항이 없는 항목(ISMS-P 심사 리스크로만 다룸), 개인정보를 처리하지 않는 자산, 시행 전 조문, 공공기관 의무 조항(민간 대상일 때)

사례 중앙값이 고객사 법정 상한보다 크면 경고를 만든다. 이 경고는 경영진용 각주와 실무진용 부록 4.3에 자동으로 실린다.

```python
# exposure.py — compute()
if dist:
    dist["over_client_cap_count"] = sum(1 for c in dist["case_ids"]
                                        if evidence_fine(evidence, c) > cap["cap_krw"])
    dist["median_exceeds_client_cap"] = dist["median_krw"] > cap["cap_krw"]
    if dist["median_exceeds_client_cap"]:
        dist["warning"] = ("유사 사례 중앙값이 이 고객사의 법정 상한보다 큼. 사례 기업이 더 커서 생긴 차이이므로 "
                           "사례 금액을 고객사 예상 과징금처럼 쓰면 안 됨 (상한을 넘는 과징금은 불가능)")
```

**조치 우선순위 점수** = 심각도(상3·중2·하1) × 개인정보 자산(예 1.0·아니오 0.3) × (1 + 0.5 × 사례 근거)
사례 근거: 동일 결함 1.0 · 같은 유형 0.7 · 관련 통제 0.5 · 참고 0.3 · 없음 0.2

```python
# exposure.py — priority()
# 심각도가 먼저, 사례 근거는 최대 1.5배까지만 올린다 → '상'은 근거가 약해도 '중'보다 뒤로 가지 않는다
score = SEV_W.get(f.get("severity"), 1) * PII_W[pii] * (1 + 0.5 * EVIDENCE_W[best])
```

예: SCAN-2026-003 — 주석 내 정보 누출(상, 동일 결함) 3 × 1.0 × 1.5 = **4.5**, 에러페이지 정보 노출(중, 동일 결함) 2 × 1.0 × 1.5 = **3.0**

---

## '검토 전' 표시

module3는 모든 법령·ISMS-P 매핑을 `reviewed: false`로 넘긴다. 보고서 엔진은 이를 세 곳에서 반영한다.

- 템플릿: 검토하지 않은 매핑에 **검토 전** 배지 표시
- LLM 규칙 3번: reviewed가 false인 법령은 단정하지 말고 "위반 소지"로 쓴다
- 검토 전 매핑 건수를 실무진용 1.3절과 경영진용 결정 사항 장표에 명시

```html
<!-- templates/tech.html.j2 -->
{% if l.reviewed %}<span class="review yes">검토 완료</span>{% else %}<span class="review no">검토 전</span>{% endif %}
```

---

## 결과물

**경영진용 (16:9, 7장)**: 표지 / 진단 결론 / 핵심 위험 / 법적 근거와 유사 사례 / 과징금 노출과 감경 여지 / 조치 로드맵(즉시·단기·중기) / 경영진 결정이 필요한 사항

**실무진용 (A4)**: 1. 진단 개요 / 2. 진단 결과 요약 / 3. 취약점 상세(현황·판단 기준·조치 방법·관련 법령 원문·매핑 근거) / 4. 부록(기준 문서 원본, 생성 방식, 과징금 산정, 조치 우선순위, 가정과 제외 항목)

---

## 검증 결과 (2026-10-06 실측)

**LLM 단독 vs 보고서 엔진 비교 실험**: GPT-4o, temperature 0.2, 같은 출력 형식으로 진단 3건을 조건마다 5회씩 생성해 코드로 자동 채점했다. LLM 단독은 진단 JSON 원본·매출·사례 과징금을 그대로 받았다.

| 오류 유형 | LLM 단독 | 보고서 엔진 |
|---|---|---|
| 오류가 하나라도 있는 보고서 | 15 / 15 | **0 / 15** |
| 양호 항목을 취약으로 보고 | 23건 | 0 |
| 관련성 낮은 사례 인용 | 13건 | 0 |
| 경영진 요약에 다른 회사 과징금 사용 (예: "최대 213억 원", 고객사 상한은 1억 5,000만 원) | 5건 | 0 |
| 출처 없는 금액 ("423억 원") | 1건 | 0 |
| 취약 항목 누락 | 1건 | 0 |

보고서 엔진은 검증(validate) 전 출력에서도 모든 유형이 0건이었다.

| 지표 | 값 |
|---|---|
| 일부러 넣은 오류 8종(가짜 ID·조문·사례, 문장 속 금액, 누락 등) 탐지 | 8 / 8 |
| 보고서 1건 생성 시간 | 약 9.5초 (GPT-4o 응답 평균 7.9초 + 사례 검색·PDF 2종 1.6초, 따로 잰 값의 합) |
| LLM 입력 토큰 | 8,580 → 4,923 (43% 감소) |
| 동일 결함 사례 매칭 | 취약점 8건 중 7건 |
| 카탈로그에 없는 항목(W-99) 입력 | 정상 종료, PDF 2종 생성 (해당 칸만 빈칸) |

**한계**: 실험은 진단 3건 × 5회 규모이고, 고객사 정보(매출 50억 원, 회원 12만 명)는 가상의 교육 플랫폼 기준이다. 유사 사례 금액은 대부분 개정법 시행 이전 처분이다.

---

## 파일 구성

| 파일 | 역할 |
|---|---|
| `engine.py` | 전체 흐름 (load → facts → llm → validate → render) |
| `case_kb.py` | 사례 지식베이스 적재·4단계 검색 |
| `exposure.py` | 과징금 노출액·우선순위 계산 |
| `convert_cases.py` | 사례 시트 → `cases.json` 변환·검사 |
| `templates/exec.html.j2`, `tech.html.j2`, `_common.css.j2` | 경영진용·실무진용 템플릿, 공통 색상 |
| `data/` | `context.json`, `item_catalog.json`, `cases.xlsx`, `sources/`(보도자료 PDF), `scans/`(진단 JSON 예시) |
| `fonts/`, `assets/` | Pretendard TTF, 루키즈 로고 |

깃에 올리지 않는 것: `.env`(API 키), `.venv/`, `out/`, `data/chroma_db/`, `data/cases.json` (뒤의 둘은 `convert_cases.py`·`case_kb.py load`로 다시 만든다)
