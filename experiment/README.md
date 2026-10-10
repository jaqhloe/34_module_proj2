# 보고서 엔진 검증 실험

메인 README와 발표 슬라이드 '검증 결과'의 수치는 아래 실험에서 나왔습니다. 모든 조건에서 GPT-4o, temperature 0.2를 사용했습니다.

| 폴더 | 실행일 | 내용 |
|---|---|---|
| [`2026-10-07_verify/`](2026-10-07_verify/REPORT.md) | 10-07 | **최종 수치.** 샘플 진단 3건으로 사례 매칭, 보고서 생성 시간, LLM 단독 vs 엔진 비교(3건 × 5회 × 2조건), 오류 8종 주입 시험, 카탈로그 밖 항목(W-99) 처리 |
| [`2026-10-07_live_scan/`](2026-10-07_live_scan/REPORT.md) | 10-07 | 같은 검증을 실제 웹 서비스 스캔 결과(SCAN-20261007-001)에 다시 적용 |
| `2026-10-06_compare/` | 10-06 | 초기 비교 실험 스크립트(`compare.py`)와 LLM 출력 원본 30건. 이후 `verify_suite.py`로 확장 |

각 폴더의 `REPORT.md`에 결과 표가 있고, `results/`에는 LLM 출력 원본과 채점 결과(`results.json`)가 있습니다.

## 다시 실행하기

`vuln_assessment/report_engine/README.md`의 환경(.venv, WeasyPrint)과 `vuln_assessment/.env`의 `OPENAI_API_KEY`가 필요합니다.

```bash
cd vuln_assessment/report_engine
DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/python ../../experiment/2026-10-07_verify/verify_suite.py
```

- 실제 API를 호출하므로 비용이 들고, LLM 출력은 실행마다 조금씩 달라집니다.
- `2026-10-07_live_scan`은 실험에 쓴 입력(`input/legal_result_SCAN-20261007-001.json`)을 함께 보관해 같은 입력으로 재현할 수 있습니다. `scanner/main.py`를 다시 실행하면 새 스캔 ID가 붙고 법령 매핑도 LLM이 다시 하므로 입력이 달라집니다.
- 로그에 남은 파일 경로는 레포 기준 상대 경로로 바꿔 두었습니다.
