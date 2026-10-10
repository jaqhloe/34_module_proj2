"""
LLM 단독 vs 보고서 엔진 비교 실험 (report_engine 폴더의 .venv로 실행)

조건 (모델·온도·JSON 모드·출력 스키마는 동일, GPT-4o temperature 0.2)
  A. LLM 단독  : 진단 JSON 원본 + 고객사 정보(매출 포함) + 유사 사례 카드(과징금 포함)를 그대로 주고
                 "과징금 노출과 유사 사례도 포함해 보고서 내용을 써 달라"는 단순 프롬프트
  B. 엔진(검증 전): engine.run_llm과 같은 입력 (SYSTEM_PROMPT 규칙 16개 + facts_for_llm, 금액 제외)
  C. 엔진(최종)  : B의 출력에 engine.validate()를 적용한 결과 (실제 보고서에 쓰이는 것)

자동 채점 (보고서 1건당)
  없는 ID        : 실제 데이터에 없는 finding_id / law_code / case_id
  부적합 사례     : 존재는 하지만 그 위험의 검색 후보가 아니거나 '참고 사례' 등급인 사례 인용
  누락           : 로드맵 또는 취약점별 설명에서 빠진 취약 항목
  출처 없는 금액   : 문장 속 원화 금액 중 원본 데이터(법정 상한, 특례 상한, 감경 예시, 매출, 사례 과징금)와 맞지 않는 것
  문장 속 금액     : 문장에 나온 원화 금액 전체 (엔진은 금액을 템플릿만 쓰기로 했으므로 참고 지표)
"""
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

RE = Path(__file__).resolve().parents[2] / "vuln_assessment/report_engine"
sys.path.insert(0, str(RE))
sys.argv = ["compare"]
import engine  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from openai import OpenAI  # noqa: E402

load_dotenv(RE.parent / ".env")
client = OpenAI()
MODEL = "gpt-4o"
RUNS = 5
SCANS = ["data/scans/output_sample.json", "data/scans/SCAN-2026-002.json", "data/scans/output_scanner_format.json"]
OUT = Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)

BASELINE_SYSTEM = "너는 정보보호 컨설팅 보고서를 쓰는 시니어 컨설턴트다. 지정된 JSON 형식으로만 답한다."


def baseline_user(scan, context, cards):
    return ("아래 취약점 진단 결과, 고객사 정보, 유사 처분 사례를 바탕으로 경영진용·실무진용 보고서 내용을 작성해줘. "
            "경영진이 위험을 체감할 수 있게 과징금 노출 규모와 유사 처분 사례도 포함해줘.\n\n출력 형식:\n"
            + engine.OUTPUT_SCHEMA
            + "\n\n진단 결과:\n" + json.dumps(scan, ensure_ascii=False, indent=1)
            + "\n\n고객사 정보:\n" + json.dumps(context, ensure_ascii=False, indent=1)
            + "\n\n유사 처분 사례:\n" + json.dumps(cards, ensure_ascii=False, indent=1))


def engine_user(facts):
    return ("아래 facts로 보고서 문장을 작성해줘.\n\n출력 형식:\n" + engine.OUTPUT_SCHEMA
            + "\n\nfacts:\n" + json.dumps(engine.facts_for_llm(facts), ensure_ascii=False, indent=2))


def call(system, user):
    t = time.time()
    r = client.chat.completions.create(model=MODEL, temperature=0.2, response_format={"type": "json_object"},
                                       messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    return (engine.parse_json_text(r.choices[0].message.content), round(time.time() - t, 2),
            r.usage.prompt_tokens, r.usage.completion_tokens)


# ── 금액 파싱 ──
AMOUNT = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*억(?:\s*(\d[\d,]*)\s*만)?\s*원?"
                    r"|(\d[\d,]*(?:\.\d+)?)\s*(천만|백만|만)\s*원"
                    r"|(\d{1,3}(?:,\d{3})+|\d{5,})\s*원")


def amounts(text):
    out = []
    for m in AMOUNT.finditer(text or ""):
        if m.group(1):
            v = float(m.group(1).replace(",", "")) * 1e8 + (float(m.group(2).replace(",", "")) * 1e4 if m.group(2) else 0)
        elif m.group(3):
            v = float(m.group(3).replace(",", "")) * {"천만": 1e7, "백만": 1e6, "만": 1e4}[m.group(4)]
        else:
            v = float(m.group(5).replace(",", ""))
        out.append((m.group(0).strip(), v))
    return out


def texts_of(llm):
    t = [llm.get("headline", ""), llm.get("summary", "")]
    for r in llm.get("top_risks", []):
        t += [r.get("title", ""), r.get("impact", "")]
    t += [s.get("action", "") for s in llm.get("roadmap", [])]
    t += list(llm.get("decisions", []))
    for n in llm.get("finding_notes", {}).values():
        t += [n.get("description", ""), n.get("impact", "")] if isinstance(n, dict) else [str(n)]
    return [x for x in t if isinstance(x, str)]


def score(llm, facts, valid_amounts):
    vuln_ids = {f["finding_id"] for f in facts["vulns"]}
    all_case_ids = {h["case_id"] for hs in facts["case_candidates"].values() for h in hs}
    e = {"없는 ID": [], "부적합 사례": [], "누락": [], "출처 없는 금액": [], "문장 속 금액": []}
    for r in llm.get("top_risks", []):
        fids = r.get("finding_ids", []) or []
        e["없는 ID"] += [f"finding {x}" for x in fids if x not in vuln_ids]
        e["없는 ID"] += [f"law {x}" for x in r.get("law_codes", []) or [] if x not in facts["laws"]]
        allowed = {h["case_id"] for fid in fids for h in facts["case_candidates"].get(fid, [])
                   if h["match_level"] in engine.STRONG_LEVELS}
        for c in r.get("case_ids", []) or []:
            if c not in all_case_ids:
                e["없는 ID"].append(f"case {c}")
            elif c not in allowed:
                e["부적합 사례"].append(c)
    for s in llm.get("roadmap", []):
        e["없는 ID"] += [f"finding {x}" for x in s.get("finding_ids", []) or [] if x not in vuln_ids]
    e["없는 ID"] += [f"note {k}" for k in llm.get("finding_notes", {}) if k not in vuln_ids]
    in_road = {x for s in llm.get("roadmap", []) for x in s.get("finding_ids", []) or []}
    e["누락"] += [f"roadmap {x}" for x in vuln_ids - in_road]
    e["누락"] += [f"note {x}" for x in vuln_ids - set(llm.get("finding_notes", {}))]
    for t in texts_of(llm):
        for raw, v in amounts(t):
            e["문장 속 금액"].append(raw)
            if not any(abs(v - a) <= max(a * 0.01, 1) for a in valid_amounts):
                e["출처 없는 금액"].append(raw)
    return e


def prepare(path):
    scan = engine.normalize_scan(engine.load_json(RE / path))
    catalog = engine.load_json(RE / "data/item_catalog.json")
    engine.resolve_catalog(scan, catalog)
    context = engine.load_json(RE / "data/context.json")
    cards = engine.load_json(RE / "data/cases.json")
    facts = engine.build_facts(scan, context, cards, catalog, engine.make_search())
    ex = facts["exposure"]
    cand_ids = {h["case_id"] for hs in facts["case_candidates"].values() for h in hs}
    cand_cards = [c for c in cards if c["case_id"] in cand_ids]
    valid = {ex["legal_cap"]["cap_krw"], ex["legal_cap"]["special_10pct"]["cap_krw"],
             ex["reductions"]["investment"]["illustration_on_cap_krw"],
             context["exposure_profile"].get("annual_revenue_krw") or 0}
    valid |= {c.get("fine_krw") or 0 for c in cand_cards} | {c.get("penalty_krw") or 0 for c in cand_cards}
    valid.discard(0)
    base_ctx = {k: v for k, v in context.items() if k not in ("logo", "disclaimer") and not k.startswith("_")}
    base_scan = {k: v for k, v in scan.items()}
    return scan, facts, cand_cards, valid, base_ctx, base_scan


def run_one(job):
    cond, path, i, prep = job
    scan, facts, cards, valid, base_ctx, base_scan = prep
    if cond == "LLM 단독":
        llm, sec, pt, ct = call(BASELINE_SYSTEM, baseline_user(base_scan, base_ctx, cards))
        rows = [("LLM 단독", score(llm, facts, valid))]
    else:
        llm, sec, pt, ct = call(engine.SYSTEM_PROMPT, engine_user(facts))
        raw_score = score(json.loads(json.dumps(llm)), facts, valid)
        clean, warns = engine.validate(json.loads(json.dumps(llm)), facts)
        rows = [("엔진(검증 전)", raw_score), ("엔진(최종)", score(clean, facts, valid))]
        llm = {"raw": llm, "validated": clean, "warnings": warns}
    (OUT / f"{scan['scan_id']}_{cond}_{i}.json").write_text(json.dumps(llm, ensure_ascii=False, indent=1), encoding="utf-8")
    return [{"scan": scan["scan_id"], "cond": c, "run": i, "sec": sec, "prompt_tokens": pt,
             "completion_tokens": ct, "errors": e} for c, e in rows]


def main():
    preps = {p: prepare(p) for p in SCANS}
    for p, (scan, facts, cards, valid, *_) in preps.items():
        strong = sum(1 for hs in facts["case_candidates"].values() if any(h["match_level"] == "동일 결함 사례" for h in hs))
        print(f"{scan['scan_id']}: 취약 {len(facts['vulns'])}건, 사례 후보 {len(cards)}건, 동일 결함 사례 매칭 {strong}/{len(facts['vulns'])}")
    jobs = [(c, p, i, preps[p]) for p in SCANS for c in ("LLM 단독", "엔진") for i in range(RUNS)]
    with ThreadPoolExecutor(6) as ex:
        results = [r for rows in ex.map(run_one, jobs) for r in rows]
    (OUT / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n완료: {len(results)}행 → {OUT/'summary.json'}")


if __name__ == "__main__":
    main()
