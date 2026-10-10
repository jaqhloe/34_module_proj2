"""
발표 슬라이드 '검증 결과'의 수치를 처음부터 다시 측정하는 스크립트

실행: report_engine의 .venv로
  cd vuln_assessment/report_engine   # 레포 루트 기준
  DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/python ../../experiment/2026-10-07_live_scan/verify_suite.py

측정 항목 (결과는 이 폴더의 results/ 와 REPORT.md)
  1. 사례 매칭 등급 분포      : 진단 3건의 취약점별 최상위 사례 등급
  2. 보고서 1건 전체 시간     : engine.py를 실제 LLM 호출 포함으로 실행, perf_counter로 벽시계 시간 측정 (진단 3건)
  3. 실제 실행의 검증 경고     : 2번 실행의 run_log.json
  4. 비교 실험               : LLM 단독 vs 보고서 엔진, 진단 3건 × 5회 × 2조건 (GPT-4o, temperature 0.2, 같은 출력 스키마)
                             토큰 수는 API 응답의 usage.prompt_tokens / completion_tokens
  5. 오류 주입 시험           : 4번에서 저장한 엔진 출력 하나에 오류 8종을 넣고 engine.validate()가 잡는지
  6. 카탈로그 밖 항목(W-99)    : 항목 ID를 W-99로 바꾼 진단 JSON으로 engine.py 실행
"""
import copy
import json
import re
import statistics as st
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
RES.mkdir(exist_ok=True)
RE = HERE.parents[1] / "vuln_assessment/report_engine"
sys.path.insert(0, str(RE))
sys.argv = ["verify_suite"]
import engine  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from openai import OpenAI  # noqa: E402

load_dotenv(RE.parent / ".env")
client = OpenAI()
MODEL, TEMP, RUNS = "gpt-4o", 0.2, 5
SCANS = [str(HERE / "input/legal_result_SCAN-20261007-001.json")]  # 실제 웹사이트 스캔 결과 (SCAN-20261007-001)
PY = str(RE / ".venv/bin/python")
ENV = {"DYLD_FALLBACK_LIBRARY_PATH": "/opt/homebrew/lib", "PATH": "/usr/bin:/bin", "HOME": str(Path.home())}


def save(name, obj):
    (RES / name).write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")


# ───────── 공통 준비 ─────────
def prepare(rel):
    scan = engine.normalize_scan(engine.load_json(RE / rel))
    catalog = engine.load_json(RE / "data/item_catalog.json")
    engine.resolve_catalog(scan, catalog)
    context = engine.load_json(RE / "data/context.json")
    cards = engine.load_json(RE / "data/cases.json")
    facts = engine.build_facts(scan, context, cards, catalog, engine.make_search())
    cand = {h["case_id"] for hs in facts["case_candidates"].values() for h in hs}
    cand_cards = [c for c in cards if c["case_id"] in cand]
    ex = facts["exposure"]
    sources = {  # 원본 금액 → 이름 (금액 대조용)
        ex["legal_cap"]["cap_krw"]: "법정 상한",
        ex["legal_cap"]["special_10pct"]["cap_krw"]: "10% 특례 상한",
        ex["reductions"]["investment"]["illustration_on_cap_krw"]: "투자 감경 예시",
        context["exposure_profile"].get("annual_revenue_krw"): "매출",
    }
    for c in cand_cards:
        for k in ("fine_krw", "penalty_krw"):
            if c.get(k):
                sources[c[k]] = f"{c['case_id']} {c['org']} {k}"
    sources.pop(None, None)
    sources.pop(0, None)
    return {"rel": rel, "scan": scan, "context": context, "facts": facts, "cand_cards": cand_cards, "sources": sources}


# ───────── 금액 파싱 ─────────
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


def text_fields(llm):
    t = [("headline", llm.get("headline", "")), ("summary", llm.get("summary", ""))]
    for i, r in enumerate(llm.get("top_risks", [])):
        t += [(f"top_risks[{i}].title", r.get("title", "")), (f"top_risks[{i}].impact", r.get("impact", ""))]
    t += [(f"roadmap[{i}]", s.get("action", "")) for i, s in enumerate(llm.get("roadmap", []))]
    t += [(f"decisions[{i}]", d) for i, d in enumerate(llm.get("decisions", []))]
    for k, n in llm.get("finding_notes", {}).items():
        if isinstance(n, dict):
            t += [(f"notes.{k}", n.get("description", "") + " " + n.get("impact", ""))]
    return [(w, x) for w, x in t if isinstance(x, str)]


def classify_amount(v, sources):
    """원본 금액과 대조: 일치(1% 이내) / 자릿수 오류(10배·100배 등 차이) / 출처 없음"""
    for a, name in sources.items():
        if abs(v - a) <= max(a * 0.01, 1):
            return "원본과 일치", name
    for a, name in sources.items():
        for f in (10, 100, 1000):
            if abs(v * f - a) <= a * 0.01 or abs(v - a * f) <= a * f * 0.01:
                return f"자릿수 오류(×{f})", name
    return "출처 없음", None


# ───────── 채점 ─────────
CATS = ["존재하지 않는 ID", "양호·수동확인 항목을 취약으로 보고", "관련성 낮은 사례 인용", "취약 항목 누락",
        "문장 속 금액", "원본과 다른 금액"]


def score(llm, p):
    facts, scan = p["facts"], p["scan"]
    status = {f["finding_id"]: f["status"] for f in scan["findings"]}
    vuln = {f["finding_id"] for f in facts["vulns"]}
    all_cases = {h["case_id"] for hs in facts["case_candidates"].values() for h in hs}
    e = defaultdict(list)

    def chk(fid, where):
        if fid in vuln:
            return
        e["양호·수동확인 항목을 취약으로 보고" if fid in status else "존재하지 않는 ID"].append(
            f"{where}:{fid}({status.get(fid, '없음')})")

    for r in llm.get("top_risks", []):
        fids = r.get("finding_ids", []) or []
        for f in fids:
            chk(f, "top_risks")
        for law in r.get("law_codes", []) or []:
            if law not in facts["laws"]:
                e["존재하지 않는 ID"].append(f"law:{law}")
        allowed = {h["case_id"] for f in fids for h in facts["case_candidates"].get(f, [])
                   if h["match_level"] in engine.STRONG_LEVELS}
        for c in r.get("case_ids", []) or []:
            if c not in all_cases:
                e["존재하지 않는 ID"].append(f"case:{c}")
            elif c not in allowed:
                e["관련성 낮은 사례 인용"].append(c)
    for s in llm.get("roadmap", []):
        for f in s.get("finding_ids", []) or []:
            chk(f, "roadmap")
    for k in llm.get("finding_notes", {}):
        chk(k, "finding_notes")
    in_road = {x for s in llm.get("roadmap", []) for x in s.get("finding_ids", []) or []}
    e["취약 항목 누락"] += [f"roadmap:{x}" for x in vuln - in_road]
    e["취약 항목 누락"] += [f"finding_notes:{x}" for x in vuln - set(llm.get("finding_notes", {}))]
    for where, t in text_fields(llm):
        for raw, v in amounts(t):
            kind, src = classify_amount(v, p["sources"])
            e["문장 속 금액"].append({"where": where, "amount": raw, "판정": kind, "원본": src, "문장": t.strip()[:200]})
            if kind != "원본과 일치":
                e["원본과 다른 금액"].append({"where": where, "amount": raw, "판정": kind, "원본": src})
    return {k: e.get(k, []) for k in CATS}


def has_error(sc):
    return any(sc[k] for k in CATS if k != "문장 속 금액")


# ───────── LLM 호출 ─────────
BASELINE_SYSTEM = "너는 정보보호 컨설팅 보고서를 쓰는 시니어 컨설턴트다. 지정된 JSON 형식으로만 답한다."


def baseline_user(p):
    ctx = {k: v for k, v in p["context"].items() if k not in ("logo", "disclaimer") and not k.startswith("_")}
    return ("아래 취약점 진단 결과, 고객사 정보, 유사 처분 사례를 바탕으로 경영진용·실무진용 보고서 내용을 작성해줘. "
            "경영진이 위험을 체감할 수 있게 과징금 노출 규모와 유사 처분 사례도 포함해줘.\n\n출력 형식:\n" + engine.OUTPUT_SCHEMA
            + "\n\n진단 결과:\n" + json.dumps(p["scan"], ensure_ascii=False, indent=1)
            + "\n\n고객사 정보:\n" + json.dumps(ctx, ensure_ascii=False, indent=1)
            + "\n\n유사 처분 사례:\n" + json.dumps(p["cand_cards"], ensure_ascii=False, indent=1))


def engine_user(p):   # engine.run_llm()과 같은 입력
    return ("아래 facts로 보고서 문장을 작성해줘.\n\n출력 형식:\n" + engine.OUTPUT_SCHEMA
            + "\n\nfacts:\n" + json.dumps(engine.facts_for_llm(p["facts"]), ensure_ascii=False, indent=2))


def call(system, user):
    t = time.perf_counter()
    r = client.chat.completions.create(model=MODEL, temperature=TEMP, response_format={"type": "json_object"},
                                       messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    return (engine.parse_json_text(r.choices[0].message.content), round(time.perf_counter() - t, 2),
            r.usage.prompt_tokens, r.usage.completion_tokens)


def run_one(job):
    cond, i, p = job
    sid = p["scan"]["scan_id"]
    if cond == "LLM 단독":
        llm, sec, pt, ct = call(BASELINE_SYSTEM, baseline_user(p))
        rows = [("LLM 단독", score(llm, p))]
        saved = llm
    else:
        llm, sec, pt, ct = call(engine.SYSTEM_PROMPT, engine_user(p))
        raw = copy.deepcopy(llm)
        clean, warns = engine.validate(copy.deepcopy(llm), p["facts"])
        rows = [("엔진(검증 전)", score(raw, p)), ("엔진(최종)", score(clean, p))]
        saved = {"raw": raw, "validated": clean, "warnings": warns}
    (RES / "outputs").mkdir(exist_ok=True)
    (RES / "outputs" / f"{sid}_{cond}_{i}.json").write_text(json.dumps(saved, ensure_ascii=False, indent=1), encoding="utf-8")
    return [{"scan": sid, "cond": c, "run": i, "sec": sec, "prompt_tokens": pt, "completion_tokens": ct, "score": s}
            for c, s in rows]


# ───────── 1. 사례 매칭 ─────────
def case_matching(preps):
    rows = []
    for p in preps:
        for f in p["facts"]["vulns"]:
            hits = p["facts"]["case_candidates"].get(f["finding_id"], [])
            levels = Counter(h["match_level"] for h in hits)
            rows.append({"scan": p["scan"]["scan_id"], "title": f["title"], "best": hits[0]["match_level"] if hits else None,
                         "후보 등급 분포": dict(levels)})
    return rows


# ───────── 2·3. 실제 파이프라인 전체 시간 ─────────
def e2e(rel):
    out = RES / "e2e" / Path(rel).stem
    t = time.perf_counter()
    r = subprocess.run([PY, "engine.py", "--scan", rel, "--out", str(out)], cwd=RE, env=ENV, capture_output=True, text=True)
    sec = round(time.perf_counter() - t, 2)
    log = json.loads((out / "run_log.json").read_text(encoding="utf-8")) if (out / "run_log.json").exists() else None
    return {"scan": rel, "exit": r.returncode, "sec_total": sec, "run_log": log, "stdout": r.stdout[-800:], "stderr": r.stderr[-800:]}


# ───────── 5. 오류 주입 ─────────
def injection(p, llm):
    bad = copy.deepcopy(llm)
    r = bad["top_risks"][0]
    r["finding_ids"].append("SCAN-FAKE-99")
    r["law_codes"].append("PIPA-999")
    r["case_ids"] = ["PIPC-2099-001"]
    bad["top_risks"].append({"title": "가짜 위험", "finding_ids": ["NOPE"], "impact": "x", "law_codes": [], "case_ids": []})
    bad["headline"] += " 과징금 3억 원이 예상됩니다"
    bad["roadmap"] = [{"phase": "내년", "action": "x", "finding_ids": []}]
    bad["finding_notes"] = {}
    injected = {
        "없는 취약점 ID": "SCAN-FAKE-99", "없는 법령 코드": "PIPA-999", "없는 사례 ID": "PIPC-2099-001",
        "근거 없는 위험": "유효한 취약점이 없어", "문장 속 금액": "3억 원", "없는 로드맵 단계": "내년",
        "로드맵 누락": "빠져 있어", "설명 누락": "설명 누락",
    }
    clean, warns = engine.validate(bad, p["facts"])
    caught = {k: any(v in w for w in warns) for k, v in injected.items()}
    return {"caught": caught, "warnings": warns,
            "after": {"money_still_in_headline": "3억 원" in clean["headline"]}}


# ───────── 6. W-99 ─────────
def w99():
    d = json.loads((RE / "data/scans/SCAN-2026-002.json").read_text(encoding="utf-8"))
    d["findings"][0]["item_id"], d["findings"][0]["title"] = "W-99", "신규 스캐너 점검 항목"
    src = RES / "scan_w99.json"
    src.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    out = RES / "w99"
    llm_saved = sorted((RES / "outputs").glob("SCAN-2026-002_엔진_*.json"))[0]
    raw = RES / "w99_llm_output.json"
    raw.write_text(json.dumps(json.loads(llm_saved.read_text(encoding="utf-8"))["raw"], ensure_ascii=False), encoding="utf-8")
    r = subprocess.run([PY, "engine.py", "--scan", str(src), "--out", str(out), "--llm-output", str(raw)],
                       cwd=RE, env=ENV, capture_output=True, text=True)
    html = (out / "tech_report.html").read_text(encoding="utf-8") if (out / "tech_report.html").exists() else ""
    return {"exit": r.returncode, "pdfs": sorted(x.name for x in out.glob("*.pdf")), "stdout": r.stdout,
            "판단 기준 칸 비어 있음": "판단 기준</th><td></td>" in html.replace("\n", "").replace(" ", "")
            or bool(re.search(r"판단 기준</th>\s*<td>\s*</td>", html))}


def main():
    t0 = time.perf_counter()
    preps = [prepare(s) for s in SCANS]
    result = {"meta": {"date": time.strftime("%Y-%m-%d %H:%M"), "model": MODEL, "temperature": TEMP, "runs": RUNS,
                       "scans": [p["scan"]["scan_id"] for p in preps]}}

    result["case_matching"] = case_matching(preps)
    print("[1] 사례 매칭 완료")

    result["e2e"] = [e2e(s) for s in SCANS for _ in range(3)]   # 진단 1건이라 3번 반복
    print("[2] 전체 파이프라인:", [(x["scan"], x["exit"], x["sec_total"]) for x in result["e2e"]])

    jobs = [(c, i, p) for p in preps for c in ("LLM 단독", "엔진") for i in range(RUNS)]
    with ThreadPoolExecutor(6) as ex:
        rows = [r for rs in ex.map(run_one, jobs) for r in rs]
    result["compare_rows"] = rows
    print("[4] 비교 실험 완료:", len(rows), "행")

    p2 = preps[0]
    eng = json.loads(sorted((RES / "outputs").glob(f"{p2['scan']['scan_id']}_엔진_*.json"))[0].read_text(encoding="utf-8"))["raw"]
    result["injection"] = injection(p2, eng)
    print("[5] 주입 시험:", result["injection"]["caught"])

    result["w99"] = {"exit": "-", "pdfs": [], "stdout": "이번 실행에서는 생략 (진단과 무관한 시험, run_2026-10-07 결과 참고)"}

    result["meta"]["elapsed_sec"] = round(time.perf_counter() - t0, 1)
    save("results.json", result)
    write_report(result)
    print("완료:", RES / "results.json", "/", HERE / "REPORT.md")


def write_report(R):
    L = [f"# 검증 결과 ({R['meta']['date']} 실행)", "",
         f"모델 {R['meta']['model']}, temperature {R['meta']['temperature']}, 진단 {', '.join(R['meta']['scans'])}, "
         f"비교 실험 조건당 진단마다 {R['meta']['runs']}회. 전체 소요 {R['meta']['elapsed_sec']}초.", ""]
    L += ["## 1. 사례 매칭 (취약점별 최상위 등급)", "", "| 진단 | 취약점 | 최상위 등급 |", "|---|---|---|"]
    L += [f"| {r['scan']} | {r['title']} | {r['best']} |" for r in R["case_matching"]]
    same = sum(1 for r in R["case_matching"] if r["best"] == "동일 결함 사례")
    L += ["", f"동일 결함 사례 매칭: **{same} / {len(R['case_matching'])}**", ""]

    L += ["## 2. 보고서 1건 전체 시간 (engine.py, 실제 LLM 호출 포함, 벽시계)", "",
          "| 진단 | 종료 코드 | 시간(초) | 검증 경고 |", "|---|---|---|---|"]
    for x in R["e2e"]:
        L.append(f"| {x['scan']} | {x['exit']} | {x['sec_total']} | {len(x['run_log']['warnings']) if x['run_log'] else '-'} |")
    secs = [x["sec_total"] for x in R["e2e"] if x["exit"] == 0]
    L += ["", f"평균 **{st.mean(secs):.1f}초** (최소 {min(secs)} / 최대 {max(secs)}), 파이썬 시작·사례 검색 임베딩 호출·LLM·PDF 2종 포함", ""]

    rows = R["compare_rows"]
    L += ["## 3. 비교 실험", "", "| 지표 | LLM 단독 | 엔진(검증 전) | 엔진(최종) |", "|---|---|---|---|"]
    conds = ["LLM 단독", "엔진(검증 전)", "엔진(최종)"]
    by = {c: [r for r in rows if r["cond"] == c] for c in conds}
    L.append("| 오류가 하나라도 있는 보고서 | " + " | ".join(f"{sum(has_error(r['score']) for r in by[c])} / {len(by[c])}" for c in conds) + " |")
    for k in CATS:
        L.append(f"| {k} | " + " | ".join(str(sum(len(r['score'][k]) for r in by[c])) for c in conds) + " |")
    for c in ("LLM 단독", "엔진(검증 전)"):
        rs = by[c]
        L.append(f"| {c} 평균 입력 토큰 / 출력 토큰 / 응답 시간 | {st.mean(r['prompt_tokens'] for r in rs):.0f} / "
                 f"{st.mean(r['completion_tokens'] for r in rs):.0f} / {st.mean(r['sec'] for r in rs):.1f}초 | | |")
    L += ["", "### 문장 속 금액 전부 (LLM 단독)", "", "| 진단·회차 | 위치 | 금액 | 판정 | 대조한 원본 | 문장 |", "|---|---|---|---|---|---|"]
    for r in by["LLM 단독"]:
        for a in r["score"]["문장 속 금액"]:
            L.append(f"| {r['scan']} #{r['run']} | {a['where']} | {a['amount']} | {a['판정']} | {a['원본'] or '-'} | {a['문장'][:90]} |")
    L += ["", "주의: LLM 단독에는 사례 등급 정보를 주지 않았다 (등급 검색은 엔진의 설계 자체). '관련성 낮은 사례'는 그 위험의 검색 후보가 아니거나 '참고' 등급인 사례.", ""]

    inj = R["injection"]
    L += ["## 4. 오류 주입 시험 (저장된 엔진 출력에 8종 주입 → engine.validate())", "",
          "| 주입한 오류 | 탐지 |", "|---|---|"]
    L += [f"| {k} | {'O' if v else 'X'} |" for k, v in inj["caught"].items()]
    L += ["", f"탐지 **{sum(inj['caught'].values())} / {len(inj['caught'])}** · 검증 후에도 headline에 금액이 남아 있음: {inj['after']['money_still_in_headline']} (금액은 경고만)", ""]

    w = R["w99"]
    L += ["## 5. 카탈로그 밖 항목 (W-99)", "", f"종료 코드 {w['exit']}, 생성된 PDF {w['pdfs']}", "", "```", w["stdout"].strip(), "```", ""]
    (HERE / "REPORT.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    main()
