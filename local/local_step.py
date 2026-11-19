#!/usr/bin/env python3
"""
로컬 한 단계: evidence_N.zip → (판정) → Claude API → (규칙 검사) → cfg_{N+1}.cfg

  python3 local_step.py evidence_0.zip   # 단계 0 근거 → 단계 1 최초 cfg 생성
  python3 local_step.py evidence_N.zip   # 반복 N 근거 → 판정 → 개선 cfg 생성

필요: pip install anthropic, API 키 파일 ~/.claude_api_key (없으면 첫 실행 때 입력받아 저장)
입력: config.txt, spec.txt, rules.txt (같은 폴더)
상태: state/ (history.json, best.cfg, blocklist.txt, lesson_candidates.txt)
출력: out/cfg_{N+1}.cfg, out/changes_{N+1}.txt, runs/{N+1}/ (프롬프트·응답 원본)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
OUT = ROOT / "out"
RUNS = ROOT / "runs"

TS_HOST = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} (.*)$")
TS_KERN = re.compile(r"\[\s*(\d+\.\d+)\]")
CFG_SET = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
CFG_UNSET = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")


# ---------------------------------------------------------------- 공통 유틸
def read_kv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def parse_cfg_text(text: str) -> dict[str, str]:
    vals: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        m, u = CFG_SET.match(line), CFG_UNSET.match(line)
        if m:
            vals[m.group(1)] = m.group(2)
        elif u:
            vals[u.group(1)] = "n"
    return vals


def cfg_line(sym: str, val: str) -> str:
    return f"# CONFIG_{sym} is not set" if val == "n" else f"CONFIG_{sym}={val}"


def norm_sym(s: str) -> str:
    return s.strip().removeprefix("CONFIG_")


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- 규칙 (rules.txt)
def load_rules() -> dict:
    """KEEP CONFIG_X=y / OFF CONFIG_X / BAN CONFIG_X=v  (# 주석 허용)"""
    rules = {"keep": {}, "off": set(), "ban": {}, "needs_allow": {"EXPERT", "PROCESSOR_SELECT"}}
    for raw in (ROOT / "rules.txt").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind, _, body = line.partition(" ")
        body = body.strip()
        if kind == "KEEP":
            s, _, v = body.partition("=")
            rules["keep"][norm_sym(s)] = v or "y"
        elif kind == "OFF":
            rules["off"].add(norm_sym(body))
        elif kind == "ALLOW_NEEDS":  # HIDDEN 해제를 위해 자동으로 켜도 되는 심볼
            rules["needs_allow"].add(norm_sym(body))
        elif kind == "BAN":
            s, _, v = body.partition("=")
            rules["ban"].setdefault(norm_sym(s), set()).add(v)
    for raw in (STATE / "blocklist.txt").read_text(encoding="utf-8").splitlines() \
            if (STATE / "blocklist.txt").exists() else []:
        if "=" in raw and not raw.startswith("#"):
            s, v = raw.split("#", 1)[0].strip().split("=", 1)
            rules["ban"].setdefault(norm_sym(s), set()).add(v.strip())
    return rules


# ---------------------------------------------------------------- 근거 정리
class Evidence:
    def __init__(self, zip_path: Path):
        self.zf = zipfile.ZipFile(zip_path)
        self.names = set(self.zf.namelist())
        self.meta = json.loads(self.text("meta.json"))
        self.measure = json.loads(self.text("measure.json")) if "measure.json" in self.names else {}
        self.map = json.loads(self.text("map.json")) if "map.json" in self.names else []
        self.map_by = {}
        for d in self.map:
            self.map_by[d["symbol"]] = d

    def text(self, name: str) -> str:
        return self.zf.read(name).decode("utf-8", "replace") if name in self.names else ""

    @property
    def iter(self) -> int:
        return int(self.meta["iter"])

    @property
    def median(self):
        return self.measure.get("median_panic_to_frame")

    def ok(self) -> bool:
        return self.meta.get("status") == "ok" and self.median is not None

    def failure(self) -> str:
        if self.meta.get("status") != "ok":
            return self.meta.get("status")
        runs = self.measure.get("runs", [])
        bad = sorted({r["status"] for r in runs if r["status"] != "ok"})
        return ",".join(bad) or "no_measurement"

    def best_log(self) -> str:
        """중앙값에 가장 가까운 성공 회차의 로그 (없으면 첫 로그)."""
        runs = [r for r in self.measure.get("runs", []) if r.get("panic_to_frame")]
        if runs and self.median:
            r = min(runs, key=lambda r: abs(r["panic_to_frame"] - self.median))
            return self.text(f"boot_{r['run']}.log")
        return self.text("boot_1.log")


def recovery_lines(log: str, max_lines: int = 400) -> list[str]:
    lines = [TS_HOST.sub(r"\1", l) for l in log.splitlines()]
    start = next((i for i, l in enumerate(lines) if "Kernel panic" in l), 0)
    out, seen = [], set()
    for l in lines[start:]:
        if l in seen:
            continue
        seen.add(l)
        out.append(l)
        if "first frame done" in l:
            break
    return out[:max_lines]


def gap_list(lines: list[str], min_gap: float) -> str:
    rows, prev, prev_l, recovering = [], None, "", False
    for l in lines:
        if "] Linux version" in l:
            recovering, prev = True, None
        m = TS_KERN.search(l)
        if not recovering or not m:
            continue
        t = float(m.group(1))
        if prev is not None and t - prev >= min_gap:
            rows.append(f"{prev:.3f}->{t:.3f} ({(t - prev) * 1000:.0f}ms)\n"
                        f"  직전: {prev_l[:140]}\n  직후: {l[:140]}")
        prev, prev_l = t, l
    return "\n".join(rows) or "(공백 없음)"


def measure_text(ev: Evidence) -> str:
    m = ev.measure
    if not m:
        return f"측정 없음 (상태: {ev.failure()})"
    rows = [f"상태: {'성공' if ev.ok() else '실패 ' + ev.failure()}",
            f"패닉→첫 화면 중앙값: {m.get('median_panic_to_frame')}초",
            f"  패닉→t0 {m.get('median_panic_to_t0')} / t0→init {m.get('median_t0_to_init')}"
            f" / init→화면 {m.get('median_init_to_frame')}",
            f"커널 이미지: {ev.meta.get('bzimage_bytes')} bytes"]
    for r in m.get("runs", []):
        rows.append(f"  회차 {r['run']}: {r['status']} {r.get('panic_to_frame')}초")
    return "\n".join(rows)


# ---------------------------------------------------------------- 끄기 가능성 검사
def plan_off(sym: str, ev: Evidence, rules: dict, depth: int = 0) -> tuple[list[tuple[str, str]], str | None]:
    """sym을 끄는 데 필요한 (심볼, 값) 목록과 불가 사유."""
    d = ev.map_by.get(sym)
    if d is None:
        return [(sym, "n")], None  # 이미 꺼져 있거나 지도에 없음
    cls = d["class"]
    if cls == "DIRECT":
        return [(sym, "n")], None
    if cls == "HIDDEN":
        needs = d.get("needs", [])
        ok = [n for n in needs if n in rules["needs_allow"] and n not in rules["off"]]
        if not ok:
            return [], f"{sym}: 프롬프트 조건 {needs} 자동 충족 불가 (허용 목록: {sorted(rules['needs_allow'])})"
        # 허용 목록 밖의 needs(예: 다른 아키텍처 심볼)는 무시하고 허용된 것만 켬
        return [(n, "y") for n in ok] + [(sym, "n")], None
    if cls == "SELECTED":
        steps: list[tuple[str, str]] = []
        for s in d.get("selected_by", []):
            name = s["symbol"]
            if name in rules["keep"]:
                return [], f"{sym}: 필수 기능 {name}이 select함"
            if depth >= 3:
                return [], f"{sym}: select 사슬이 너무 깊음"
            sub, why = plan_off(name, ev, rules, depth + 1)
            if why:
                return [], why
            steps += sub
        return steps + [(sym, "n")], None
    if cls == "DERIVED":
        return [], f"{sym}: 프롬프트 없음(자동 결정, depends: {d.get('depends_on')}) → 소스 수정 또는 조건 심볼 처리 필요"
    return [], f"{sym}: {cls}는 cfg로 직접 끌 수 없음"


def check_changes(changes: list[dict], ev: Evidence, rules: dict, limit: int | None):
    """규칙 위반 제거 + select/EXPERT 자동 보정. (최종 변경 목록, 보고 줄)"""
    final: dict[str, str] = {}
    report: list[str] = []
    for c in changes:
        sym, val = norm_sym(c["symbol"]), str(c["value"]).strip()
        if sym in rules["keep"] and val != rules["keep"][sym]:
            report.append(f"제거(필수 기능): CONFIG_{sym}={val}")
            continue
        if sym in rules["off"] and val != "n":
            report.append(f"제거(반드시 끔): CONFIG_{sym}={val}")
            continue
        if val in rules["ban"].get(sym, set()):
            report.append(f"제거(금지/실패 이력): CONFIG_{sym}={val}")
            continue
        if val == "n":
            steps, why = plan_off(sym, ev, rules)
            if why:
                report.append(f"제거(끌 수 없음): {why}")
                continue
            for s, v in steps:
                if s != sym:
                    report.append(f"보정 추가: CONFIG_{s}={v} (CONFIG_{sym}을 끄기 위해)")
                final[s] = v
        else:
            final[sym] = val
    report = list(dict.fromkeys(report))
    items = [{"symbol": s, "value": v} for s, v in final.items()]
    if limit and len(items) > limit:
        report.append(f"변경 {len(items)}개 → 앞의 {limit}개만 적용")
        items = items[:limit]
    return items, report


# ---------------------------------------------------------------- cfg 병합
def merge(base_text: str, changes: list[dict], header: str) -> str:
    want = {norm_sym(c["symbol"]): str(c["value"]) for c in changes}
    out, done = [header.rstrip()], set()
    for line in base_text.splitlines():
        if line.startswith("# ===== iteration"):
            continue
        m, u = CFG_SET.match(line.strip()), CFG_UNSET.match(line.strip())
        sym = (m or u).group(1) if (m or u) else None
        if sym in want:
            out.append(cfg_line(sym, want[sym]))
            done.add(sym)
        else:
            out.append(line)
    extra = [cfg_line(s, v) for s, v in want.items() if s not in done]
    if extra:
        out += ["", f"# --- added {datetime.now():%Y-%m-%d %H:%M} ---"] + extra
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------- Claude
SYSTEM = """너는 리눅스 커널 부팅 시간 최적화 전문가다.
목표: kexec crash kernel(복구 커널)이 패닉 후 initramfs의 계기판 앱(rdinit)을 실행해 첫 화면을 그릴 때까지의 시간을 최소화한다.

근거 사용 규칙:
- 입력의 측정값·로그 공백·끄기 가능성 지도·불일치 목록은 스크립트가 계산한 사실이다. 추측보다 우선한다.
- 모든 변경에는 근거(evidence)를 단다: 로그 줄, 로그 공백 구간, 지도 항목, 불일치 항목, 명세 항목 중 하나.
- 끄기 가능성 지도에서:
  DIRECT=바로 끌 수 있음 / SELECTED=selector(<-)를 먼저 꺼야 함 / HIDDEN=needs의 심볼(예: EXPERT)을 켜야 끌 수 있음 /
  DERIVED=프롬프트 없음, cfg로 직접 못 끔(조건 심볼을 끄거나 source_patch_needed로 보고) / CHOICE=다른 멤버를 y로.
- 규칙(rules.txt)의 KEEP은 절대 끄지 않고, OFF는 절대 켜지 않으며, BAN 값은 쓰지 않는다.
- 이력에서 실패한 변경은 다시 제안하지 않는다.
- 확실하지 않으면 risk를 high로 표시한다.
- 결과는 반드시 submit 도구로 제출한다."""

TOOL_INITIAL = {
    "name": "submit",
    "description": "최초 복구 커널 cfg를 제출한다 (기준 설정 위에 덮어쓸 항목).",
    "input_schema": {
        "type": "object",
        "properties": {
            "analysis": {"type": "array", "items": {"type": "object", "properties": {
                "gap": {"type": "string"}, "cause": {"type": "string"}, "evidence": {"type": "string"}},
                "required": ["gap", "cause"]}},
            "cfg": {"type": "array", "description": "기준 설정 대비 변경할 항목 전체",
                    "items": {"type": "object", "properties": {
                        "group": {"type": "string"}, "symbol": {"type": "string"},
                        "value": {"type": "string", "description": "y, n, m 또는 값"},
                        "reason": {"type": "string"}, "evidence": {"type": "string"}},
                        "required": ["group", "symbol", "value", "reason", "evidence"]}},
            "source_patch_needed": {"type": "array", "items": {"type": "object", "properties": {
                "symbol": {"type": "string"}, "reason": {"type": "string"}}, "required": ["symbol"]}},
            "cmdline": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["analysis", "cfg"],
    },
}

TOOL_IMPROVE = {
    "name": "submit",
    "description": "현재 최선 cfg에 적용할 다음 변경 목록을 제출한다.",
    "input_schema": {
        "type": "object",
        "properties": {
            "analysis": {"type": "array", "items": {"type": "object", "properties": {
                "gap": {"type": "string"}, "cause": {"type": "string"}, "evidence": {"type": "string"}},
                "required": ["gap", "cause"]}},
            "changes": {"type": "array", "items": {"type": "object", "properties": {
                "symbol": {"type": "string"}, "value": {"type": "string"},
                "reason": {"type": "string"}, "evidence": {"type": "string"},
                "expected_ms": {"type": "number"}, "risk": {"type": "string", "enum": ["low", "mid", "high"]}},
                "required": ["symbol", "value", "reason", "evidence", "risk"]}},
            "source_patch_needed": {"type": "array", "items": {"type": "object", "properties": {
                "symbol": {"type": "string"}, "reason": {"type": "string"}}, "required": ["symbol"]}},
            "cmdline": {"type": "array", "items": {"type": "string"}},
            "lesson_candidates": {"type": "array", "items": {"type": "string"},
                                  "description": "실패에서 얻은 제약 후보 (사람이 검토)"},
        },
        "required": ["analysis", "changes"],
    },
}


def load_api_key(conf: dict) -> str:
    """API 키: config.txt의 API_KEY_FILE (기본 ~/.claude_api_key). 없으면 입력받아 저장."""
    key_file = Path(conf.get("API_KEY_FILE") or "~/.claude_api_key").expanduser()
    if not key_file.exists():
        key_file.write_text(input("API 키 입력: ").strip())
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
    key = key_file.read_text().strip()
    if not key:
        raise ValueError(f"API 키 파일이 비어 있습니다: {key_file}")
    return key


def call_claude(conf: dict, user: str, tool: dict, run_dir: Path) -> dict:
    spec = (ROOT / "spec.txt").read_text(encoding="utf-8")
    system = [
        {"type": "text", "text": SYSTEM},
        {"type": "text", "text": "[명세]\n" + spec, "cache_control": {"type": "ephemeral"}},
    ]
    (run_dir / "prompt.txt").write_text(SYSTEM + "\n\n[명세]\n" + spec + "\n\n" + user, encoding="utf-8")
    if conf.get("DRY_RUN", "false").lower() == "true":
        print(f"DRY_RUN: API 호출 안 함. 입력: {run_dir / 'prompt.txt'} ({len(user):,}자)")
        sys.exit(0)
    if conf.get("MOCK_RESPONSE"):  # API 대신 저장된 응답 사용 (submit 입력 JSON 또는 response_N.json)
        data = json.loads(Path(conf["MOCK_RESPONSE"]).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "content" in data:
            for block in data["content"]:
                if block.get("type") == "tool_use" and block.get("name") == "submit":
                    print(f"저장된 응답 사용 (API 호출 안 함): {conf['MOCK_RESPONSE']}")
                    return block["input"]
            raise RuntimeError("저장된 응답에 submit 도구 호출이 없습니다.")
        return data

    import anthropic
    client = anthropic.Anthropic(api_key=load_api_key(conf))
    messages = [{"role": "user", "content": user}]
    for attempt in (1, 2):
        # 이 모델은 tool_choice 강제(tool/any)를 지원하지 않으므로 auto + 지시로 submit 호출을 유도
        with client.messages.stream(
            model=conf.get("MODEL", "claude-opus-5-5"),
            max_tokens=int(conf.get("MAX_TOKENS", "32000")),
            system=system,
            tools=[tool],
            tool_choice={"type": "auto"},
            messages=messages,
        ) as stream:
            resp = stream.get_final_message()
        (run_dir / f"response_{attempt}.json").write_text(resp.model_dump_json(indent=2), encoding="utf-8")
        u = resp.usage
        print(f"토큰: 입력 {u.input_tokens}, 캐시 읽기 {getattr(u, 'cache_read_input_tokens', 0) or 0}, "
              f"출력 {u.output_tokens} (stop_reason={resp.stop_reason})")
        for block in resp.content:
            if block.type == "tool_use" and block.name == "submit":
                if resp.stop_reason == "max_tokens":
                    raise RuntimeError("출력이 MAX_TOKENS에서 잘렸습니다. config.txt의 MAX_TOKENS를 늘리세요.")
                return block.input
        if resp.stop_reason == "max_tokens":
            raise RuntimeError("출력이 MAX_TOKENS에서 잘렸습니다. config.txt의 MAX_TOKENS를 늘리세요.")
        # submit 없이 텍스트로만 답한 경우: 한 번 더 요청
        messages = messages + [
            {"role": "assistant", "content": resp.content},
            {"role": "user", "content": "분석 내용을 반드시 submit 도구 호출로 제출하라. 텍스트 답변은 처리되지 않는다."},
        ]
    raise RuntimeError("submit 도구 응답이 없습니다 (2회 시도). runs 폴더의 response_*.json을 확인하세요.")


# ---------------------------------------------------------------- 이력
def history_table(hist: list[dict]) -> str:
    rows = ["반복 | 출처 | 변경 수 | 판정 | 패닉→첫 화면 | 커널 bytes | 비고"]
    for h in hist:
        rows.append(f"{h['iter']} | {h.get('origin', '')} | {len(h.get('changes', []))} | {h.get('verdict', '대기')} | "
                    f"{h.get('median')} | {h.get('ksize')} | {h.get('note', '')}")
        if h.get("verdict") in ("rejected", "failed"):
            rows.append("    변경: " + ", ".join(f"{c['symbol']}={c['value']}" for c in h.get("changes", []))[:600])
    return "\n".join(rows)


def _actionable(d: dict) -> bool:
    cls = d.get("class")
    if cls in ("DIRECT", "HIDDEN", "CHOICE"):
        return True
    if cls == "SELECTED":
        return any(_actionable(x) for x in d.get("selected_by", []) if "class" in x)
    return False


def _sel_str(d: dict) -> str:
    c = (d.get("class") or "?")[0]
    subs = [x for x in d.get("selected_by", []) if "class" in x and _actionable(x)]
    if c == "S" and subs:
        return f"{d['symbol']}(S<-" + ",".join(_sel_str(x) for x in subs) + ")"
    return f"{d['symbol']}({c})"


def compact_map(entries: list[dict]) -> str:
    """지도를 한 줄씩으로 압축. 끌 방법이 없는 항목(아키텍처 고정 등)은 이름만 모음."""
    lines, fixed = [], []
    for d in entries:
        if not _actionable(d):
            fixed.append(d["symbol"])
            continue
        cls, pr = d["class"], (d.get("prompt") or "")[:40]
        tail = f' "{pr}"' if pr else ""
        if cls == "HIDDEN":
            lines.append(f"{d['symbol']}={d['value']} H needs={','.join(d.get('needs', []))}{tail}")
        elif cls == "SELECTED":
            subs = [x for x in d.get("selected_by", []) if "class" in x and _actionable(x)]
            lines.append(f"{d['symbol']}={d['value']} S <- " + ", ".join(_sel_str(x) for x in subs) + tail)
        else:
            lines.append(f"{d['symbol']}={d['value']} {cls[0]}{tail}")
    head = ("형식: SYM=값 분류 [needs/<- selector]  분류 D=DIRECT H=HIDDEN S=SELECTED C=CHOICE, "
            "selector 뒤 괄호는 그 selector의 분류")
    return head + "\n" + "\n".join(lines) + "\n\n[cfg로 끌 방법이 없는 항목 (DERIVED, 또는 고정 옵션만 select함)]\n" + ", ".join(fixed)


def evidence_block(ev: Evidence, conf: dict) -> str:
    lines = recovery_lines(ev.best_log(), int(conf.get("LOG_MAX_LINES", "400")))
    parts = [
        "[측정]\n" + measure_text(ev),
        "[로그 공백 (복구 커널, 커널 시간)]\n" + gap_list(lines, float(conf.get("MIN_GAP_SEC", "0.02"))),
        "[요청 cfg 대비 최종 .config 불일치]\n" + (ev.text("gaps.txt").strip() or "없음"),
        "[끄기 가능성 지도 (최종 .config에서 켜진 옵션)]\n" + (compact_map(ev.map) if ev.map else "없음"),
        "[복구 커널 로그 (중복 제거)]\n" + "\n".join(lines),
    ]
    if ev.meta.get("status") == "build_failed":
        parts.insert(1, "[빌드 실패 로그 끝부분]\n" + ev.text("build_tail.log")[-6000:])
    return "\n\n".join(parts)


# ---------------------------------------------------------------- 메인
def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    conf = read_kv(ROOT / "config.txt")
    for d in (STATE, OUT, RUNS):
        d.mkdir(exist_ok=True)
    ev = Evidence(Path(sys.argv[1]))
    rules = load_rules()
    hist: list[dict] = load_json(STATE / "history.json", [])
    st: dict = load_json(STATE / "state.json", {"best_median": None, "pending": [], "no_improve": 0})
    n = ev.iter
    nxt = n + 1
    run_dir = RUNS / str(nxt)
    run_dir.mkdir(exist_ok=True)
    tol = float(conf.get("REGRESSION_TOL_SEC", "0.03"))
    target = float(conf.get("TARGET_SEC", "1.0"))

    # ---- 판정
    if n == 0:
        if not ev.ok():
            print(f"기준 측정 실패: {ev.failure()} → 서버 환경을 먼저 확인하세요.")
            return 1
        base = ev.text("applied.cfg")
        (STATE / "best.cfg").write_text(base, encoding="utf-8")
        st["best_median"] = ev.median
        hist = [{"iter": 0, "origin": "baseline", "changes": [], "verdict": "baseline",
                 "median": ev.median, "ksize": ev.meta.get("bzimage_bytes")}]
        print(f"기준: {ev.median}초")
    else:
        h = next((x for x in hist if x["iter"] == n), None)
        if h is None:
            print(f"history에 반복 {n}이 없습니다. 순서를 확인하세요.")
            return 1
        if h.get("cfg_sha") and h["cfg_sha"] != ev.meta.get("cfg_sha256"):
            print("경고: 서버에 적용된 cfg가 로컬에서 만든 cfg와 다릅니다.")
        h["ksize"] = ev.meta.get("bzimage_bytes")
        h["median"] = ev.median
        if ev.ok() and ev.median <= st["best_median"] + tol:
            h["verdict"] = "accepted"
            improved = ev.median < st["best_median"] - 0.01
            st["no_improve"] = 0 if improved else st["no_improve"] + 1
            st["best_median"] = min(st["best_median"], ev.median)
            (STATE / "best.cfg").write_text(ev.text("applied.cfg"), encoding="utf-8")
            print(f"채택: {ev.median}초 (최선 {st['best_median']}초)")
        elif ev.ok():
            h["verdict"] = "rejected"
            h["note"] = f"악화 {ev.median}초"
            st["no_improve"] += 1
            print(f"롤백(악화): {ev.median}초 > 최선 {st['best_median']}초 + {tol}")
        else:
            h["verdict"] = "failed"
            h["note"] = ev.failure()
            ch = h.get("changes", [])
            print(f"롤백(실패: {ev.failure()}), 변경 {len(ch)}개")
            if len(ch) > 1:
                half = len(ch) // 2
                st["pending"] = [ch[:half], ch[half:]] + st["pending"]
                print(f"  → 반으로 나눠 재시도 ({half} + {len(ch) - half})")
            elif len(ch) == 1:
                c = ch[0]
                with (STATE / "blocklist.txt").open("a", encoding="utf-8") as f:
                    f.write(f"CONFIG_{norm_sym(c['symbol'])}={c['value']}  # 반복 {n}: {ev.failure()}\n")
                print(f"  → 원인 확정, 금지 목록에 추가: CONFIG_{c['symbol']}={c['value']}")
                rules = load_rules()

        if h["verdict"] == "accepted" and st["best_median"] <= target:
            save_json(STATE / "history.json", hist)
            save_json(STATE / "state.json", st)
            print(f"목표 달성: {st['best_median']}초 ≤ {target}초. 최종 cfg: {STATE / 'best.cfg'}")
            return 0
        if st["no_improve"] >= int(conf.get("NO_IMPROVE_LIMIT", "3")) and not st["pending"]:
            save_json(STATE / "history.json", hist)
            save_json(STATE / "state.json", st)
            print(f"개선 없는 반복 {st['no_improve']}회 → 종료. 최선 {st['best_median']}초")
            return 0

    # 끄기 가능성 지도: 채택된 설정의 지도를 기준으로 사용
    if n == 0 or (hist and hist[-1].get("verdict") == "accepted"):
        if ev.map:
            save_json(STATE / "best_map.json", ev.map)
    elif (STATE / "best_map.json").exists():
        ev.map_by = {d["symbol"]: d for d in load_json(STATE / "best_map.json", [])}

    best_text = (STATE / "best.cfg").read_text(encoding="utf-8")

    # ---- 다음 변경 결정
    origin, report, extra_out = "", [], {}
    if st["pending"]:
        changes = st["pending"].pop(0)
        origin = "bisect"
        report.append(f"분할 재시도: 이전 실패 묶음의 일부 {len(changes)}개 (LLM 호출 없음)")
    else:
        common = ("[규칙 rules.txt]\n" + (ROOT / "rules.txt").read_text(encoding="utf-8") +
                  "\n\n[금지 목록 (실패 확정)]\n" + ((STATE / "blocklist.txt").read_text(encoding="utf-8")
                                              if (STATE / "blocklist.txt").exists() else "없음") +
                  "\n\n[이력]\n" + history_table(hist))
        if n == 0:
            origin = "initial"
            user = (common + "\n\n[기준 cfg (Yocto 기본 위에 적용된 항목)]\n" + best_text +
                    "\n\n" + evidence_block(ev, conf) +
                    "\n\n[요청]\n명세를 만족하는 최소 복구 커널이 되도록, 기준 설정 위에 덮어쓸 cfg 항목 전체를 제출하라. "
                    "지도에서 켜진 옵션 중 명세상 불필요한 것은 모두 끄고, 끄는 방법은 지도의 분류를 따르라.")
            out = call_claude(conf, user, TOOL_INITIAL, run_dir)
            raw = out.get("cfg", [])
            limit = None
        else:
            origin = "llm"
            user = (common + "\n\n[현재 최선 cfg]\n" + best_text + "\n\n[이번 반복 " + str(n) + " 결과]\n" +
                    evidence_block(ev, conf) +
                    f"\n\n[요청]\n현재 최선 cfg에 적용할 다음 변경을 최대 {conf.get('MAX_CHANGES', '15')}개 제출하라. "
                    "효과가 큰 공백 구간부터 다루고, 이번 결과가 실패/악화였다면 그 원인을 analysis에 먼저 적어라.")
            out = call_claude(conf, user, TOOL_IMPROVE, run_dir)
            raw = out.get("changes", [])
            limit = int(conf.get("MAX_CHANGES", "15"))
        changes, report = check_changes(raw, ev, rules, limit)
        extra_out = out
        if out.get("lesson_candidates"):
            with (STATE / "lesson_candidates.txt").open("a", encoding="utf-8") as f:
                for l in out["lesson_candidates"]:
                    f.write(f"[반복 {n}] {l}\n")

    if not changes:
        print("적용할 변경이 없습니다. 보고 내용을 확인하세요:\n" + "\n".join(report))
        save_json(STATE / "history.json", hist)
        save_json(STATE / "state.json", st)
        return 1

    header = f"# ===== iteration {nxt} ({origin}) {datetime.now():%Y-%m-%d %H:%M} ====="
    new_cfg = merge(best_text, changes, header)
    cfg_path = OUT / f"cfg_{nxt}.cfg"
    cfg_path.write_text(new_cfg, encoding="utf-8")
    sha = hashlib.sha256(new_cfg.encode()).hexdigest()[:16]

    # 사람이 읽는 변경 요약
    reasons = {norm_sym(c["symbol"]): c for c in (extra_out.get("changes") or extra_out.get("cfg") or [])}
    lines = [f"반복 {nxt} ({origin})  변경 {len(changes)}개", ""]
    for c in changes:
        r = reasons.get(norm_sym(c["symbol"]), {})
        lines.append(f"{cfg_line(norm_sym(c['symbol']), c['value'])}")
        if r:
            lines.append(f"    이유: {r.get('reason', '')}  근거: {r.get('evidence', '')}  위험: {r.get('risk', '')}")
    if report:
        lines += ["", "[규칙 검사]"] + report
    for a in extra_out.get("analysis", []):
        lines.append(f"[분석] {a.get('gap')}: {a.get('cause')}")
    if extra_out.get("source_patch_needed"):
        lines += ["", "[소스 수정 필요]"] + [f"{s['symbol']}: {s.get('reason', '')}" for s in extra_out["source_patch_needed"]]
    if extra_out.get("cmdline"):
        lines += ["", "[커맨드라인 제안 (자동 적용 안 함)]"] + extra_out["cmdline"]
    (OUT / f"changes_{nxt}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (run_dir / "changes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    hist.append({"iter": nxt, "origin": origin, "changes": changes, "cfg_sha": sha})
    save_json(STATE / "history.json", hist)
    save_json(STATE / "state.json", st)
    print("\n".join(lines[:40]))
    print(f"\n서버로 옮길 파일: {cfg_path}")
    print(f"서버에서 실행: ./server_step.sh {nxt} cfg_{nxt}.cfg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
