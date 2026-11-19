#!/usr/bin/env python3
"""
kconfiglib로 최종 .config를 분석한다.
  1) 끄기 가능성 지도 (map.txt / map.json): 켜진 옵션마다 끄는 방법
     DIRECT    : cfg에 '# CONFIG_X is not set'으로 바로 끌 수 있음
     SELECTED  : 다른 옵션이 select로 켬 → selector를 먼저 꺼야 함
     HIDDEN    : 프롬프트 조건이 거짓 (예: EXPERT 필요) → 조건 심볼을 켜야 끌 수 있음
     DERIVED   : 프롬프트 없음. depends/default 조건으로 자동 결정 (조건 쪽을 꺼야 함)
     CHOICE    : choice 멤버 → 다른 멤버를 y로
  2) 불일치 원인 (gaps.txt / gaps.json): 요청 cfg 값과 최종값이 다른 항목

필요: kconfiglib.py (같은 폴더, 파일 1개)
사용: python3 kconfig_map.py --out DIR [--cfg requested.cfg] [--config server_config.txt]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

CONFIG_LINE = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
NOT_SET_LINE = re.compile(r"^# CONFIG_([A-Za-z0-9_]+) is not set$")
AUTO_PREFIX = ("HAVE_", "ARCH_", "CC_", "AS_", "LD_", "TOOLS_", "GCC", "CLANG", "RUSTC",
               "PAHOLE", "OBJTOOL", "GENERIC_", "BUILDTIME_", "HAS_", "NEED_", "MMU_",
               "SPARSEMEM_VMEMMAP_ENABLE", "X86_NEED_", "FUNCTION_ALIGNMENT")


def read_kv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def parse_config(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        m, u = CONFIG_LINE.fullmatch(line), NOT_SET_LINE.fullmatch(line)
        if m:
            vals[m.group(1)] = m.group(2).strip('"')
        elif u:
            vals[u.group(1)] = "n"
    return vals


def bitbake_env(recipe: str, build_dir: Path) -> dict[str, str]:
    p = subprocess.run(["bitbake", "-e", recipe], cwd=build_dir, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if p.returncode != 0:
        raise RuntimeError("bitbake -e 실패:\n" + p.stdout[-3000:])
    want = {"S", "B", "ARCH", "KERNEL_CC", "KERNEL_LD", "PATH", "LINUX_VERSION"}
    env: dict[str, str] = {}
    for line in p.stdout.splitlines():
        if "=" not in line or line.startswith((" ", "\t", "#")):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        k, v = line.split("=", 1)
        if k in want:
            try:
                parts = shlex.split(v)
                env[k] = parts[0] if len(parts) == 1 else v.strip('"')
            except ValueError:
                env[k] = v.strip('"')
    return env


def setup_kconfig(cfg: dict[str, str]):
    env: dict[str, str] = {}
    if not cfg.get("KERNEL_SRC") or not cfg.get("FINAL_CONFIG"):
        env = bitbake_env(cfg.get("RECIPE", "linux-yocto-recovery"),
                          Path(cfg["BUILD_DIR"]).expanduser())
    srctree = Path(cfg.get("KERNEL_SRC") or env["S"]).expanduser().resolve()
    final = Path(cfg.get("FINAL_CONFIG") or (Path(env["B"]) / ".config")).expanduser().resolve()

    os.environ["srctree"] = str(srctree)
    arch = cfg.get("ARCH") or env.get("ARCH") or "x86"
    os.environ["ARCH"] = os.environ["SRCARCH"] = arch
    cc = cfg.get("CC") or env.get("KERNEL_CC") or "gcc"
    os.environ["CC"] = cc
    os.environ["LD"] = cfg.get("LD") or env.get("KERNEL_LD") or "ld"
    os.environ.setdefault("HOSTCC", "gcc")
    if env.get("PATH"):
        os.environ["PATH"] = env["PATH"] + os.pathsep + os.environ.get("PATH", "")
    try:
        ver = subprocess.run(shlex.split(cc) + ["--version"], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.splitlines()
        os.environ["CC_VERSION_TEXT"] = ver[0] if ver else ""
    except OSError:
        os.environ["CC_VERSION_TEXT"] = ""
    os.environ.setdefault("KERNELVERSION", env.get("LINUX_VERSION", ""))

    import kconfiglib
    cwd = os.getcwd()
    os.chdir(srctree)
    kconf = kconfiglib.Kconfig("Kconfig", warn=False)
    kconf.load_config(str(final))
    os.chdir(cwd)
    return kconfiglib, kconf, final


class Analyzer:
    def __init__(self, kl, kconf):
        self.kl, self.kconf = kl, kconf
        self.selectors: dict[str, list] = {}
        for s in kconf.unique_defined_syms:
            for target, cond, *_ in s.selects:
                self.selectors.setdefault(target.name, []).append((s, cond))

    def prompt(self, sym) -> str:
        for n in sym.nodes:
            if n.prompt:
                return n.prompt[0]
        return ""

    def active_selectors(self, sym) -> list:
        return [s for s, cond in self.selectors.get(sym.name, [])
                if s.tri_value > 0 and self.kl.expr_value(cond) > 0]

    def _positive_missing(self, expr) -> set[str]:
        """expr를 참으로 만들려면 y로 켜야 하는 심볼 (부정 !X 안의 심볼은 제외)."""
        kl = self.kl
        if kl.expr_value(expr) > 0:
            return set()
        if isinstance(expr, kl.Symbol):
            return set() if expr.is_constant else {expr.name}
        if isinstance(expr, kl.Choice) or not isinstance(expr, tuple):
            return set()
        op = expr[0]
        if op == kl.AND:
            return self._positive_missing(expr[1]) | self._positive_missing(expr[2])
        if op == kl.OR:
            left = self._positive_missing(expr[1])
            return left if left else self._positive_missing(expr[2])
        return set()  # NOT, 비교식: 켜서 해결할 수 없음

    def missing_for_prompt(self, sym) -> list[str]:
        miss = set()
        for n in sym.nodes:
            if n.prompt:
                miss |= self._positive_missing(n.prompt[1]) | self._positive_missing(n.dep)
        return sorted(miss)

    def classify(self, sym, depth: int = 0) -> dict:
        es = self.kl.expr_str
        loc = f"{sym.nodes[0].filename}:{sym.nodes[0].linenr}" if sym.nodes else ""
        d = {"symbol": sym.name, "value": sym.str_value, "prompt": self.prompt(sym), "loc": loc}
        sel = self.active_selectors(sym)
        if sel:
            d["class"] = "SELECTED"
            d["selected_by"] = [
                (self.classify(s, depth + 1) if depth < 2 else {"symbol": s.name, "value": s.str_value})
                for s in sel
            ]
        elif sym.choice is not None:
            d["class"] = "CHOICE"
            d["choice_members"] = [m.name for m in sym.choice.syms]
        elif any(n.prompt for n in sym.nodes):
            if sym.visibility > 0 and 0 in sym.assignable:
                d["class"] = "DIRECT"
            else:
                d["class"] = "HIDDEN"
                d["needs"] = self.missing_for_prompt(sym)
        else:
            d["class"] = "DERIVED"
            d["depends_on"] = es(sym.direct_dep)
            d["defaults"] = [f"{es(v)} if {es(c)}" for v, c, *_ in sym.defaults][:3]
        return d


def fmt(d: dict, indent: str = "") -> list[str]:
    head = f"{indent}{d['symbol']}={d['value']} {d.get('class', '')}"
    if d.get("prompt"):
        head += f' "{d["prompt"]}"'
    lines = [head]
    if d.get("class") == "HIDDEN":
        lines.append(f"{indent}  needs: {', '.join(d['needs']) or '?'}")
    elif d.get("class") == "DERIVED":
        lines.append(f"{indent}  depends: {d['depends_on']}  defaults: {'; '.join(d['defaults'])}")
    elif d.get("class") == "CHOICE":
        lines.append(f"{indent}  members: {', '.join(d['choice_members'])}")
    for s in d.get("selected_by", []):
        lines += fmt(s, indent + "  <- ")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cfg", help="요청 cfg (불일치 분석용)")
    ap.add_argument("--config", default=str(ROOT / "server_config.txt"))
    a = ap.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    cfg = read_kv(Path(a.config))
    kl, kconf, final_path = setup_kconfig(cfg)
    an = Analyzer(kl, kconf)

    # 1) 끄기 가능성 지도
    entries, lines = [], []
    for sym in kconf.unique_defined_syms:
        if sym.orig_type not in (kl.BOOL, kl.TRISTATE) or sym.tri_value == 0:
            continue
        has_prompt = any(n.prompt for n in sym.nodes)
        if not has_prompt and sym.name.startswith(AUTO_PREFIX):
            continue
        d = an.classify(sym)
        entries.append(d)
        lines += fmt(d)
    counts: dict[str, int] = {}
    for d in entries:
        counts[d["class"]] = counts.get(d["class"], 0) + 1
    (out / "map.json").write_text(json.dumps(entries, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "map.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"끄기 가능성 지도: {len(entries)}개 {counts}")

    # 2) 요청 cfg 대비 불일치
    if a.cfg:
        want = parse_config(Path(a.cfg))
        final = parse_config(final_path)
        gaps, glines = [], []
        for name, v in want.items():
            got = final.get(name, "n")
            if v == got:
                continue
            sym = kconf.syms.get(name)
            if sym is None or not sym.nodes:
                d = {"symbol": name, "class": "UNKNOWN_SYMBOL", "value": got}
                glines.append(f"{name}: 요청={v} 최종={got} UNKNOWN_SYMBOL (이 커널에 없음)")
            else:
                d = an.classify(sym)
                if v != "n" and got == "n":
                    d["class"] = "DEPENDS_UNMET" if kl.expr_value(sym.direct_dep) == 0 else "NOT_ENABLED"
                    d["depends_on"] = kl.expr_str(sym.direct_dep)
                glines.append(f"{name}: 요청={v} 최종={got}")
                glines += fmt(d, "  ")
                if d["class"] == "DEPENDS_UNMET":
                    glines.append(f"    depends: {d['depends_on']}")
            d["requested"] = v
            gaps.append(d)
        (out / "gaps.json").write_text(json.dumps(gaps, ensure_ascii=False, indent=1), encoding="utf-8")
        (out / "gaps.txt").write_text("\n".join(glines) + "\n", encoding="utf-8")
        print(f"불일치: {len(gaps)}개")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
