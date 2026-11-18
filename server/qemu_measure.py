#!/usr/bin/env python3
"""
QEMU 자동 측정: 정상 부팅 → root 로그인 → kexec 적재 확인 → 패닉 발생
→ 복구 커널 로그를 호스트 시각과 함께 저장 → (선택) 화면 캡처로 표시 확인.

외부 패키지 없이 표준 라이브러리만 사용 (회사 서버에서 pip 불필요).

사용:
  python3 qemu_measure.py --out DIR [--runs 3] [--config server_config.txt]
출력:
  DIR/boot_<i>.log      호스트 시각이 붙은 시리얼 로그
  DIR/screen_<i>.ppm    복구 후 화면 캡처 (SCREEN_CHECK=true일 때)
  DIR/measure.json      회차별 측정값과 상태
"""

from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import shlex
import signal
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TS_HOST = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) (.*)$")
TS_KERN = re.compile(r"\[\s*(\d+\.\d+)\]")
FRAME_DONE = "[cluster] first frame done"


def read_kv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class Serial:
    """QEMU 표준 입출력(-serial stdio)을 줄 단위로 읽고, 받은 시각을 붙여 기록."""

    def __init__(self, proc: subprocess.Popen, log_path: Path):
        self.proc = proc
        self.log = log_path.open("w", encoding="utf-8")
        self.sel = selectors.DefaultSelector()
        self.sel.register(proc.stdout, selectors.EVENT_READ)
        self.buf = b""
        self.recent = ""  # 프롬프트처럼 줄바꿈 없는 출력 검사용

    def send(self, text: str) -> None:
        self.proc.stdin.write(text.encode())
        self.proc.stdin.flush()

    def _pump(self, timeout: float) -> list[str]:
        lines: list[str] = []
        for _key, _ in self.sel.select(timeout):
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError("QEMU 출력 종료")
            stamp = now_str()
            self.buf += chunk
            while b"\n" in self.buf:
                raw, self.buf = self.buf.split(b"\n", 1)
                text = raw.decode("utf-8", "replace").rstrip("\r")
                self.log.write(f"{stamp} {text}\n")
                lines.append(text)
            self.recent = (self.recent + chunk.decode("utf-8", "replace"))[-512:]
        self.log.flush()
        return lines

    def expect(self, patterns: list[str], timeout: float) -> str | None:
        """patterns 중 하나가 나오면 그 패턴을 반환, 시간 초과면 None."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            lines = self._pump(min(0.2, max(0.0, deadline - time.monotonic())))
            text = "\n".join(lines) + "\n" + self.recent
            for p in patterns:
                if p in text:
                    self.recent = ""
                    return p
        return None

    def close(self) -> None:
        try:
            self._pump(0.1)
        except Exception:
            pass
        self.log.close()


def monitor_cmd(sock_path: str, cmd: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.recv(4096)  # 인사말
    s.sendall((cmd + "\n").encode())
    time.sleep(0.5)
    try:
        resp = s.recv(4096).decode("utf-8", "replace")
    except socket.timeout:
        resp = ""
    s.close()
    return resp


def ppm_center_color(path: Path) -> tuple[int, int, int] | None:
    data = path.read_bytes()
    parts = data.split(maxsplit=4)
    if len(parts) < 5 or parts[0] != b"P6":
        return None
    w, h = int(parts[1]), int(parts[2])
    pix = parts[4]
    off = ((h // 2) * w + (w // 2)) * 3
    return tuple(pix[off:off + 3]) if off + 3 <= len(pix) else None


def analyze_log(path: Path) -> dict:
    """호스트 시각 로그에서 측정값 계산.
    T0 = host(Run init 줄) - kernel(Run init 줄),  T_frame = T0 + kernel(first frame done)."""
    t_panic = t0 = t_init = t_frame = None
    in_recovery = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = TS_HOST.match(raw)
        if not m:
            continue
        host = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f").timestamp()
        body = m.group(2)
        k = TS_KERN.search(body)
        if t_panic is None and "Kernel panic" in body:
            t_panic = host
            continue
        if t_panic is not None and "] Linux version" in body:
            in_recovery = True
        if not in_recovery or not k:
            continue
        kt = float(k.group(1))
        if t0 is None and "as init process" in body:
            t0 = host - kt
            t_init = host
        if FRAME_DONE in body and t0 is not None:
            t_frame = t0 + kt
            break
    res = {"panic_to_t0": None, "t0_to_init": None, "init_to_frame": None, "panic_to_frame": None}
    if t_panic and t0:
        res["panic_to_t0"] = round(t0 - t_panic, 3)
        res["t0_to_init"] = round(t_init - t0, 3)
    if t_panic and t_frame:
        res["init_to_frame"] = round(t_frame - t_init, 3)
        res["panic_to_frame"] = round(t_frame - t_panic, 3)
    return res


def one_run(cfg: dict[str, str], out: Path, idx: int) -> dict:
    build = Path(cfg["BUILD_DIR"]).expanduser()
    img = build / cfg.get("IMAGE_DIR", "tmp/deploy/images/qemux86-64")
    qemu = build / cfg["QEMU_BIN"]
    mon = str(out / f"qmon_{idx}.sock")
    display = "sdl,show-cursor=on" if cfg.get("SHOW_DISPLAY", "false").lower() == "true" else "none"
    args = [
        str(qemu),
        "-device", "virtio-net-pci,netdev=net0,mac=52:54:00:12:35:02",
        "-netdev", "user,id=net0",
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0",
        "-drive", f"file={img / cfg['ROOTFS']},if=virtio,format=raw,snapshot=on",
        "-cpu", "IvyBridge", "-machine", "q35,i8042=off", "-smp", "4", "-m", "2048",
        "-serial", "stdio", "-serial", "null",
        "-monitor", f"unix:{mon},server,nowait",
        "-vga", "std", "-display", display,
        "-kernel", str(img / "bzImage"),
        "-append", cfg["NORMAL_CMDLINE"],
    ] + shlex.split(cfg.get("QEMU_EXTRA", ""))

    log_path = out / f"boot_{idx}.log"
    status = "ok"
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    ser = Serial(proc, log_path)
    try:
        if not ser.expect(["login:"], float(cfg.get("BOOT_TIMEOUT", "120"))):
            status = "normal_boot_timeout"
            return {"run": idx, "status": status}
        ser.send("root\n")
        if not ser.expect(["# "], 20):
            status = "login_failed"
            return {"run": idx, "status": status}

        # 부팅 스크립트가 kexec -p를 적재할 때까지 대기
        loaded = False
        for _ in range(int(cfg.get("KEXEC_WAIT", "30"))):
            ser.send("cat /sys/kernel/kexec_crash_loaded\n")
            hit = ser.expect(["\n1\r", "\n1\n", "\n0\r", "\n0\n"], 2)
            if hit and "1" in hit:
                loaded = True
                break
            time.sleep(1)
        if not loaded:
            status = "kexec_not_loaded"
            return {"run": idx, "status": status}

        ser.send("echo c > /proc/sysrq-trigger\n")
        if not ser.expect([FRAME_DONE], float(cfg.get("RECOVERY_TIMEOUT", "10"))):
            status = "recovery_timeout"

        if cfg.get("SCREEN_CHECK", "true").lower() == "true":
            time.sleep(0.3)
            ppm = out / f"screen_{idx}.ppm"
            try:
                monitor_cmd(mon, f"screendump {ppm}")
                time.sleep(0.5)
                color = ppm_center_color(ppm) if ppm.exists() else None
            except OSError as exc:
                color = None
                print(f"  화면 캡처 실패: {exc}")
            expect_rgb = tuple(int(x) for x in cfg.get("SCREEN_RGB", "255,0,0").split(","))
            screen_ok = color == expect_rgb
            if status == "ok" and not screen_ok:
                status = "screen_mismatch"
            return {"run": idx, "status": status, "screen_center": color}
        return {"run": idx, "status": status}
    except EOFError:
        return {"run": idx, "status": "qemu_exited"}
    finally:
        ser.close()
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(5)
        except Exception:
            os.killpg(proc.pid, signal.SIGKILL)
        if os.path.exists(mon):
            os.unlink(mon)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=None)
    ap.add_argument("--config", default=str(ROOT / "server_config.txt"))
    a = ap.parse_args()

    cfg = read_kv(Path(a.config))
    runs = a.runs or int(cfg.get("RUNS", "3"))
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    results = []
    for i in range(1, runs + 1):
        print(f"[측정 {i}/{runs}] QEMU 실행")
        r = one_run(cfg, out, i)
        if (out / f"boot_{i}.log").exists():
            r.update(analyze_log(out / f"boot_{i}.log"))
        print(f"  상태={r['status']}  패닉→첫 화면={r.get('panic_to_frame')}초")
        results.append(r)

    ok = [r["panic_to_frame"] for r in results if r["status"] == "ok" and r.get("panic_to_frame")]
    summary = {
        "runs": results,
        "success_count": len(ok),
        "median_panic_to_frame": round(statistics.median(ok), 3) if ok else None,
    }
    for key in ("panic_to_t0", "t0_to_init", "init_to_frame"):
        vals = [r[key] for r in results if r["status"] == "ok" and r.get(key) is not None]
        summary[f"median_{key}"] = round(statistics.median(vals), 3) if vals else None
    (out / "measure.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"중앙값 패닉→첫 화면: {summary['median_panic_to_frame']}초 (성공 {len(ok)}/{runs})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
