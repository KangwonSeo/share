#!/bin/bash
# 서버 한 단계: cfg 적용 → 빌드 → 끄기 가능성 지도/불일치 → QEMU 측정 → evidence_N.zip
#
# 사용 (Yocto 환경을 source한 셸에서):
#   ./server_step.sh 0 baseline          # 단계 0: 기준 수집 (baseline.cfg 사용)
#   ./server_step.sh 3 cfg_3.cfg         # 반복 3
#
# 결과: out/evidence_<N>.zip  → 로컬 PC로 복사

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/server_config.txt"

if [ $# -ne 2 ]; then
    echo "사용: $0 <반복번호> <cfg 파일 | baseline>"
    exit 2
fi
ITER="$1"
if [ "$2" = "baseline" ]; then CFG="$HERE/baseline.cfg"; else CFG="$(realpath "$2")"; fi
[ -f "$CFG" ] || { echo "cfg 없음: $CFG"; exit 2; }
command -v bitbake >/dev/null || { echo "bitbake 없음: oe-init-build-env를 먼저 source 하세요"; exit 2; }

# server_config.txt 읽기 (KEY=VALUE)
while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    v="${v%\"}"; v="${v#\"}"
    printf -v "$k" '%s' "$v"
done < "$CONF"

EV="$HERE/out/iter_$ITER"
rm -rf "$EV"; mkdir -p "$EV"
cp "$CFG" "$EV/applied.cfg"
STATUS=ok

echo "[1/4] cfg 적용: $CFG -> $LAYER_CFG"
cp "$CFG" "$LAYER_CFG"

echo "[2/4] 빌드: $BUILD_TARGETS"
cd "$BUILD_DIR"
if ! bitbake $BUILD_TARGETS > "$EV/build.log" 2>&1; then
    STATUS=build_failed
    echo "  빌드 실패 (build.log 참고)"
fi

B_DIR="$(bitbake -e "$RECIPE" 2>/dev/null | sed -n 's/^B="\(.*\)"$/\1/p')"
if [ -f "$B_DIR/.config" ]; then cp "$B_DIR/.config" "$EV/final.config"; fi
KSIZE=0
if [ -f "$B_DIR/arch/x86/boot/bzImage" ]; then KSIZE=$(stat -c %s "$B_DIR/arch/x86/boot/bzImage"); fi

if [ "$STATUS" = ok ]; then
    echo "[3/4] 끄기 가능성 지도 / 불일치 분석"
    python3 "$HERE/kconfig_map.py" --out "$EV" --cfg "$EV/applied.cfg" --config "$CONF" \
        > "$EV/kconfig_map.log" 2>&1 || echo "  분석 실패 (kconfig_map.log 참고)"
    cat "$EV/kconfig_map.log"

    echo "[4/4] QEMU 측정"
    python3 "$HERE/qemu_measure.py" --out "$EV" --config "$CONF" || STATUS=measure_failed
    rm -f "$EV"/screen_*.ppm.tmp
fi

python3 - "$EV" "$ITER" "$STATUS" "$KSIZE" <<'EOF'
import hashlib, json, sys, zipfile
from pathlib import Path
ev, it, status, ksize = Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
meta = {"iter": int(it), "status": status, "bzimage_bytes": ksize,
        "cfg_sha256": hashlib.sha256((ev / "applied.cfg").read_bytes()).hexdigest()[:16]}
(ev / "meta.json").write_text(json.dumps(meta, indent=2))
if status == "build_failed":
    log = (ev / "build.log").read_text(errors="replace").splitlines()
    (ev / "build_tail.log").write_text("\n".join(log[-150:]) + "\n")
out = ev.parent / f"evidence_{it}.zip"
skip = {"build.log"}  # 전체 빌드 로그는 크므로 제외 (실패 시 build_tail.log 포함)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for p in sorted(ev.iterdir()):
        if p.is_file() and p.name not in skip and not p.name.endswith(".sock"):
            zf.write(p, p.name)
print(f"상태={status}  커널={ksize} bytes")
print(f"로컬로 옮길 파일: {out}")
EOF
