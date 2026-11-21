#!/usr/bin/env bash
# Records docs/dashboard.gif without screen recording:
#   1. runs scripts/demo-dashboard.sh (stack + one chaos round)
#   2. once the harness has cleared the tables, headless Chromium (Playwright)
#      screenshots http://localhost:8080/ once per second until the run is verified
#   3. ffmpeg turns the frames into a palette-optimised GIF (1000 px wide,
#      ~55 s, caption on the first frames)
# Playwright and ffmpeg live in $TOOLS_DIR, never in the project. Dev use only.
# Needs: node + npm, ./mvnw package -DskipTests, docker compose build.
# On Windows, ffmpeg is downloaded into $TOOLS_DIR if it is not on PATH.
set -euo pipefail
cd "$(dirname "$0")/../.."
TOOLS=${TOOLS_DIR:-$HOME/.cache/scan-queue-gif-tools}
WORK=${WORK_DIR:-$(mktemp -d)}
OUT=${OUT:-docs/dashboard.gif}
TARGET_SECONDS=${TARGET_SECONDS:-55}
PLAYWRIGHT_VERSION=1.64.1
mkdir -p "$TOOLS" "$WORK"

# ---- tools (outside the repo) ----
if [ ! -d "$TOOLS/node_modules/playwright" ]; then
  echo "installing playwright@$PLAYWRIGHT_VERSION into $TOOLS"
  (cd "$TOOLS" && npm init -y > /dev/null && npm install --silent "playwright@$PLAYWRIGHT_VERSION" \
     && npx playwright install --only-shell chromium)
fi
FFMPEG=$(command -v ffmpeg || true)
if [ -z "$FFMPEG" ]; then
  FFMPEG=$(find "$TOOLS" -name 'ffmpeg.exe' -o -name ffmpeg -type f 2>/dev/null | head -1)
fi
if [ -z "$FFMPEG" ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      echo "downloading ffmpeg (gyan.dev release essentials) into $TOOLS"
      curl -sSL --retry 5 --retry-all-errors --retry-delay 3 -o "$TOOLS/ffmpeg.zip" https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip
      unzip -q -o "$TOOLS/ffmpeg.zip" -d "$TOOLS/ffmpeg" && rm "$TOOLS/ffmpeg.zip"
      FFMPEG=$(find "$TOOLS/ffmpeg" -name ffmpeg.exe | head -1) ;;
    *) echo "install ffmpeg first (e.g. apt install ffmpeg / brew install ffmpeg)"; exit 1 ;;
  esac
fi
echo "ffmpeg: $FFMPEG"

# ---- run the demo, capture once the tables are cleared ----
rm -rf "$WORK/frames" "$WORK/go" "$WORK/stop"
# Browser starts first and loads the page; it takes frames only after "go".
NODE_PATH="$TOOLS/node_modules" node scripts/dev/capture-dashboard.cjs \
  http://localhost:8080/ "$WORK/frames" "$WORK/go" "$WORK/stop" 400 &
CAP=$!
# The harness holds 5 s on the zeroed dashboard after clearing the tables.
WAIT=0 PAUSE_AFTER_RESET_MS=5000 bash scripts/demo-dashboard.sh > "$WORK/demo.log" 2>&1 &
DEMO=$!
until grep -q "run 1: tables cleared" "$WORK/demo.log" 2>/dev/null; do
  kill -0 $DEMO 2>/dev/null || { cat "$WORK/demo.log"; touch "$WORK/stop"; exit 1; }
  sleep 0.1
done
touch "$WORK/go"
echo "tables cleared: capturing"
# keep capturing through the drain so the last frames show the verified end state
until grep -q "checks" "$WORK/demo.log" 2>/dev/null; do
  kill -0 $DEMO 2>/dev/null || break
  sleep 1
done
sleep 4
touch "$WORK/stop"
wait $CAP
wait $DEMO || true
grep -E "checks|uploads done|chaos stopped" "$WORK/demo.log" || true

# ---- frames -> GIF ----
N=$(ls "$WORK/frames" | wc -l)
FPS=$(awk -v n="$N" -v t="$TARGET_SECONDS" 'BEGIN { f = n / t; if (f < 1) f = 1; printf "%.3f", f }')
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) FONT="C\\:/Windows/Fonts/segoeuib.ttf" ;;
  *) FONT=$(fc-match -f '%{file}' 'sans:bold' 2>/dev/null || echo /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf) ;;
esac
CAPTION="Chaos demo\\: workers being killed live"
FILTER="fps=$FPS,scale=1000:-1:flags=lanczos,drawtext=fontfile='$FONT':text='$CAPTION':fontsize=30:fontcolor=white:box=1:boxcolor=black@0.72:boxborderw=16:x=(w-text_w)/2:y=h-text_h-36:enable='lt(t,4)',split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle"
mkdir -p "$(dirname "$OUT")"
"$FFMPEG" -hide_banner -loglevel error -y -framerate "$FPS" -i "$WORK/frames/frame-%04d.png" \
  -filter_complex "$FILTER" -loop 0 "$OUT"
echo "frames: $N, playback ${FPS} fps (~$(awk -v n="$N" -v f="$FPS" 'BEGIN{printf "%.0f", n/f}') s), $OUT: $(du -h "$OUT" | cut -f1)"
echo "work dir (frames, demo log): $WORK"
