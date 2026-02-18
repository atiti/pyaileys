#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run end-to-end smoke tests against examples/simple_cli.py and a real WhatsApp account.

Usage:
  tools/e2e_smoke.sh --jid <target_jid> [options]

Options:
  --jid <jid>        Target chat JID for send/history tests (required)
  --auth <dir>       Auth directory (default: ./auth)
  --cli <path>       CLI script path (default: examples/simple_cli.py)
  --python <path>    Python executable (default: .venv/bin/python, fallback: python3)
  --timeout <sec>    Per-command wait timeout (default: 25)
  --keep-tmp         Keep temp fixtures/downloads folder
  -h, --help         Show this help

Examples:
  tools/e2e_smoke.sh --jid 4527148803@s.whatsapp.net
  tools/e2e_smoke.sh --jid 98183136948407@lid --auth ./auth --timeout 35
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH="./auth"
CLI="examples/simple_cli.py"
TIMEOUT="25"
KEEP_TMP="0"
JID=""
PYTHON_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jid)
      JID="${2:-}"
      shift 2
      ;;
    --auth)
      AUTH="${2:-}"
      shift 2
      ;;
    --cli)
      CLI="${2:-}"
      shift 2
      ;;
    --python)
      PYTHON_BIN="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT="${2:-}"
      shift 2
      ;;
    --keep-tmp)
      KEEP_TMP="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$JID" ]]; then
  echo "--jid is required" >&2
  usage >&2
  exit 2
fi

if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 2
fi

AUTH_ABS="$(cd "$ROOT" && cd "$(dirname "$AUTH")" && pwd)/$(basename "$AUTH")"
CLI_ABS="$(cd "$ROOT" && cd "$(dirname "$CLI")" && pwd)/$(basename "$CLI")"

if [[ ! -d "$AUTH_ABS" ]]; then
  echo "Auth directory not found: $AUTH_ABS" >&2
  exit 2
fi

if [[ ! -f "$CLI_ABS" ]]; then
  echo "CLI script not found: $CLI_ABS" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pyaileys-e2e.XXXXXX")"
cleanup() {
  if [[ "$KEEP_TMP" == "1" ]]; then
    echo "kept temp dir: $TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

echo "Running smoke test"
echo "- python: $PYTHON_BIN"
echo "- cli:    $CLI_ABS"
echo "- auth:   $AUTH_ABS"
echo "- jid:    $JID"
echo "- tmp:    $TMP_DIR"

"$PYTHON_BIN" - "$CLI_ABS" "$AUTH_ABS" "$JID" "$TIMEOUT" "$TMP_DIR" <<'PY'
from __future__ import annotations

import base64
from contextlib import suppress
import os
import re
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Check:
    status: str
    name: str
    detail: str = ""


class CliSession:
    def __init__(self, cli_path: str, auth_dir: str) -> None:
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-u", cli_path, "--auth", auth_dir, "--no-qr-file"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            env=env,
        )
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self._stdin = self.proc.stdin
        self._stdout = self.proc.stdout
        self._buf = ""

    @property
    def output(self) -> str:
        return self._buf

    def _pump(self, wait_s: float = 0.2) -> None:
        if self.proc.poll() is not None and self._stdout.closed:
            return
        fd = self._stdout.fileno()
        end = time.monotonic() + max(wait_s, 0.0)
        while True:
            now = time.monotonic()
            timeout = max(0.0, end - now)
            if timeout == 0 and now >= end:
                break
            r, _, _ = select.select([fd], [], [], timeout)
            if not r:
                break
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            self._buf += chunk.decode("utf-8", errors="replace")
            if time.monotonic() >= end:
                break

    def wait_for(self, pattern: str, *, start: int = 0, timeout_s: float = 25.0) -> re.Match[str]:
        rx = re.compile(pattern, re.S | re.M)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self._pump(0.25)
            m = rx.search(self._buf, pos=start)
            if m:
                return m
            if self.proc.poll() is not None:
                break
        tail = self._buf[max(0, len(self._buf) - 1200) :]
        raise TimeoutError(f"pattern not found: {pattern!r}\n--- output tail ---\n{tail}")

    def send(self, cmd: str) -> int:
        marker = len(self._buf)
        self._stdin.write((cmd + "\n").encode("utf-8"))
        self._stdin.flush()
        return marker

    def close(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.send("quit")
            self.proc.wait(timeout=8)
        except Exception:
            with suppress(Exception):
                self.proc.kill()
            with suppress(Exception):
                self.proc.wait(timeout=3)


def write_fixtures(tmp: Path) -> tuple[dict[str, Path], bool, str]:
    paths: dict[str, Path] = {}
    paths["png"] = tmp / "smoke.png"
    paths["doc"] = tmp / "smoke_doc.png"
    paths["vcard1"] = tmp / "contact1.vcf"
    paths["vcard2"] = tmp / "contact2.vcf"

    png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+nD1cAAAAASUVORK5CYII="
    png_bytes = base64.b64decode(png_b64.encode("ascii"))
    paths["png"].write_bytes(png_bytes)
    paths["doc"].write_bytes(png_bytes)

    paths["vcard1"].write_text(
        "BEGIN:VCARD\nVERSION:3.0\nN:Smoke;One;;;\nFN:Codex Smoke One\nTEL;TYPE=CELL:+4511111111\nEND:VCARD\n",
        encoding="utf-8",
    )
    paths["vcard2"].write_text(
        "BEGIN:VCARD\nVERSION:3.0\nN:Smoke;Two;;;\nFN:Codex Smoke Two\nTEL;TYPE=CELL:+4522222222\nEND:VCARD\n",
        encoding="utf-8",
    )

    ffmpeg = shutil.which("ffmpeg")
    cwebp = shutil.which("cwebp")
    if not ffmpeg or not cwebp:
        return paths, False, "ffmpeg/cwebp not found"

    paths["ptt"] = tmp / "smoke.ogg"
    paths["video"] = tmp / "smoke.mp4"
    paths["sticker"] = tmp / "smoke.webp"
    try:
        # Prefer a valid ffmpeg-produced PNG for all media transforms.
        subprocess.run(
            [
                ffmpeg,
                "-y",
                "-f",
                "lavfi",
                "-i",
                "color=c=red:size=64x64",
                "-frames:v",
                "1",
                str(paths["png"]),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        paths["doc"].write_bytes(paths["png"].read_bytes())

        subprocess.run(
            [
                ffmpeg,
                "-y",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=1000:duration=1",
                "-c:a",
                "libopus",
                "-b:a",
                "24k",
                str(paths["ptt"]),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                ffmpeg,
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=64x64:rate=10",
                "-t",
                "1",
                "-pix_fmt",
                "yuv420p",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-crf",
                "32",
                str(paths["video"]),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [cwebp, "-quiet", "-q", "60", "-resize", "64", "64", str(paths["png"]), "-o", str(paths["sticker"])],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return paths, True, ""
    except Exception as e:
        return paths, False, str(e)


def main() -> int:
    if len(sys.argv) != 6:
        print("internal arg error", file=sys.stderr)
        return 2

    cli_path = sys.argv[1]
    auth_dir = sys.argv[2]
    jid = sys.argv[3]
    timeout_s = float(sys.argv[4])
    tmp = Path(sys.argv[5]).resolve()

    checks: list[Check] = []
    message_ids: dict[str, str] = {}
    ts = int(time.time())
    text_token = f"codex-smoke-text-{ts}"
    img_token = f"codex-smoke-img-{ts}"
    doc_token = f"codex-smoke-doc-{ts}"
    vid_token = f"codex-smoke-video-{ts}"
    loc_token = f"codex-smoke-location-{ts}"

    def add(status: str, name: str, detail: str = "") -> None:
        checks.append(Check(status=status, name=name, detail=detail))
        suffix = f" :: {detail}" if detail else ""
        print(f"[{status}] {name}{suffix}")

    def run_cmd(
        session: CliSession,
        *,
        name: str,
        cmd: str,
        expect: str,
        timeout_mult: float = 1.0,
    ) -> re.Match[str] | None:
        marker = session.send(cmd)
        try:
            m = session.wait_for(expect, start=marker, timeout_s=timeout_s * timeout_mult)
            add("PASS", name)
            return m
        except Exception as e:
            add("FAIL", name, str(e))
            return None

    fixtures, has_rich_media, rich_media_reason = write_fixtures(tmp)
    if has_rich_media:
        add("PASS", "fixture generation (rich media)")
    else:
        add("SKIP", "fixture generation (rich media)", rich_media_reason)

    session = CliSession(cli_path, auth_dir)
    fatal = False

    try:
        try:
            session.wait_for(r"connection:\s*open", timeout_s=max(20.0, timeout_s))
            add("PASS", "connect")
        except Exception as e:
            add("FAIL", "connect", str(e))
            fatal = True

        if fatal:
            return 1

        run_cmd(session, name="me", cmd="me", expect=r"me:\s*Contact\(")
        run_cmd(session, name="appsync", cmd="appsync", expect=r"\[app_state\.sync\]")
        run_cmd(session, name="status", cmd=f"status {jid}", expect=rf"-\s*{re.escape(jid)}:")
        run_cmd(session, name="ppic preview", cmd=f"ppic {jid} preview", expect=r"url:\s*https?://")
        run_cmd(session, name="typing on", cmd=f"typing {jid} on", expect=r"\bok\b")
        run_cmd(session, name="recording on", cmd=f"recording {jid} on", expect=r"\bok\b")

        m = run_cmd(
            session,
            name="send text",
            cmd=f"send {jid} {text_token}",
            expect=r"sent:\s*([A-Z0-9]+)",
        )
        if m:
            message_ids["text"] = m.group(1)

        m = run_cmd(
            session,
            name="send image",
            cmd=f"send_image {jid} {fixtures['png']} {img_token}",
            expect=r"sent:\s*([A-Z0-9]+)",
        )
        if m:
            message_ids["image"] = m.group(1)

        m = run_cmd(
            session,
            name="send document",
            cmd=f"send_doc {jid} {fixtures['doc']} {doc_token}",
            expect=r"sent:\s*([A-Z0-9]+)",
        )
        if m:
            message_ids["document"] = m.group(1)

        run_cmd(
            session,
            name="send location",
            cmd=f"send_location {jid} 47.4979 19.0402 {loc_token}",
            expect=r"sent:\s*([A-Z0-9]+)",
        )

        m = run_cmd(
            session,
            name="send vcard",
            cmd=f"send_vcard {jid} {fixtures['vcard1']} \"Codex Smoke One\"",
            expect=r"sent:\s*([A-Z0-9]+)",
        )
        if m:
            message_ids["vcard"] = m.group(1)

        run_cmd(
            session,
            name="send contacts",
            cmd=f"send_contacts {jid} {fixtures['vcard1']} {fixtures['vcard2']}",
            expect=r"sent:\s*([A-Z0-9]+)",
        )

        if has_rich_media:
            m = run_cmd(
                session,
                name="send ptt",
                cmd=f"send_ptt {jid} {fixtures['ptt']} 1",
                expect=r"sent:\s*([A-Z0-9]+)",
            )
            if m:
                message_ids["ptt"] = m.group(1)

            m = run_cmd(
                session,
                name="send video",
                cmd=f"send_video {jid} {fixtures['video']} {vid_token}",
                expect=r"sent:\s*([A-Z0-9]+)",
            )
            if m:
                message_ids["video"] = m.group(1)

            m = run_cmd(
                session,
                name="send sticker",
                cmd=f"send_sticker {jid} {fixtures['sticker']}",
                expect=r"sent:\s*([A-Z0-9]+)",
            )
            if m:
                message_ids["sticker"] = m.group(1)
        else:
            add("SKIP", "send ptt/video/sticker", rich_media_reason)

        run_cmd(session, name="chats", cmd="chats", expect=rf"{re.escape(jid.split('@', 1)[0])}")
        run_cmd(
            session,
            name="history contains sent text",
            cmd=f"history {jid} 80",
            expect=rf"{re.escape(text_token)}",
            timeout_mult=1.5,
        )
        run_cmd(
            session,
            name="history contains image caption",
            cmd=f"history {jid} 80",
            expect=rf"{re.escape(img_token)}",
            timeout_mult=1.5,
        )

        download_pairs: list[tuple[str, Path, Path]] = []

        if "image" in message_ids:
            out = tmp / "download_image.bin"
            m = run_cmd(
                session,
                name="download image",
                cmd=f"download {jid} {message_ids['image']} {out}",
                expect=rf"wrote\s+{re.escape(str(out))}\s+\((\d+)\s+bytes\)",
                timeout_mult=2.0,
            )
            if m:
                download_pairs.append(("image bytes match", fixtures["png"], out))

        if "document" in message_ids:
            out = tmp / "download_doc.bin"
            m = run_cmd(
                session,
                name="download document",
                cmd=f"download {jid} {message_ids['document']} {out}",
                expect=rf"wrote\s+{re.escape(str(out))}\s+\((\d+)\s+bytes\)",
                timeout_mult=2.0,
            )
            if m:
                download_pairs.append(("document bytes match", fixtures["doc"], out))

        if has_rich_media and "ptt" in message_ids:
            out = tmp / "download_ptt.ogg"
            m = run_cmd(
                session,
                name="download ptt",
                cmd=f"download {jid} {message_ids['ptt']} {out}",
                expect=rf"wrote\s+{re.escape(str(out))}\s+\((\d+)\s+bytes\)",
                timeout_mult=2.0,
            )
            if m:
                download_pairs.append(("ptt bytes match", fixtures["ptt"], out))

        if has_rich_media and "video" in message_ids:
            out = tmp / "download_video.mp4"
            m = run_cmd(
                session,
                name="download video",
                cmd=f"download {jid} {message_ids['video']} {out}",
                expect=rf"wrote\s+{re.escape(str(out))}\s+\((\d+)\s+bytes\)",
                timeout_mult=2.0,
            )
            if m:
                download_pairs.append(("video bytes match", fixtures["video"], out))

        if has_rich_media and "sticker" in message_ids:
            out = tmp / "download_sticker.webp"
            m = run_cmd(
                session,
                name="download sticker",
                cmd=f"download {jid} {message_ids['sticker']} {out}",
                expect=rf"wrote\s+{re.escape(str(out))}\s+\((\d+)\s+bytes\)",
                timeout_mult=2.0,
            )
            if m:
                download_pairs.append(("sticker bytes match", fixtures["sticker"], out))

        for name, src, out in download_pairs:
            try:
                if src.read_bytes() == out.read_bytes():
                    add("PASS", name)
                else:
                    add("FAIL", name, "downloaded bytes differ from source")
            except Exception as e:
                add("FAIL", name, str(e))

        run_cmd(session, name="typing off", cmd=f"typing {jid} off", expect=r"\bok\b")
        run_cmd(session, name="recording off", cmd=f"recording {jid} off", expect=r"\bok\b")
    finally:
        session.close()

    total = len(checks)
    passed = sum(1 for c in checks if c.status == "PASS")
    failed = sum(1 for c in checks if c.status == "FAIL")
    skipped = sum(1 for c in checks if c.status == "SKIP")
    print(f"\nSummary: total={total} pass={passed} fail={failed} skip={skipped}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
