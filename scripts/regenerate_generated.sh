#!/usr/bin/env bash
set -euo pipefail

BAILEYS_DIR_ARG="${1:-${BAILEYS_DIR:-}}"
if [[ -n "${BAILEYS_DIR_ARG}" ]]; then
  python3 tools/gen_wabinary_constants.py --baileys "${BAILEYS_DIR_ARG}"
else
  python3 tools/gen_wabinary_constants.py
fi
python3 tools/patch_waproto_for_protoc.py
protoc -Iproto --python_out=src/pyaileys/proto proto/WAProto.proto

echo "done"
