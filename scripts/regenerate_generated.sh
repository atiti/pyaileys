#!/usr/bin/env bash
set -euo pipefail

python3 tools/gen_wabinary_constants.py
python3 tools/patch_waproto_for_protoc.py
protoc -Iproto --python_out=src/pyaileys/proto proto/WAProto.proto

echo "done"

