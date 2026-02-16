# Contributing

Thanks for contributing. This repo is a protocol-level WhatsApp Web client, so please be mindful of safety and
abuse risks.

## Ground Rules

- Do not commit any WhatsApp auth state, QR codes, or account data. The default `.gitignore` excludes `auth/`.
- Do not add features that facilitate spam/automation at scale.
- Keep runtime dependencies minimal. Dev-only dependencies are fine.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality Gates

Run these locally before opening a PR:

```bash
ruff check .
ruff format .
mypy src/pyaileys
pytest -q
```

CI runs the same checks on Python 3.11-3.13.

## Generated Files

Two parts of the repo are generated and intentionally excluded from linting/type-checking:

- `src/pyaileys/wabinary/constants.py` (token tables vendored from Baileys)
- `src/pyaileys/proto/WAProto_pb2.py` (protoc output)

To regenerate:

```bash
python3 tools/gen_wabinary_constants.py
python3 tools/patch_waproto_for_protoc.py
protoc -Iproto --python_out=src/pyaileys/proto proto/WAProto.proto
```

## API Design Guidelines

- Prefer `async` APIs at the public surface.
- Keep the user-facing API stable in `src/pyaileys/client.py` and treat lower layers as internal.
- Be conservative with breaking changes (even pre-1.0): changes should be justified and documented.

## Reporting Bugs

Please include:

- Python version
- OS
- `pyaileys` version
- minimal repro steps
- logs with sensitive material redacted (JIDs are usually fine, auth keys are not)

