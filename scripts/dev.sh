#!/usr/bin/env bash
# Dev/build script for unwindy.
# Pure stdlib: there is nothing to compile; "build" == run the test suite and a
# smoke test against the bundled sample.
set -euo pipefail
cd "$(dirname "$0")/.."

# Locate a Python interpreter (python / python3 / py launcher).
PY="${PYTHON:-}"
if [ -z "${PY}" ]; then
  for cand in python python3 py; do
    if command -v "${cand}" >/dev/null 2>&1; then PY="${cand}"; break; fi
  done
fi
if [ -z "${PY}" ]; then
  echo "error: no Python interpreter found (set PYTHON=/path/to/python)" >&2
  exit 1
fi

echo "== python =="
"${PY}" --version

echo
echo "== unit tests =="
"${PY}" -m unittest discover -s tests -p 'test_*.py' "$@"

echo
echo "== smoke: analyze sample =="
sample="$(ls samples/*.bin 2>/dev/null | head -n1 || true)"
if [ -n "${sample}" ]; then
  "${PY}" -m unwindy "${sample}" -s -q --no-color
else
  echo "(no sample binary found in samples/)"
fi

echo
echo "OK"
