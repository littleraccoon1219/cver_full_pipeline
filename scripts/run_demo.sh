#!/usr/bin/env bash
set -euo pipefail
python3 -m cver doctor
python3 -m cver init-db
python3 -m cver demo
python3 -m cver benchmark --profile benchmark
