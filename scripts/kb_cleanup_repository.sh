#!/usr/bin/env bash
set -euo pipefail

# Remove generated files from Git tracking without deleting the local virtual environment.
git rm -r --cached --ignore-unmatch .venv venv
find . -type d -name '__pycache__' -prune -exec rm -rf {} +
find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

echo "Repository cache cleanup complete. Review with: git status --short"
