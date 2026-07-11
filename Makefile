PY ?= python3
.PHONY: setup doctor init-db demo test benchmark web clean

setup:
	$(PY) -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

doctor:
	$(PY) -m cver doctor

init-db:
	$(PY) -m cver init-db

demo:
	$(PY) -m cver demo

test:
	$(PY) -m unittest discover -s tests -p 'test_*.py'

benchmark:
	$(PY) -m cver benchmark --profile benchmark

web:
	$(PY) -m cver web --host 0.0.0.0 --port 8000

clean:
	rm -rf outputs data/*.db __pycache__ .pytest_cache */__pycache__ */*/__pycache__
