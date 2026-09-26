.PHONY: install test lint demo serve docker verify

install:
	pip install -e ".[dev]"

test:
	pytest -q --cov=ash --cov-report=term-missing

lint:
	ruff check ash tests scripts && ruff format --check ash tests scripts

fmt:
	ruff check --fix ash tests scripts && ruff format ash tests scripts

demo:
	python -m scripts.demo

serve:
	ash serve --port 8080

docker:
	docker build -t agentic-soc-harness:local .

verify:
	ash verify-audit
