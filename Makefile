.PHONY: test build

PYTHON ?= python3

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) -m py_compile src/ainglish_moderation/*.py

build:
	$(PYTHON) -m build
