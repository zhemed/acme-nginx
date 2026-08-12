.PHONY: build check test

build:
	bash scripts/build.sh

check:
	bash scripts/build.sh --check

test:
	bash tests/verify.sh
