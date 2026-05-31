SHELL := /bin/bash

.PHONY: lint test install

lint:
	shellcheck monitor.sh

test:
	bash tests/run.sh

install:
	bash install.sh
