.PHONY: build release

VERSION=usenix-eval-jun2023

build:
	docker build -t greenhouse:${VERSION} .

release:
	docker build --no-cache -t greenhouse:${VERSION} .
