.PHONY: build release

VERSION=3.4-haccs-1.0

build:
	docker build -t gh_routersploit .

test: build
	docker tag gh_routersploit capysix/gh2routersploit:${VERSION}
	docker push capysix/gh2routersploit:${VERSION}

rhelmot: build
	docker tag gh_routersploit docker.shellphish.net/rhelmot/gh2routersploit:${VERSION}
	docker push docker.shellphish.net/rhelmot/gh2routersploit:${VERSION}


latest: build
	docker tag gh_routersploit docker.shellphish.net/haccs/gh2routersploit:${VERSION}
	docker push docker.shellphish.net/haccs/gh2routersploit:${VERSION}
