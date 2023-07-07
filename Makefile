.PHONY: docker-build-pdfsign docker-build-ca docker-push ci vscode_venv vscode_pip vscode_packages vscode

PYTHON=$(shell which python)
PIPCOMPILE=pip-compile -v --upgrade --generate-hashes --allow-unsafe --index-url https://pypi.sunet.se/simple
PIPSYNC=pip-sync --index-url https://pypi.sunet.se/simple --python-executable $(PYTHON)

sync_deps:
	$(PIPSYNC) requirements.txt

ifndef VERSION
VERSION := latest                                                                                                                                                                                                                              
endif

DOCKER_TAG_PDFSIGN 	:= 	docker.sunet.se/dc4eu/pkcs11_pdfsign:$(VERSION)
DOCKER_TAG_CA 		:= 	docker.sunet.se/dc4eu/pkcs11_ca:$(VERSION)

docker-build-pdfsign:
	$(info building docker image $(DOCKER_TAG_PDFSIGN))
	docker build --tag $(DOCKER_TAG_PDFSIGN) --file containers/pdfsign/Dockerfile .

docker-build-ca:
	$(info building docker image $(DOCKER_TAG_CA) )
	docker build --tag $(DOCKER_TAG_CA) --file containers/ca/Dockerfile .

docker-build: docker-build-pdfsign docker-build-ca

docker-push:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_PDFSIGN)
	docker push $(DOCKER_TAG_CA)

ci: docker-build docker-push

vscode_venv:
	$(info Creating virtualenv in devcontainer)

vscode_pip: vscode_venv
	$(info Installing pip packages in devcontainer)
	pip3 install --upgrade pip
	pip3 install pip-tools
	pip3 install -r requirements.txt

vscode_packages:
	$(info Installing apt packages in devcontainer)
	sudo apt-get update
	sudo apt install -y docker.io

# This target is used by the devcontainer.json to configure the devcontainer
vscode: vscode_packages vscode_pip sync_deps