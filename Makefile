.PHONY: docker-build-pdfsign docker-build-ca docker-push ci


ifndef VERSION
$(warning No VERSION found)
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
