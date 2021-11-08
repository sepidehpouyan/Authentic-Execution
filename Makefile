REPO          ?= authexec/event-manager-trustzone
TAG           ?= latest
OPTEE_DIR     ?= /opt/optee

build:
	docker build -t $(REPO):$(TAG) .

push: login
	docker push $(REPO):$(TAG)

pull:
	docker pull $(REPO):$(TAG)

run: check_port
	docker run --rm -v $(OPTEE_DIR):/opt/optee -e PORT=$(PORT) -p $(PORT):1236 --name event-manager-$(PORT) $(REPO):$(TAG)

login:
	docker login

check_port:
	@test $(PORT) || (echo "PORT variable not defined. Run make <target> PORT=<port>" && return 1)