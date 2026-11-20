# Host targets run everything inside the dev container, so no Go or clang
# toolchain is required on the host. "*-local" targets run inside it.

IMAGE      ?= edr-dev
RUNTIME    ?= edr-agent
GOCACHE_VOL = edr-gocache
DOCKER_RUN  = docker run --rm -v $(CURDIR):/src -v $(GOCACHE_VOL):/root/.cache -w /src
PRIV_RUN    = $(DOCKER_RUN) --privileged -v /sys/kernel/btf:/sys/kernel/btf:ro

BPF_DIR = internal/sensor/ebpf/bpf

.PHONY: image build test generate run e2e image-runtime \
        generate-local build-local test-local e2e-local

image:
	docker build --target dev -t $(IMAGE) .

generate: image
	$(DOCKER_RUN) $(IMAGE) make generate-local

build: image
	$(DOCKER_RUN) $(IMAGE) make generate-local build-local

test: image
	$(DOCKER_RUN) $(IMAGE) make generate-local test-local

run: build
	$(PRIV_RUN) -it $(IMAGE) ./bin/edr-agent --rules rules $(ARGS)

e2e: build
	$(PRIV_RUN) $(IMAGE) make e2e-local

image-runtime:
	docker build --target runtime -t $(RUNTIME) .

# ---- inside the container ----

generate-local:
	@test -f $(BPF_DIR)/vmlinux.h || bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/vmlinux.h
	go generate ./internal/sensor/ebpf/...

build-local:
	CGO_ENABLED=0 go build -o bin/edr-agent ./cmd/edr-agent

test-local:
	go vet ./...
	go test ./...

e2e-local:
	go test -tags e2e -count=1 -v ./test/e2e/...
	./test/e2e/agent_e2e.sh
