# Development and build image: Go toolchain plus the clang/libbpf/bpftool
# toolchain needed to compile eBPF CO-RE programs.
FROM golang:1.26-bookworm AS dev
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev bpftool make jq \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

FROM dev AS build
COPY . .
RUN make generate-local build-local

FROM debian:bookworm-slim AS runtime
COPY --from=build /src/bin/edr-agent /usr/local/bin/edr-agent
COPY rules /etc/edr/rules
ENTRYPOINT ["/usr/local/bin/edr-agent"]
CMD ["--rules", "/etc/edr/rules"]
