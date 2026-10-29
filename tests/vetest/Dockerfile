# qbtcd image for the vote-extension scenario harness (tests/vetest/run.sh).
#
# Default: Docker downloads the Go modules itself. With `run.sh --vendor` the
# build context carries a vendor/ directory made on the host (`go mod vendor`)
# and VENDOR=1 makes the build use it, for machines where the Docker build
# cannot reach the Go module proxy. Only ./cmd/qbtcd is built.
#
#   docker build -f tests/vetest/Dockerfile -t qbtcd-vetest:normal <ctx>
#   docker build -f tests/vetest/Dockerfile --build-arg EXTRA_TAGS=vetest_malicious \
#       -t qbtcd-vetest:malicious <ctx>
FROM golang:1.26-alpine AS builder

ARG EXTRA_TAGS=""
ARG VENDOR=0
ENV PACKAGES="build-base git bash file linux-headers eudev-dev"
RUN apk add --no-cache $PACKAGES

# See https://github.com/CosmWasm/wasmvm/releases (same pinned version and
# checksums as the repository Dockerfile). Fetched before the sources so the
# layer is cached across builds.
ADD https://github.com/CosmWasm/wasmvm/releases/download/v2.2.4/libwasmvm_muslc.x86_64.a /lib/libwasmvm_muslc.x86_64.a
ADD https://github.com/CosmWasm/wasmvm/releases/download/v2.2.4/libwasmvm_muslc.aarch64.a /lib/libwasmvm_muslc.aarch64.a
RUN echo "70c989684d2b48ca17bbd55bb694bbb136d75c393c067ef3bdbca31d2b23b578 /lib/libwasmvm_muslc.x86_64.a" | sha256sum -c
RUN echo "27fb13821dbc519119f4f98c30a42cb32429b111b0fdc883686c34a41777488f /lib/libwasmvm_muslc.aarch64.a" | sha256sum -c

WORKDIR /src/app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    if [ "$VENDOR" != 1 ]; then go mod download; fi
COPY . /src/app

ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ "$VENDOR" = 1 ]; then export GOFLAGS=-mod=vendor GOTOOLCHAIN=local; fi && \
    LDFLAGS='-X github.com/cosmos/cosmos-sdk/version.Name=qbtc -X github.com/cosmos/cosmos-sdk/version.AppName=qbtcd -X github.com/cosmos/cosmos-sdk/version.Version=vetest -linkmode=external -extldflags "-Wl,-z,muldefs -static"' && \
    go build -tags "netgo muslc ${EXTRA_TAGS}" -ldflags "$LDFLAGS" -o /out/qbtcd ./cmd/qbtcd

# Final image
FROM alpine:3.23
WORKDIR /qbtc_data
ENV HOME=/qbtc_data
COPY --from=builder /out/qbtcd /usr/bin/qbtcd
RUN apk add -U --no-cache ca-certificates

CMD ["qbtcd", "start", "--home", "/qbtc_data/.qbtc"]
