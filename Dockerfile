FROM golang:1.25-alpine AS builder

ENV PACKAGES="curl build-base git bash file linux-headers eudev-dev"
RUN apk add --no-cache $PACKAGES;
WORKDIR /src/app
COPY . /src/app

# See https://github.com/CosmWasm/wasmvm/releases
# Download the correct version of libwasmvm for the given platform and verify checksum
ADD https://github.com/CosmWasm/wasmvm/releases/download/v2.2.4/libwasmvm_muslc.x86_64.a /lib/libwasmvm_muslc.x86_64.a
ADD https://github.com/CosmWasm/wasmvm/releases/download/v2.2.4/libwasmvm_muslc.aarch64.a /lib/libwasmvm_muslc.aarch64.a
RUN echo "70c989684d2b48ca17bbd55bb694bbb136d75c393c067ef3bdbca31d2b23b578 /lib/libwasmvm_muslc.x86_64.a" | sha256sum -c
RUN echo "27fb13821dbc519119f4f98c30a42cb32429b111b0fdc883686c34a41777488f /lib/libwasmvm_muslc.aarch64.a" | sha256sum -c

RUN  BUILD_TAGS=muslc LINK_STATICALLY=true  make build


# Final Image
FROM alpine:3.23

WORKDIR /qbtc_data
ENV HOME=/qbtc_data
COPY --from=builder /src/app/build/qbtcd /usr/bin/qbtcd
COPY --from=builder /src/app/build/bifrost /usr/bin/bifrost
RUN apk add -U --no-cache ca-certificates

CMD ["qbtcd", "start", "--home", "/qbtc_data/.qbtcd"]
