FROM golang:1.26-alpine AS builder

ENV PACKAGES="curl build-base git bash file linux-headers eudev-dev"
RUN apk add --no-cache $PACKAGES;
WORKDIR /src/app
COPY . /src/app

RUN go mod download
RUN LINK_STATICALLY=true make build


# Final Image
FROM alpine:3.23

WORKDIR /qbtc_data
ENV HOME=/qbtc_data
COPY --from=builder /src/app/build/qbtcd /usr/bin/qbtcd
RUN apk add -U --no-cache ca-certificates

CMD ["qbtcd", "start", "--home", "/qbtc_data/.qbtc"]
