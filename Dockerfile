# Reproducible build for the KMIP gateway confidential container-app.
#
# Self-contained: the RA-TLS Go fork is fetched from its public release and the
# two sibling modules behind the go.mod `replace` directives (ra-tls-clients,
# enclave-vaults-client) are cloned + pinned, so the image builds from this repo
# alone (build context = repo root). Pin the refs for reproducibility; bump the
# ARGs when the siblings move.
ARG GO_RATLS_VERSION=privasys-v0.5.1-go1.26.5
ARG RA_TLS_CLIENTS_REF=64438d2593f26e4250bbb75e25240a5422876136
ARG ENCLAVE_VAULTS_CLIENT_REF=b34605cc81282e10dedbd3eecf6512f1e91ccebe

FROM alpine:3.21 AS toolchain
ARG GO_RATLS_VERSION
RUN apk add --no-cache curl
RUN curl -fsSL \
    "https://github.com/Privasys/go/releases/download/${GO_RATLS_VERSION}/go-ratls-${GO_RATLS_VERSION}-linux-amd64.tar.gz" \
    -o /tmp/go-ratls.tar.gz && \
    mkdir /go-ratls && \
    tar xzf /tmp/go-ratls.tar.gz -C /go-ratls --strip-components=1 && \
    rm /tmp/go-ratls.tar.gz

FROM alpine:3.21 AS builder
ARG RA_TLS_CLIENTS_REF
ARG ENCLAVE_VAULTS_CLIENT_REF
RUN apk add --no-cache git musl-dev ca-certificates
COPY --from=toolchain /go-ratls /go-ratls
ENV GOROOT=/go-ratls
ENV PATH="/go-ratls/bin:$PATH"
ENV GOPROXY=https://proxy.golang.org,direct

# Sibling modules (the replace-directive targets), cloned + pinned.
RUN git clone https://github.com/Privasys/ra-tls-clients /siblings/ra-tls-clients && \
    git -C /siblings/ra-tls-clients checkout "${RA_TLS_CLIENTS_REF}"
RUN git clone https://github.com/Privasys/enclave-vaults-client /siblings/enclave-vaults-client && \
    git -C /siblings/enclave-vaults-client checkout "${ENCLAVE_VAULTS_CLIENT_REF}"

WORKDIR /src
# Repoint the local replace paths at the cloned siblings. Run once to download
# dependencies, then again after COPY . . (which restores the original go.mod).
COPY go.mod go.sum ./
RUN sed -i \
      -e 's|\.\./ra-tls-clients/go|/siblings/ra-tls-clients/go|' \
      -e 's|\.\./enclave-vaults-client/go|/siblings/enclave-vaults-client/go|' \
      go.mod && \
    go mod download

COPY . .
RUN sed -i \
      -e 's|\.\./ra-tls-clients/go|/siblings/ra-tls-clients/go|' \
      -e 's|\.\./enclave-vaults-client/go|/siblings/enclave-vaults-client/go|' \
      go.mod && \
    CGO_ENABLED=0 go build -tags ratls -o /kmip-gateway .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /kmip-gateway /usr/local/bin/kmip-gateway
# The gateway serves one HTTP surface on the manager-injected $PORT (no own TLS).
ENTRYPOINT ["kmip-gateway"]
