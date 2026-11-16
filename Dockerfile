# One binary: coredns with the dnstest plugin. It also fetches the ASN table itself.
# Base images are pinned by digest; Renovate bumps them, never use a floating tag.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/coredns ./cmd/coredns \
 && mkdir /out-data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.source="https://github.com/payam-foundation/dotvpn-dnstest" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.description="dotvpn DNS leak test server"
COPY --from=build /out/ /usr/local/bin/
# The table directory belongs to root: compose runs the server as root with only the
# bind capability (no DAC override), and a fresh named volume copies this ownership.
COPY --from=build /out-data /data
COPY Corefile /etc/coredns/Corefile
VOLUME /data
USER nonroot
ENTRYPOINT ["/usr/local/bin/coredns"]
CMD ["-conf", "/etc/coredns/Corefile", "-quiet"]
