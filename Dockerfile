# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go main_test.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/church-oidc .

# distroless static image: ships CA certs (needed for HTTPS calls to
# ChurchTools) and runs as non-root, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/church-oidc /church-oidc
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/church-oidc"]
