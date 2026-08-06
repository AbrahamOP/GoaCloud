# Build Stage — exécuté sur l'arch NATIVE du runner, cross-compile le binaire Go vers
# l'arch cible (TARGETOS/TARGETARCH injectés par buildx). Go cross-compile sans
# émulation : les builds multi-arch (amd64/arm64) restent rapides.
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /app

# Installation des dépendances pour le build
RUN apk add --no-cache git

# Copie des fichiers de définition de module
COPY go.mod go.sum ./

# Copie du code source
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY assets/ ./assets/
# Cache busting
ARG CACHEBUST=1
COPY playbooks/ ./playbooks/
# deploy/ contient le helper goabackup-runner.sh embarqué par //go:embed dans
# goacore/deploy/goabackup, importé transitivement par cmd/server. Sans cette copie,
# `go build ./cmd/server` échoue ("package goacore/deploy/goabackup is not in std").
# Le stage final n'en a pas besoin : l'embed est compilé dans le binaire.
COPY deploy/ ./deploy/

# Téléchargement des dépendances
RUN go mod download

# Build de l'application statique pour l'arch cible (cross-compilation).
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o goacloud ./cmd/server

# Final Stage
FROM alpine:3.24

WORKDIR /app

# Ajout des certificats CA, timezone, ansible et client ssh
RUN apk --no-cache add ca-certificates tzdata ansible openssh

# Create non-root user
RUN addgroup -g 1000 goacloud && adduser -D -u 1000 -G goacloud goacloud

# Copie du binaire depuis le builder
COPY --from=builder /app/goacloud .
COPY playbooks/ ./playbooks/
COPY ansible.cfg ./

# Ensure app user owns the working directory
RUN chown -R goacloud:goacloud /app

USER goacloud

# Exposition du port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO /dev/null https://localhost:8443/login --no-check-certificate || exit 1

# Commande de démarrage
CMD ["./goacloud"]
