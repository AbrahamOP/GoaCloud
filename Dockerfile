# Build Stage
FROM golang:alpine AS builder

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
COPY templates/ ./templates/
COPY playbooks/ ./playbooks/

# Téléchargement des dépendances
RUN go mod download

# Build de l'application statique depuis le nouveau point d'entrée
RUN CGO_ENABLED=0 GOOS=linux go build -o goacloud ./cmd/server

# Final Stage
FROM alpine:latest

WORKDIR /app

# Ajout des certificats CA, timezone, ansible et client ssh
RUN apk --no-cache add ca-certificates tzdata ansible openssh

# Copie du binaire depuis le builder
COPY --from=builder /app/goacloud .
COPY templates/ ./templates/
COPY playbooks/ ./playbooks/
COPY ansible.cfg ./

# Exposition du port
EXPOSE 8080

# Commande de démarrage
CMD ["./goacloud"]
