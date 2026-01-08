# Build Stage
FROM golang:alpine AS builder

WORKDIR /app

# Installation des dépendances pour le build (git n'est pas toujours dans alpine par défaut)
RUN apk add --no-cache git

# Copie des fichiers de définition de module
COPY go.mod ./

# Copie du code source pour que go mod tidy puisse analyser les déps
COPY *.go ./
# Cache busting
ARG CACHEBUST=1
COPY templates/ ./templates/
COPY playbooks/ ./playbooks/

# Téléchargement des dépendances
RUN go mod tidy
RUN go mod download

# Build de l'application statique
RUN CGO_ENABLED=0 GOOS=linux go build -o goacloud .

# Final Stage
# Utilisation d'une image minimale
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
