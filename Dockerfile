# Images de base épinglées PAR DIGEST : un tag comme `golang:alpine` ou
# `alpine:3.21` est mouvant, donc deux builds du même commit ne produisent pas le
# même binaire et une régression de base est indétectable. Le tag lisible reste en
# commentaire pour savoir ce qu'on épingle.
#
# Mise à jour du digest (à faire consciemment, jamais automatiquement) :
#   docker buildx imagetools inspect alpine:3.21 --format '{{.Manifest.Digest}}'
#
# Build Stage — exécuté sur l'arch NATIVE du runner, cross-compile le binaire Go vers
# l'arch cible (TARGETOS/TARGETARCH injectés par buildx). Go cross-compile sans
# émulation : les builds multi-arch (amd64/arm64) restent rapides.
# golang:1.23-alpine3.21
FROM --platform=$BUILDPLATFORM golang@sha256:4bb4be21ac98da06bc26437ee870c4973f8039f13e9a1a36971b4517632b0fc6 AS builder

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
# alpine:3.21
FROM alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

WORKDIR /app

# ca-certificates + tzdata : appels sortants HTTPS et horodatage local.
#
# ansible : REQUIS par le module d'automatisation (services.RunPlaybook exécute
# ansible-playbook). Il faut en connaître le prix : il tire un interpréteur Python
# complet et plusieurs centaines de modules dans l'image d'une application web.
# C'est, de loin, la plus grosse surface d'attaque du conteneur — un module Ansible
# est du code Python exécuté localement avec les droits de l'app, et Python donne
# accès à tout ce que la Go stdlib n'exposait pas. Les garde-fous qui la bornent :
#   - conteneur non-root, rootfs en lecture seule et toutes capacités retirées
#     (voir docker-compose.yml : read_only / cap_drop / no-new-privileges) ;
#   - seuls les playbooks de /app/playbooks sont exécutables (contrôle de chemin
#     côté handlers), sur des cibles dont la clé d'hôte est épinglée en base.
# Si l'automatisation Ansible n'est pas utilisée, la bonne réponse est de rebâtir
# l'image sans cette dépendance, pas de la « durcir » davantage.
#
# openssh-client (et NON openssh) : Ansible n'a besoin que du client ssh. Le
# paquet complet embarquerait aussi sshd, c'est-à-dire un serveur SSH inutile dans
# l'image d'une application web.
RUN apk --no-cache add ca-certificates tzdata ansible openssh-client

# Create non-root user
RUN addgroup -g 1000 goacloud && adduser -D -u 1000 -G goacloud goacloud

# Copie du binaire depuis le builder
COPY --from=builder /app/goacloud .
# Les playbooks livrés vont dans un répertoire de RÉFÉRENCE, pas directement dans
# /app/playbooks : ce dernier est un volume, et un volume masque le contenu de
# l'image. L'entrypoint les recopie au démarrage (voir plus bas).
COPY playbooks/ ./playbooks-dist/
COPY ansible.cfg ./

# Répertoires que l'application écrit à l'exécution, créés ici pour qu'ils existent
# et appartiennent à l'app même quand un volume vide est monté dessus :
#   certs/    → certificat TLS auto-signé PERSISTÉ (cf. internal/server/tls.go)
#   playbooks/→ playbooks livrés (synchronisés au boot) + ceux de l'utilisateur
RUN mkdir -p /app/certs /app/playbooks && chown -R goacloud:goacloud /app && chmod 700 /app/certs

# Entrypoint : resynchronise le catalogue de playbooks livré vers le volume, puis
# exec le binaire (voir docker-entrypoint.sh pour le détail et le compromis).
COPY docker-entrypoint.sh /usr/local/bin/goacore-entrypoint.sh
RUN chmod 555 /usr/local/bin/goacore-entrypoint.sh

USER goacloud

# Rootfs en lecture seule (docker-compose.yml) : tout ce qu'Ansible écrit doit
# aller dans le tmpfs /tmp, pas dans ~/.ansible.
ENV ANSIBLE_HOME=/tmp/.ansible

# Port réellement servi : HTTPS 8443 (l'ancien EXPOSE 8080 ne correspondait à rien
# de publié). 8080 n'est que la redirection HTTP→HTTPS interne, non exposée.
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO /dev/null https://localhost:8443/login --no-check-certificate || exit 1

# Commande de démarrage
ENTRYPOINT ["/usr/local/bin/goacore-entrypoint.sh"]
CMD ["./goacloud"]
