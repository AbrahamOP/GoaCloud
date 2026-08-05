#!/bin/sh
# ==============================================================================
# GoaCore — sauvegarde et restauration de sa PROPRE base.
#
# GoaCore vend la restaurabilité prouvée ; sa base MySQL contient l'intégralité de
# son état (comptes, planifications, cibles, historiques) et ses secrets chiffrés
# (token Proxmox, clés SSH). Elle doit donc être sauvegardée comme n'importe
# quelle donnée de production — et la restauration doit être testée.
#
# ⚠ SESSION_SECRET FAIT PARTIE DE LA SAUVEGARDE.
#   Les secrets stockés en base sont chiffrés en AES-256-GCM avec une clé dérivée
#   de SESSION_SECRET, qui n'est PAS dans la base. Un dump restauré avec un autre
#   SESSION_SECRET rend tous les secrets illisibles : l'application redémarre,
#   mais aucune connexion Proxmox/Wazuh/SSH ne fonctionne. Conservez SESSION_SECRET
#   (et le .env) au même endroit que vos dumps, dans un coffre.
#
# Usage (depuis le répertoire qui contient docker-compose.yml et .env) :
#   ./backup.sh dump [répertoire]     dump gzip horodaté (défaut : ./backups)
#   ./backup.sh restore <fichier>     restaure un dump (.sql ou .sql.gz)
#   ./backup.sh prune [répertoire]    supprime les dumps au-delà de la rétention
#   ./backup.sh verify <fichier>      vérifie la lisibilité d'un dump
#
# Planification (cron de l'hôte, tous les jours à 3 h) :
#   0 3 * * * cd /opt/goacore && ./backup.sh dump && ./backup.sh prune
#
# Réglages (variables d'environnement) :
#   GOACORE_BACKUP_DIR             répertoire des dumps        (défaut ./backups)
#   GOACORE_BACKUP_RETENTION_DAYS  rétention en jours          (défaut 14)
#   GOACORE_DB_SERVICE             nom du service compose      (défaut db ;
#                                  « db-dev » pour docker-compose-dev.yml)
#
# Le dump n'est pas chiffré : envoyez-le vers un stockage chiffré (rclone crypt,
# borg, etc.). Il contient tout l'état du produit.
# ==============================================================================
set -eu

BACKUP_DIR="${GOACORE_BACKUP_DIR:-./backups}"
RETENTION_DAYS="${GOACORE_BACKUP_RETENTION_DAYS:-14}"
DB_SERVICE="${GOACORE_DB_SERVICE:-db}"

die() {
    echo "erreur : $*" >&2
    exit 1
}

COMPOSE=""

# require_compose choisit docker compose (v2) ou docker-compose (v1). Résolu à la
# demande : vérifier et lister les dumps doit rester possible sur une machine qui
# n'a pas Docker (poste de sauvegarde, hôte de restauration).
require_compose() {
    [ -z "$COMPOSE" ] || return 0
    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE="docker-compose"
    else
        die "ni « docker compose » ni « docker-compose » n'est disponible"
    fi
}

# db_running vérifie que le service de base est bien démarré : un dump silencieux
# sur un conteneur arrêté produirait un fichier vide, donc une fausse sauvegarde.
db_running() {
    require_compose
    [ -n "$($COMPOSE ps -q "$DB_SERVICE" 2>/dev/null)" ] || die "le service « $DB_SERVICE » n'est pas démarré"
}

# check_dump vérifie qu'un fichier est une sauvegarde exploitable : archive gzip
# intacte ET terminée par le marqueur de fin de mysqldump. C'est ce marqueur qui
# distingue un dump complet d'un dump tronqué (disque plein, conteneur tué,
# identifiants refusés) — le code de retour du pipeline, lui, est celui de gzip,
# donc toujours 0.
check_dump() {
    file="$1"
    gzip -t "$file" 2>/dev/null || return 1
    gunzip -c "$file" | tail -c 2048 | grep -q "Dump completed" || return 1
}

# Les identifiants ne circulent PAS en argument de commande (ils seraient visibles
# dans la table des processus de l'hôte) : on réutilise les variables déjà
# présentes dans l'environnement du conteneur MySQL — d'où les guillemets simples,
# qui laissent l'expansion se faire dans le conteneur.
cmd_dump() {
    dir="${1:-$BACKUP_DIR}"
    db_running
    mkdir -p "$dir"
    stamp="$(date +%Y%m%d-%H%M%S)"
    tmp="$dir/.goacore-$stamp.sql.gz.part"
    out="$dir/goacore-$stamp.sql.gz"

    # --single-transaction : dump cohérent sans verrouiller l'application.
    # --routines/--triggers/--events : le schéma complet, pas seulement les tables.
    # shellcheck disable=SC2016  # $MYSQL_* doivent s'expandre DANS le conteneur
    $COMPOSE exec -T "$DB_SERVICE" sh -c \
        'exec mysqldump --single-transaction --routines --triggers --events \
            --default-character-set=utf8mb4 \
            -u root -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"' | gzip > "$tmp" || true

    # Un fichier partiel ne doit jamais porter le nom d'une sauvegarde valide :
    # on ne renomme qu'après vérification.
    if ! check_dump "$tmp"; then
        rm -f "$tmp"
        die "le dump a échoué ou est tronqué — aucune sauvegarde écrite"
    fi
    mv "$tmp" "$out"
    chmod 600 "$out"
    echo "dump : $out ($(wc -c < "$out") octets)"
    echo "rappel : sauvegardez aussi SESSION_SECRET (.env), sans lui les secrets sont irrécupérables"
}

cmd_restore() {
    file="${1:-}"
    [ -n "$file" ] || die "usage : $0 restore <fichier>"
    [ -f "$file" ] || die "fichier introuvable : $file"
    db_running

    echo "ATTENTION : la base de GoaCore va être ÉCRASÉE par $file."
    echo "Le SESSION_SECRET utilisé doit être celui d'origine, sinon les secrets"
    echo "stockés resteront indéchiffrables."
    printf "Taper « oui » pour confirmer : "
    read -r answer
    [ "$answer" = "oui" ] || die "restauration annulée"

    # shellcheck disable=SC2016  # $MYSQL_* doivent s'expandre DANS le conteneur
    if [ "${file%.gz}" != "$file" ]; then
        gunzip -c "$file"
    else
        cat "$file"
    fi | $COMPOSE exec -T "$DB_SERVICE" sh -c \
        'exec mysql --default-character-set=utf8mb4 -u root -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"'

    echo "restauration terminée — redémarrez l'application : $COMPOSE restart app"
}

cmd_verify() {
    file="${1:-}"
    [ -n "$file" ] || die "usage : $0 verify <fichier>"
    [ -f "$file" ] || die "fichier introuvable : $file"
    if [ "${file%.gz}" != "$file" ]; then
        check_dump "$file" || die "dump illisible ou tronqué : $file"
    else
        tail -c 2048 "$file" | grep -q "Dump completed" || die "dump tronqué : $file"
    fi
    echo "dump lisible et complet : $file"
}

cmd_prune() {
    dir="${1:-$BACKUP_DIR}"
    [ -d "$dir" ] || die "répertoire introuvable : $dir"
    find "$dir" -name 'goacore-*.sql.gz' -type f -mtime "+$RETENTION_DAYS" -print -delete
    echo "rétention appliquée : $RETENTION_DAYS jours ($dir)"
}

case "${1:-}" in
    dump)    shift; cmd_dump "$@" ;;
    restore) shift; cmd_restore "$@" ;;
    verify)  shift; cmd_verify "$@" ;;
    prune)   shift; cmd_prune "$@" ;;
    *)
        echo "usage : $0 {dump|restore|verify|prune} [argument]" >&2
        exit 1
        ;;
esac
