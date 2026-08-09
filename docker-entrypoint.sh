#!/bin/sh
# ==============================================================================
# GoaCore — entrypoint du conteneur.
#
# Il ne fait que préparer le système de fichiers avant de passer la main au
# binaire (exec, donc pas de processus intermédiaire : les signaux d'arrêt
# arrivent bien à l'application et l'arrêt gracieux fonctionne).
# ==============================================================================
set -eu

PLAYBOOKS_DIST="${GOACORE_PLAYBOOKS_DIST:-/app/playbooks-dist}"
PLAYBOOKS_DIR="${GOACORE_PLAYBOOKS_DIR:-/app/playbooks}"

# Ansible écrit ses fichiers de travail dans ANSIBLE_HOME (répertoires temporaires
# locaux, ControlPath SSH). Il pointe sur /tmp, monté en tmpfs, parce que le rootfs
# du conteneur est en lecture seule : sans cela, ansible-playbook échoue à créer
# ~/.ansible et aucun playbook ne tourne.
mkdir -p "${ANSIBLE_HOME:-/tmp/.ansible}" 2>/dev/null || true

# /app/playbooks est un volume, et un volume MASQUE le contenu de l'image : sans
# cette synchronisation, les playbooks livrés restent figés à la version installée
# le premier jour et un playbook corrigé — y compris un correctif de sécurité — ne
# parvient jamais au client.
#
# Choix : on recopie les playbooks livrés par-dessus, on n'efface rien. Ceux que
# l'utilisateur crée ou téléverse depuis l'interface (même arborescence) sont donc
# conservés ; en contrepartie, la modification locale d'un playbook LIVRÉ est
# écrasée à chaque démarrage. C'est assumé : le catalogue livré appartient à
# l'image, une variante maison doit être enregistrée sous un autre nom.
if [ -d "$PLAYBOOKS_DIST" ]; then
    if cp -R "$PLAYBOOKS_DIST/." "$PLAYBOOKS_DIR/" 2>/dev/null; then
        echo "playbooks: catalogue livré synchronisé vers $PLAYBOOKS_DIR"
    else
        # Non fatal : l'application démarre quand même, avec les playbooks déjà
        # présents dans le volume. Mais il faut le dire fort, c'est un correctif
        # qui n'arrive pas.
        echo "playbooks: synchronisation IMPOSSIBLE ($PLAYBOOKS_DIR non inscriptible) — le catalogue livré n'est pas à jour" >&2
    fi
fi

exec "$@"
