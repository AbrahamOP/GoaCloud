// Global Search (Ctrl+K)
(function() {
    // HTML escape helper to prevent XSS
    function escapeHTML(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // La palette est une COUCHE COMME LES AUTRES : elle est empilée par
    // GoaUI.openModal (ui.js) au lieu de gérer son propre affichage. Tant qu'elle
    // vivait à côté de la pile partagée, ouvrir Ctrl+K par-dessus une modale volait
    // le focus sans que le piège de focus de la modale ne le sache, et Échap était
    // consommé par la modale du dessous : la palette restait à l'écran, inutilisable.
    //
    // D'où le balisage : role/aria-modal pour être une vraie boîte de dialogue,
    // data-modal-autofocus pour que le focus aille dans le champ, et
    // data-modal-discardable pour qu'Échap ferme immédiatement — la garde « saisie
    // non enregistrée » de ui.js n'a aucun sens sur un champ de recherche.
    const modalHTML = `
    <div id="search-modal" role="dialog" aria-modal="true" aria-label="Recherche globale" tabindex="-1"
         data-modal-discardable class="fixed inset-0 z-[200] hidden">
        <div class="fixed inset-0 bg-scrim/60 backdrop-blur-sm" onclick="closeSearch()"></div>
        <div class="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-lg z-[201]">
            <div class="mx-4 rounded-2xl border border-outline-variant bg-surface-container-high shadow-2xl overflow-hidden">
                <div class="flex items-center px-4 border-b border-outline-variant">
                    <svg class="w-5 h-5 text-on-surface-variant shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <input id="search-input" type="text" placeholder="Rechercher apps, VMs, pages..." data-modal-autofocus
                        class="w-full bg-transparent border-0 px-3 py-4 text-on-surface text-sm focus:outline-none placeholder-on-surface-variant"
                        oninput="onSearchInput(this.value)" autocomplete="off">
                    <kbd class="hidden sm:inline text-xs text-on-surface-variant bg-surface-container-highest px-2 py-0.5 rounded font-mono">ESC</kbd>
                </div>
                <div id="search-results" class="max-h-80 overflow-y-auto p-2"></div>
            </div>
        </div>
    </div>`;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    let searchTimeout = null;

    function searchModal() {
        return document.getElementById('search-modal');
    }

    function resetResults() {
        var container = document.getElementById('search-results');
        container.textContent = '';
        var hint = document.createElement('p');
        hint.className = 'text-center text-on-surface-variant text-sm py-6';
        hint.textContent = 'Tapez pour rechercher...';
        container.appendChild(hint);
    }

    window.openSearch = function() {
        var modal = searchModal();
        document.getElementById('search-input').value = '';
        resetResults();
        // Repli si ui.js n'est pas chargé sur la page : la palette doit s'ouvrir
        // quand même, quitte à perdre le piège de focus.
        if (window.GoaUI && window.GoaUI.openModal) {
            window.GoaUI.openModal(modal);
        } else {
            modal.classList.remove('hidden');
            document.getElementById('search-input').focus();
        }
    };

    window.closeSearch = function() {
        clearTimeout(searchTimeout);
        var modal = searchModal();
        if (window.GoaUI && window.GoaUI.closeModal) {
            window.GoaUI.closeModal(modal);
        } else {
            modal.classList.add('hidden');
        }
    };

    // Échap est géré par la pile partagée : elle appelle closeModal directement,
    // sans passer par closeSearch. Le ménage (requête en vol) se raccroche donc à
    // l'événement de fermeture, qui est émis quelle que soit l'origine.
    searchModal().addEventListener('goa:modal-close', function() {
        clearTimeout(searchTimeout);
    });

    // Build a search result element safely using DOM methods
    function buildResultLink(r) {
        var icons = { app: '\u{1F4E6}', vm: '\u{1F5A5}\uFE0F', page: '\u{1F4C4}' };
        var typeLabels = { app: 'Application', vm: (r.icon || ''), page: 'Page' };

        var a = document.createElement('a');
        a.href = r.url || '#';
        a.className = 'flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-on-surface/5 transition group';
        if (r.type === 'app') {
            a.target = '_blank';
            a.rel = 'noopener';
        }

        var iconSpan = document.createElement('span');
        iconSpan.className = 'text-lg';
        iconSpan.textContent = icons[r.type] || '\u{1F4C4}';
        a.appendChild(iconSpan);

        var infoDiv = document.createElement('div');
        infoDiv.className = 'flex-1 min-w-0';

        var nameP = document.createElement('p');
        nameP.className = 'text-sm text-on-surface font-medium truncate group-hover:text-primary';
        nameP.textContent = r.name || '';
        infoDiv.appendChild(nameP);

        var typeP = document.createElement('p');
        typeP.className = 'text-xs text-on-surface-variant';
        typeP.textContent = typeLabels[r.type] || '';
        infoDiv.appendChild(typeP);

        a.appendChild(infoDiv);

        // Arrow SVG
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('class', 'w-4 h-4 text-on-surface-variant group-hover:text-on-surface');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('stroke', 'currentColor');
        var path = document.createElementNS(svgNS, 'path');
        path.setAttribute('stroke-linecap', 'round');
        path.setAttribute('stroke-linejoin', 'round');
        path.setAttribute('stroke-width', '2');
        path.setAttribute('d', 'M9 5l7 7-7 7');
        svg.appendChild(path);
        a.appendChild(svg);

        return a;
    }

    window.onSearchInput = function(q) {
        clearTimeout(searchTimeout);
        var container = document.getElementById('search-results');
        if (!q.trim()) {
            container.textContent = '';
            var hint = document.createElement('p');
            hint.className = 'text-center text-on-surface-variant text-sm py-6';
            hint.textContent = 'Tapez pour rechercher...';
            container.appendChild(hint);
            return;
        }
        searchTimeout = setTimeout(function() {
            fetch('/api/search?q=' + encodeURIComponent(q))
                .then(function(r) { return r.json(); })
                .then(function(results) {
                    container.textContent = '';
                    if (!results || results.length === 0) {
                        var empty = document.createElement('p');
                        empty.className = 'text-center text-on-surface-variant text-sm py-6';
                        empty.textContent = 'Aucun résultat';
                        container.appendChild(empty);
                        return;
                    }
                    results.forEach(function(r) {
                        container.appendChild(buildResultLink(r));
                    });
                })
                .catch(function(err) {
                    console.error('Search error:', err);
                    container.textContent = '';
                    var errP = document.createElement('p');
                    errP.className = 'text-center text-error text-sm py-6';
                    errP.textContent = 'Erreur de recherche';
                    container.appendChild(errP);
                });
        }, 200);
    };

    // Raccourci clavier. Échap n'est PLUS traité ici : la pile de ui.js l'intercepte
    // en capture pour la couche du dessus, et la palette en fait maintenant partie.
    // Deux gestionnaires concurrents fermaient tantôt l'une, tantôt l'autre.
    document.addEventListener('keydown', function(e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            // Deuxième Ctrl+K sur une palette déjà ouverte : on la referme plutôt
            // que d'empiler la même couche deux fois (openModal l'ignorerait, mais
            // le comportement attendu d'une bascule est de basculer).
            if (window.GoaUI && window.GoaUI.isModalOpen && window.GoaUI.isModalOpen(searchModal())) {
                closeSearch();
            } else {
                openSearch();
            }
        }
    });
})();
