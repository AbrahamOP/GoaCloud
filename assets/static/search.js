// Global Search (Ctrl+K)
(function() {
    // HTML escape helper to prevent XSS
    function escapeHTML(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // Create modal HTML
    const modalHTML = `
    <div id="search-modal" class="fixed inset-0 z-[200] hidden">
        <div class="fixed inset-0 bg-black/60 backdrop-blur-sm" onclick="closeSearch()"></div>
        <div class="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-lg z-[201]">
            <div class="mx-4 rounded-2xl border border-[#2a2839] bg-[#1b1928] shadow-2xl overflow-hidden">
                <div class="flex items-center px-4 border-b border-[#2a2839]">
                    <svg class="w-5 h-5 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <input id="search-input" type="text" placeholder="Rechercher apps, VMs, pages..."
                        class="w-full bg-transparent border-0 px-3 py-4 text-white text-sm focus:outline-none placeholder-gray-500"
                        oninput="onSearchInput(this.value)" autocomplete="off">
                    <kbd class="hidden sm:inline text-xs text-gray-600 bg-[#2a2839] px-2 py-0.5 rounded font-mono">ESC</kbd>
                </div>
                <div id="search-results" class="max-h-80 overflow-y-auto p-2"></div>
            </div>
        </div>
    </div>`;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    let searchTimeout = null;

    window.openSearch = function() {
        document.getElementById('search-modal').classList.remove('hidden');
        const input = document.getElementById('search-input');
        input.value = '';
        input.focus();
        document.getElementById('search-results').textContent = '';
        var hint = document.createElement('p');
        hint.className = 'text-center text-gray-600 text-sm py-6';
        hint.textContent = 'Tapez pour rechercher...';
        document.getElementById('search-results').appendChild(hint);
    };

    window.closeSearch = function() {
        document.getElementById('search-modal').classList.add('hidden');
        clearTimeout(searchTimeout);
    };

    // Build a search result element safely using DOM methods
    function buildResultLink(r) {
        var icons = { app: '\u{1F4E6}', vm: '\u{1F5A5}\uFE0F', page: '\u{1F4C4}' };
        var typeLabels = { app: 'Application', vm: (r.icon || ''), page: 'Page' };

        var a = document.createElement('a');
        a.href = r.url || '#';
        a.className = 'flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/5 transition group';
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
        nameP.className = 'text-sm text-white font-medium truncate group-hover:text-purple-300';
        nameP.textContent = r.name || '';
        infoDiv.appendChild(nameP);

        var typeP = document.createElement('p');
        typeP.className = 'text-xs text-gray-500';
        typeP.textContent = typeLabels[r.type] || '';
        infoDiv.appendChild(typeP);

        a.appendChild(infoDiv);

        // Arrow SVG
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('class', 'w-4 h-4 text-gray-600 group-hover:text-gray-400');
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
            hint.className = 'text-center text-gray-600 text-sm py-6';
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
                        empty.className = 'text-center text-gray-500 text-sm py-6';
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
                    errP.className = 'text-center text-red-400 text-sm py-6';
                    errP.textContent = 'Erreur de recherche';
                    container.appendChild(errP);
                });
        }, 200);
    };

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            openSearch();
        }
        if (e.key === 'Escape' && !document.getElementById('search-modal').classList.contains('hidden')) {
            closeSearch();
        }
    });
})();
