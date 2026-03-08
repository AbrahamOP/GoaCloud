// Global Search (Ctrl+K)
(function() {
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
        document.getElementById('search-results').innerHTML = '<p class="text-center text-gray-600 text-sm py-6">Tapez pour rechercher...</p>';
    };

    window.closeSearch = function() {
        document.getElementById('search-modal').classList.add('hidden');
    };

    window.onSearchInput = function(q) {
        clearTimeout(searchTimeout);
        if (!q.trim()) {
            document.getElementById('search-results').innerHTML = '<p class="text-center text-gray-600 text-sm py-6">Tapez pour rechercher...</p>';
            return;
        }
        searchTimeout = setTimeout(() => {
            fetch('/api/search?q=' + encodeURIComponent(q))
                .then(r => r.json())
                .then(results => {
                    const container = document.getElementById('search-results');
                    if (!results || results.length === 0) {
                        container.innerHTML = '<p class="text-center text-gray-500 text-sm py-6">Aucun résultat</p>';
                        return;
                    }
                    container.innerHTML = results.map(r => {
                        const icons = { app: '\u{1F4E6}', vm: '\u{1F5A5}\uFE0F', page: '\u{1F4C4}' };
                        const typeLabels = { app: 'Application', vm: r.icon, page: 'Page' };
                        return `<a href="${r.url}" class="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/5 transition group" ${r.type === 'app' ? 'target="_blank"' : ''}>
                            <span class="text-lg">${icons[r.type] || '\u{1F4C4}'}</span>
                            <div class="flex-1 min-w-0">
                                <p class="text-sm text-white font-medium truncate group-hover:text-purple-300">${r.name}</p>
                                <p class="text-xs text-gray-500">${typeLabels[r.type]}</p>
                            </div>
                            <svg class="w-4 h-4 text-gray-600 group-hover:text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                        </a>`;
                    }).join('');
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
