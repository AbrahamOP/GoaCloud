// ========================================
// GoaCloud — Theme toggle + SSE connection
// ========================================

// ---- Theme ----
(function() {
    const saved = localStorage.getItem('goacloud-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
})();

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('goacloud-theme', next);
}

// ---- SSE ----
let _sseSource = null;
const _sseListeners = {};

function connectSSE() {
    if (_sseSource) return;
    _sseSource = new EventSource('/api/events');

    _sseSource.addEventListener('proxmox_stats', function(e) {
        try {
            const data = JSON.parse(e.data);
            if (_sseListeners['proxmox_stats']) {
                _sseListeners['proxmox_stats'].forEach(fn => fn(data));
            }
        } catch(err) {
            console.error('SSE parse error:', err);
        }
    });

    _sseSource.onerror = function() {
        _sseSource.close();
        _sseSource = null;
        // Reconnect after 5s
        setTimeout(connectSSE, 5000);
    };
}

function onSSE(event, callback) {
    if (!_sseListeners[event]) _sseListeners[event] = [];
    _sseListeners[event].push(callback);
    connectSSE();
}
