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

// ---- Browser Notifications ----
function requestNotifPermission() {
    if (!('Notification' in window)) return;
    if (Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

function sendLocalNotif(title, body) {
    if (Notification.permission === 'granted') {
        new Notification(title, {
            body: body,
            icon: 'https://img.icons8.com/dusk/64/server.png',
        });
    }
}

// Auto-request on first visit
if ('Notification' in window && Notification.permission === 'default') {
    // Defer permission request to avoid being annoying on first load
    setTimeout(requestNotifPermission, 5000);
}

// Hook into SSE to trigger notifications for VM status changes
(function() {
    let knownVMStatus = {};

    if (typeof onSSE === 'function') {
        onSSE('proxmox_stats', function(data) {
            if (!data.VMs) return;
            data.VMs.forEach(function(vm) {
                const prev = knownVMStatus[vm.ID];
                if (prev && prev !== vm.Status) {
                    const action = vm.Status === 'running' ? 'd\u00e9marr\u00e9e' : 'arr\u00eat\u00e9e';
                    sendLocalNotif('GoaCloud - VM ' + action, vm.Name + ' (#' + vm.ID + ') est maintenant ' + action);
                }
                knownVMStatus[vm.ID] = vm.Status;
            });
        });
    }
})();
