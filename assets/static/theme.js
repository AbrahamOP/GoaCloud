// ========================================
// GoaCore — Theme toggle + SSE connection
// ========================================

// ---- Theme ----
// data-theme est posé par le script inline de "head-common" (partials.html), avant
// les feuilles de style, pour éviter le flash de thème. Il ne reste ici que ce qui
// doit attendre le premier rendu.
(function() {
    // Enable CSS transitions only after initial paint to avoid animations on page load
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            document.documentElement.classList.add('transitions-ready');
        });
    });
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
const _sseStateListeners = [];

// Reconnexion : délai exponentiel plafonné. Un délai fixe de 5 s martelait le
// serveur pendant toute la durée d'une panne, et rien à l'écran ne distinguait
// « flux vivant » de « flux mort depuis dix minutes ».
const SSE_BACKOFF_MIN_MS = 2000;
const SSE_BACKOFF_MAX_MS = 60000;
const SSE_FAILURES_BEFORE_DOWN = 3;

let _sseRetryDelay = SSE_BACKOFF_MIN_MS;
let _sseFailures = 0;
let _sseState = 'idle'; // idle | connected | reconnecting | down
let _sseRetryTimer = null;

function _setSSEState(state) {
    if (_sseState === state) return;
    _sseState = state;
    _sseStateListeners.forEach(function(fn) {
        try { fn(state); } catch (err) { console.error('SSE state listener error:', err); }
    });
}

function connectSSE() {
    if (_sseSource) return;
    clearTimeout(_sseRetryTimer);
    _sseSource = new EventSource('/api/events');

    _sseSource.onopen = function() {
        _sseRetryDelay = SSE_BACKOFF_MIN_MS;
        _sseFailures = 0;
        _setSSEState('connected');
    };

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
        _sseFailures++;
        // Au-delà de quelques échecs, on considère le flux perdu et on le signale :
        // une page figée qui affiche « tout va bien » est un faux négatif dangereux.
        _setSSEState(_sseFailures >= SSE_FAILURES_BEFORE_DOWN ? 'down' : 'reconnecting');
        _sseRetryTimer = setTimeout(connectSSE, _sseRetryDelay);
        _sseRetryDelay = Math.min(_sseRetryDelay * 2, SSE_BACKOFF_MAX_MS);
    };
}

function onSSE(event, callback) {
    if (!_sseListeners[event]) _sseListeners[event] = [];
    _sseListeners[event].push(callback);
    connectSSE();
}

/**
 * S'abonne à l'état du flux temps réel ('connected' | 'reconnecting' | 'down').
 * Permet aux pages d'afficher un état « déconnecté » plutôt que de laisser
 * croire que les valeurs à l'écran sont fraîches.
 */
function onSSEState(callback) {
    _sseStateListeners.push(callback);
    callback(_sseState);
}

// ---- Browser Notifications ----
// Aucune demande de permission SPONTANÉE : le navigateur ne doit afficher la popup
// que sur un geste explicite de l'utilisateur (et Chrome ignore purement et
// simplement une demande faite hors geste). Mais supprimer la demande sans la
// remplacer laissait la fonctionnalité définitivement morte : la permission restant
// à « default », sendLocalNotif n'affichait jamais rien et rien, nulle part, ne
// permettait de l'accorder. D'où le déclencheur explicite ci-dessous, câblé sur un
// bouton (voir proxmox.html).

/**
 * Indique si la page a intérêt à proposer l'activation des notifications :
 * l'API existe et l'utilisateur n'a encore ni accordé ni refusé.
 */
function canRequestNotifications() {
    return ('Notification' in window) && Notification.permission === 'default';
}

/**
 * Demande la permission d'afficher des notifications navigateur.
 * À N'APPELER QUE depuis un gestionnaire d'événement utilisateur (clic).
 * @returns {Promise<string>} la permission résultante ('granted' | 'denied' | 'default')
 */
function requestNotificationPermission() {
    if (!('Notification' in window)) {
        if (window.notify) notify('warning', "Ce navigateur ne gère pas les notifications de bureau.");
        return Promise.resolve('denied');
    }
    return Promise.resolve(Notification.requestPermission()).then(function(permission) {
        if (window.notify) {
            if (permission === 'granted') {
                notify('success', 'Notifications activées : vous serez prévenu des changements d’état des VM.');
            } else {
                notify('info', 'Notifications non activées. Vous pouvez les autoriser plus tard dans les réglages du navigateur.');
            }
        }
        return permission;
    });
}

function sendLocalNotif(title, body) {
    if (!('Notification' in window)) return;
    if (Notification.permission === 'granted') {
        new Notification(title, {
            body: body,
            icon: '/static/favicon.png',
        });
    }
}

// Hook into SSE to trigger notifications for VM status changes.
// Called explicitly by pages that need SSE (dashboard, proxmox).
function enableVMNotifications() {
    let knownVMStatus = {};
    onSSE('proxmox_stats', function(data) {
        if (!data.VMs) return;
        data.VMs.forEach(function(vm) {
            const prev = knownVMStatus[vm.ID];
            if (prev && prev !== vm.Status) {
                const action = vm.Status === 'running' ? 'd\u00e9marr\u00e9e' : 'arr\u00eat\u00e9e';
                sendLocalNotif('GoaCore - VM ' + action, vm.Name + ' (#' + vm.ID + ') est maintenant ' + action);
            }
            knownVMStatus[vm.ID] = vm.Status;
        });
    });
}
