// ========================================
// GoaCore — Retours utilisateur (toasts) + modales accessibles
// ========================================
// Deux briques partagées par toutes les pages :
//   1. notify(type, message)  — remplace les alert() natifs. Une boîte du
//      navigateur bloque la page entière, affiche l'URL du site et ne se
//      referme qu'au clic : ça ressemble à une page piégée, pas à un produit.
//   2. GoaUI.openModal / closeModal — comportement de dialogue unique pour les
//      24 modales du projet : Échap, piège de focus, restauration du focus du
//      déclencheur. Chaque page garde son propre balisage, mais plus sa propre
//      (absence de) logique d'accessibilité.
(function (window, document) {
    "use strict";

    // ============================================================
    // Toasts
    // ============================================================

    var TOAST_HOST_ID = "goa-toast-host";

    // Palette alignée sur les toasts déjà en place (backups, proxmox).
    var TONES = {
        success: "bg-success/10 text-success border-success/30",
        error: "bg-error/10 text-error border-error/30",
        warning: "bg-warning/10 text-warning border-warning/30",
        info: "bg-surface-container-high text-on-surface border-outline-variant"
    };

    // Une erreur reste affichée plus longtemps : elle demande une décision.
    var DURATIONS = { success: 4000, info: 4000, warning: 7000, error: 8000 };

    function toastHost() {
        var host = document.getElementById(TOAST_HOST_ID);
        if (host) return host;
        // Filet de sécurité pour les pages qui n'incluent pas
        // {{template "toast-host"}} : une notification ne doit jamais être perdue.
        host = document.createElement("div");
        host.id = TOAST_HOST_ID;
        host.className = "fixed bottom-6 right-6 z-[200] flex flex-col items-end gap-2 pointer-events-none";
        host.setAttribute("aria-live", "polite");
        host.setAttribute("aria-atomic", "false");
        document.body.appendChild(host);
        return host;
    }

    function dismiss(toast) {
        if (!toast || toast._goaDismissed) return;
        toast._goaDismissed = true;
        clearTimeout(toast._goaTimer);
        toast.classList.add("opacity-0", "translate-y-2");
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 200);
    }

    /**
     * Affiche une notification non bloquante.
     * @param {"success"|"error"|"warning"|"info"} type
     * @param {string} message  phrase complète, compréhensible sans contexte technique
     * @returns {HTMLElement|undefined} le toast créé
     */
    function notify(type, message) {
        if (!message) return;
        var tone = TONES[type] ? type : "info";
        var host = toastHost();

        var toast = document.createElement("div");
        toast.className =
            "pointer-events-auto max-w-sm px-4 py-3 rounded-xl shadow-xl border text-sm font-medium " +
            "flex items-start gap-3 opacity-0 translate-y-2 transition duration-200 " + TONES[tone];
        // Une erreur doit interrompre la lecture du lecteur d'écran, pas une réussite.
        toast.setAttribute("role", tone === "error" ? "alert" : "status");

        var text = document.createElement("span");
        text.className = "flex-1";
        text.textContent = message;
        toast.appendChild(text);

        var close = document.createElement("button");
        close.type = "button";
        close.className = "shrink-0 opacity-70 hover:opacity-100 transition-opacity";
        close.setAttribute("aria-label", "Fermer la notification");
        close.innerHTML =
            '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">' +
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>';
        close.addEventListener("click", function () { dismiss(toast); });
        toast.appendChild(close);

        host.appendChild(toast);
        requestAnimationFrame(function () {
            toast.classList.remove("opacity-0", "translate-y-2");
        });

        toast._goaTimer = setTimeout(function () { dismiss(toast); }, DURATIONS[tone]);
        return toast;
    }

    /**
     * Traduit une erreur JS ou réseau brute en phrase utile.
     * « TypeError: Failed to fetch » n'apprend rien à un administrateur de PME.
     * @param {*} err     Error, chaîne, ou message renvoyé par l'API
     * @param {string} [context] début de phrase décrivant l'action tentée
     */
    function describeError(err, context) {
        var raw = "";
        if (typeof err === "string") raw = err;
        else if (err && typeof err.message === "string") raw = err.message;

        var prefix = context ? context + " : " : "";
        if (!raw) return prefix + "une erreur inattendue est survenue.";
        if (/failed to fetch|networkerror|load failed|network request failed/i.test(raw)) {
            return prefix + "le serveur est injoignable. Vérifiez votre connexion réseau, puis réessayez.";
        }
        if (/abort/i.test(raw)) return prefix + "l'opération a été interrompue avant la fin.";
        if (/timeout|timed out/i.test(raw)) return prefix + "le serveur n'a pas répondu à temps. Réessayez dans un instant.";
        if (/^\s*(TypeError|ReferenceError|SyntaxError)\b/.test(raw)) {
            return prefix + "une erreur interne s'est produite. Rechargez la page ; si le problème persiste, consultez les journaux.";
        }
        return prefix + raw;
    }

    /** Raccourci : notifie une erreur en la rendant lisible au passage. */
    function notifyError(err, context) {
        return notify("error", describeError(err, context));
    }

    // ============================================================
    // Modales
    // ============================================================

    var FOCUSABLE = [
        "a[href]", "area[href]", "button:not([disabled])",
        'input:not([disabled]):not([type="hidden"])',
        "select:not([disabled])", "textarea:not([disabled])",
        "iframe", "audio[controls]", "video[controls]",
        '[contenteditable]:not([contenteditable="false"])',
        '[tabindex]:not([tabindex="-1"])'
    ].join(",");

    // Pile : une modale peut en ouvrir une autre (ex. sauvegardes → confirmation).
    var stack = [];

    function resolve(target) {
        return typeof target === "string" ? document.getElementById(target) : target;
    }

    function focusables(root) {
        return Array.prototype.filter.call(root.querySelectorAll(FOCUSABLE), function (el) {
            return el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0;
        });
    }

    function isOpen(target) {
        var el = resolve(target);
        return !!el && stack.indexOf(el) !== -1;
    }

    /**
     * Ouvre une modale : retire `hidden`, mémorise le déclencheur et pose le
     * focus sur le premier élément utile (ou sur l'élément marqué autofocus).
     */
    function openModal(target) {
        var el = resolve(target);
        if (!el || stack.indexOf(el) !== -1) return null;

        el._goaOpener = document.activeElement;
        clearTimeout(el._goaHideTimer);
        el.classList.remove("hidden");
        el.removeAttribute("aria-hidden");
        el.inert = false;
        if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
        stack.push(el);
        document.documentElement.classList.add("modal-open");

        var preferred = el.querySelector("[data-modal-autofocus]");
        var candidates = focusables(el);
        (preferred || candidates[0] || el).focus();
        return el;
    }

    /**
     * Ferme une modale, rend le focus au bouton qui l'avait ouverte et émet
     * `goa:modal-close` pour que la page fasse son propre ménage (timers,
     * champs à vider, animation de sortie…) — y compris lors d'une fermeture
     * par Échap. Une page qui anime sa sortie déclare la durée sur la racine
     * via `data-modal-exit-ms` : le masquage effectif attend d'autant.
     */
    function closeModal(target) {
        var el = resolve(target);
        if (!el) return;
        var idx = stack.indexOf(el);
        if (idx !== -1) stack.splice(idx, 1);
        if (!stack.length) document.documentElement.classList.remove("modal-open");

        // Inerte dès la demande de fermeture : pendant l'animation de sortie, la
        // modale reste visible mais ne doit plus capter ni le focus ni les clics.
        el.inert = true;
        el.dispatchEvent(new CustomEvent("goa:modal-close", { bubbles: true }));

        // Le focus revient immédiatement : il ne doit jamais dépendre d'une animation.
        var opener = el._goaOpener;
        el._goaOpener = null;
        if (opener && document.contains(opener) && typeof opener.focus === "function") {
            opener.focus();
        }

        function hide() {
            if (stack.indexOf(el) !== -1) return; // rouverte entre-temps
            el.classList.add("hidden");
            el.setAttribute("aria-hidden", "true");
        }

        var delay = parseInt(el.getAttribute("data-modal-exit-ms"), 10);
        clearTimeout(el._goaHideTimer);
        if (delay > 0) el._goaHideTimer = setTimeout(hide, delay);
        else hide();
    }

    function trapFocus(event, root) {
        var items = focusables(root);
        if (!items.length) {
            event.preventDefault();
            root.focus();
            return;
        }
        var first = items[0];
        var last = items[items.length - 1];
        var active = document.activeElement;

        if (!root.contains(active)) {
            event.preventDefault();
            (event.shiftKey ? last : first).focus();
        } else if (event.shiftKey && active === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && active === last) {
            event.preventDefault();
            first.focus();
        }
    }

    // Capture : la modale la plus haute de la pile intercepte Échap et Tab avant
    // les handlers de page (console.html gère déjà Échap pour son terminal).
    document.addEventListener("keydown", function (event) {
        if (!stack.length) return;
        var top = stack[stack.length - 1];
        if (event.key === "Escape" || event.key === "Esc") {
            event.preventDefault();
            event.stopPropagation();
            closeModal(top);
        } else if (event.key === "Tab") {
            trapFocus(event, top);
        }
    }, true);

    // Clic sur le fond : uniquement pour les racines marquées `data-modal-dismiss`,
    // pour ne pas faire perdre un formulaire à moitié rempli par mégarde.
    document.addEventListener("click", function (event) {
        if (!stack.length) return;
        var top = stack[stack.length - 1];
        if (event.target === top && top.hasAttribute("data-modal-dismiss")) {
            closeModal(top);
        }
    });

    // ============================================================
    // Export
    // ============================================================

    var GoaUI = {
        notify: notify,
        notifyError: notifyError,
        describeError: describeError,
        openModal: openModal,
        closeModal: closeModal,
        isModalOpen: isOpen
    };

    window.GoaUI = GoaUI;
    // Alias globaux : les pages sont écrites en handlers `onclick=""`, où seul le
    // scope global est accessible.
    window.notify = notify;
    window.notifyError = notifyError;
    window.openModal = openModal;
    window.closeModal = closeModal;
})(window, document);
