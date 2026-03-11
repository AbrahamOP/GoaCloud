// CSRF token auto-injection
(function () {
    function getCSRFToken() {
        var match = document.cookie.match(/(^|;\s*)_csrf=([^;]+)/);
        return match ? match[2] : "";
    }

    // Inject hidden csrf_token field into all POST forms
    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll('form[method="POST"], form[method="post"]').forEach(function (form) {
            if (!form.querySelector('input[name="csrf_token"]')) {
                var input = document.createElement("input");
                input.type = "hidden";
                input.name = "csrf_token";
                input.value = getCSRFToken();
                form.appendChild(input);
            }
        });
    });

    // Patch fetch to auto-include X-CSRF-Token header
    var originalFetch = window.fetch;
    window.fetch = function (url, opts) {
        opts = opts || {};
        if (opts.method && opts.method !== "GET" && opts.method !== "HEAD") {
            opts.headers = opts.headers || {};
            if (opts.headers instanceof Headers) {
                if (!opts.headers.has("X-CSRF-Token")) {
                    opts.headers.set("X-CSRF-Token", getCSRFToken());
                }
            } else {
                if (!opts.headers["X-CSRF-Token"]) {
                    opts.headers["X-CSRF-Token"] = getCSRFToken();
                }
            }
        }
        return originalFetch.call(this, url, opts);
    };

    // Patch XMLHttpRequest to auto-include X-CSRF-Token header
    var originalOpen = XMLHttpRequest.prototype.open;
    var originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method) {
        this._csrfMethod = method;
        return originalOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        if (this._csrfMethod && this._csrfMethod !== "GET" && this._csrfMethod !== "HEAD") {
            this.setRequestHeader("X-CSRF-Token", getCSRFToken());
        }
        return originalSend.apply(this, arguments);
    };
})();
