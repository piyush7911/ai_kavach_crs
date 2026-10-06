"""Config-fix remediation for the deterministic live classes (clickjacking, cookies, CSRF, CORS,
rate-limit, JWT). We CONFIRM these over HTTP but they have no code-sink to splice — the fix is a
framework-level config/middleware change. This produces the exact, framework-aware remediation for each
confirmed finding (RoE explicitly allows config fixes). Placement is app-specific, so the remediation is an
advisory, ready-to-apply snippet (verified by re-running the same live oracle after applying), not an
auto-spliced diff. Framework is detected from the source tree — no hardcoding per app.
"""
from __future__ import annotations

from pathlib import Path


def detect_framework(target: str | Path) -> str:
    """express | spring | flask | django | rails | generic — from deps/imports in the tree."""
    root = Path(target)
    blob = ""
    for name in ("package.json", "requirements.txt", "pom.xml", "build.gradle", "Gemfile", "go.mod"):
        f = root / name
        if f.exists():
            blob += f.read_text(errors="replace").lower()
    if "express" in blob:
        return "express"
    if "spring" in blob:
        return "spring"
    if "django" in blob:
        return "django"
    if "flask" in blob:
        return "flask"
    if "rails" in blob or "gemfile" in blob:
        return "rails"
    return "generic"


# remediation[class][framework] = (snippet, where-to-add). "generic" is the HTTP-header-level fallback.
_R = {
    "clickjacking": {
        "express": ("app.use(require('helmet').frameguard({action:'deny'}));", "app setup, before routes"),
        "spring": ("http.headers(h -> h.frameOptions(fo -> fo.deny()));", "Spring Security filter chain config"),
        "flask": ("resp.headers['X-Frame-Options'] = 'DENY'", "an after_request hook (or flask-talisman)"),
        "django": ("MIDDLEWARE += ['django.middleware.clickjacking.XFrameOptionsMiddleware']; X_FRAME_OPTIONS='DENY'", "settings.py"),
        "generic": ("set response header: X-Frame-Options: DENY  (or CSP frame-ancestors 'none')", "the reverse proxy or app response headers"),
    },
    "cookie-flags": {
        "express": ("cookie: { httpOnly: true, secure: true, sameSite: 'strict' }", "the session/cookie options"),
        "spring": ("server.servlet.session.cookie.http-only=true; .secure=true; .same-site=strict", "application.properties"),
        "flask": ("SESSION_COOKIE_HTTPONLY=True; SESSION_COOKIE_SECURE=True; SESSION_COOKIE_SAMESITE='Strict'", "app config"),
        "django": ("SESSION_COOKIE_HTTPONLY=True; SESSION_COOKIE_SECURE=True; CSRF_COOKIE_SECURE=True", "settings.py"),
        "generic": ("add HttpOnly; Secure; SameSite=Strict to the Set-Cookie attributes", "the cookie-issuing code"),
    },
    "cookie-samesite": {"generic": ("add SameSite=Strict (or Lax) to the Set-Cookie attributes", "cookie config")},
    "csrf-missing": {
        "express": ("app.use(require('csurf')()); // + render the token as a hidden form field", "after the session middleware"),
        "spring": ("(CSRF is on by default) remove any http.csrf(c -> c.disable()); keep it enabled", "Spring Security config"),
        "flask": ("from flask_wtf import CSRFProtect; CSRFProtect(app)  # add {{ csrf_token() }} to forms", "app setup"),
        "django": ("ensure 'django.middleware.csrf.CsrfViewMiddleware' is enabled; add {% csrf_token %} to forms", "settings.py + templates"),
        "generic": ("require a per-session anti-CSRF token on state-changing POST forms and verify it server-side", "the form handler"),
    },
    "cors-misconfig": {
        "express": ("app.use(require('cors')({ origin: ['https://TRUSTED'], credentials: true }));  // never reflect arbitrary Origin", "CORS middleware"),
        "spring": ("configuration.setAllowedOrigins(List.of('https://TRUSTED')); // not '*', not reflected", "CorsConfiguration"),
        "generic": ("set Access-Control-Allow-Origin to a fixed allow-list (never reflect Origin, never '*' with credentials)", "CORS config"),
    },
    "no-rate-limit": {
        "express": ("app.use('/login', require('express-rate-limit')({ windowMs: 60000, max: 5 }));", "before the auth route"),
        "spring": ("add a bucket4j / resilience4j rate-limit filter on the auth endpoint", "filter chain"),
        "flask": ("from flask_limiter import Limiter; limiter.limit('5/minute')(login_view)", "the login view"),
        "django": ("use django-ratelimit: @ratelimit(key='ip', rate='5/m') on the login view", "the login view"),
        "generic": ("enforce a per-IP/per-account attempt limit + lockout/backoff on authentication", "the auth handler or gateway"),
    },
    "jwt-none-alg": {"generic": ("reject alg=none; pin the expected algorithm (e.g. require HS256/RS256) in the verifier", "JWT verification")},
    "jwt-weak-secret": {"generic": ("replace the signing secret with a 256-bit random value from a secret store; rotate it", "JWT signing config")},
    "jwt-no-expiry": {"generic": ("set a short 'exp' claim and verify it on every request", "token issuance + verification")},
}


def remediation_for(klass: str, target: str | Path | None) -> dict | None:
    """Return {framework, snippet, where, verify} for a config class, or None if we have no remediation."""
    table = _R.get(klass)
    if not table:
        return None
    fw = detect_framework(target) if target else "generic"
    snippet, where = table.get(fw) or table.get("generic") or next(iter(table.values()))
    return {"framework": fw, "snippet": snippet, "where": where,
            "verify": "re-run the same live oracle after applying; the class must no longer confirm"}
