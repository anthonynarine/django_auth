from django.utils.deprecation import MiddlewareMixin


class DisableCSRFMiddleware(MiddlewareMixin):
    """
    Exempts specific /api/ endpoints from Django's CSRF protection.

    This is an explicit allowlist rather than a blanket "/api/*" exemption.
    Every endpoint listed here needs it today because the frontend
    (gaitobservatory.com) and this API live on different registrable domains:
    a CSRF cookie set by this backend is never visible to the frontend's own
    JS (cross-origin document.cookie reads are blocked by the browser
    regardless of SameSite), so the standard double-submit-cookie CSRF
    pattern cannot function here without a same-site reverse proxy or a
    body-based token handshake -- see the security review notes for why a
    full CSRF rework is out of scope for a quick patch. The operative
    protection today is that state-changing requests require a bearer JWT
    in the Authorization header, which a cross-site attacker can neither
    read (different origin) nor forge (no secret).

    New endpoints are NOT exempt by default -- add a path here deliberately
    if it genuinely needs to skip CSRF, instead of inheriting the exemption
    automatically the way every /api/ path used to.
    """

    EXEMPT_PATHS = [
        '/api/register/',
        '/api/login/',
        '/api/guest-login/',
        '/api/two-factor-login/',
        '/api/token-refresh/',
        '/api/logout/',
        '/api/logout-all/',
        '/api/forgot-password/',
        '/api/reset-password/',
        '/api/generate-qr/',
        '/api/verify-otp/',
        '/api/validate-session/',
        '/api/user/toggle-2fa/',
        '/api/test-csrf-exempt/',
        '/api/whoami/',
    ]

    def process_request(self, request):
        path = request.path_info
        if any(path.startswith(exempt_path) for exempt_path in self.EXEMPT_PATHS):
            setattr(request, '_dont_enforce_csrf_checks', True)
