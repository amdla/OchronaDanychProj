class CSPMiddleware:
    """
    Middleware to add a Content-Security-Policy (CSP) header.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Define the CSP rules based on your HTML files
        csp_rules = {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net",
            "style-src": "'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com",
            "img-src": "'self'",
        }

        # Build the CSP header value
        csp_header = "; ".join([f"{key} {value}" for key, value in csp_rules.items()])

        # Add the CSP header to the response
        response["Content-Security-Policy"] = csp_header
        return response
