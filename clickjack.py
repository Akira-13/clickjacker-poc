import requests

def check_clickjacking(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        # check x-frame-options if frameable
        xfo = headers.get('X-Frame-Options', 'MISSING').upper()
        has_xfo = xfo in ['DENY', 'SAMEORIGIN']

        # check csp if frameable
        csp = headers.get('Content-Security-Policy', 'MISSING').upper()
        has_csp_frame_ancestors = 'FRAME-ANCESTORS' in csp

        # check cookies if requests can be sent through iframe
        cookies_missing_samesite = []
        cookies_with_samesite = []
        for cookie in response.cookies:
            rest = getattr(cookie, "_rest", {}) or {}
            samesite = (rest.get("SameSite") or rest.get("samesite") or "").upper()
            if samesite not in ['STRICT', 'LAX']:
                cookies_missing_samesite.append(cookie.name)
            else:
                cookies_with_samesite.append(cookie.name)

        # Site is not vulnerable if it has XFO or CSP frame-ancestors protection
        vulnerable = not (has_xfo or has_csp_frame_ancestors)

        # Check if vulnerable site has protected cookies
        if vulnerable and cookies_with_samesite:
            print(f"Site appears to be frameable but has protected cookies: {', '.join(cookies_with_samesite)}")

        return {
            "url": url,
            "vulnerable": vulnerable,
            "details": {
                "x_frame_options": xfo,
                "csp_frame_ancestors": has_csp_frame_ancestors,
                "insecure_cookies": cookies_missing_samesite
            }
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

target = "https://example.com"
report = check_clickjacking(target)
print(f"Target: {report['url']}\nVulnerable: {report['vulnerable']}")
print(report)
