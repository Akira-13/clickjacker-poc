import argparse
import requests

poc_template = "poc_maker_template.html"

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

def generate_poc_maker(url):
    """Generates an HTML file to help calibrate the attack."""
    # We load the template from a separate file or string
    try:
        with open(poc_template, "r") as f:
            template = f.read()
    except FileNotFoundError:
        print("Error: poc_maker_template.html not found.")
        return

    # Inject the target URL into the template
    # This replaces a placeholder {{TARGET_URL}} in the HTML
    poc_content = template.replace("{{TARGET_URL}}", url)
    
    filename = "clickjack_poc.html"
    with open(filename, "w") as f:
        f.write(poc_content)
    print(f"[+] PoC Maker generated: {filename}")
    print("[+] Open this file in your browser to calibrate the attack.")

def main():
    parser = argparse.ArgumentParser(description="Clickjacking scanner and PoC generator.",
                                     epilog="Educational purposes only. Use responsibly.")
    parser.add_argument("url", help="The target URL to scan.")
    args = parser.parse_args()

    print(f"[*] Scanning {args.url}...")
    report = check_clickjacking(args.url)
    if "error" in report:
        print(f"[!] Error: {report['error']}")
    elif report["vulnerable"]:
        print(f"[!] Target allows framing!")

        insecure = report["details"]["insecure_cookies"]
        if len(insecure) != 0:
            print(f"[*] Site appears frameable but has protected cookies: {', '.join(insecure)}")
        
        ans = input("[*] Generate PoC? (y/n): ")
        if ans.lower() in ['y', 'yes', '']:
            print("[*] Generating PoC...")
            generate_poc_maker(args.url)
        elif ans.lower() not in ['n', 'no']:
            print("[!] Invalid input, skipping PoC generation.")
            return

    elif not report["vulnerable"]:
        print("[!] Target is not vulnerable.")

if __name__ == "__main__":
    main()
