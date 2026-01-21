# Clickjack Vulnerability Analyzer and PoC Creator

This tool analyzes the headers in a URL to verify if a site is vulnerable to clickjacking and prepares a PoC creator.

## Quickstart

    python3 clickjack.py [url]

When prompted (and if site is vulnerable), a PoC HTML creator will be generated with the target URL in an iframe. Then, follow instructions from the PoC generator.

## What is clickjacking?

[Clickjacking](https://portswigger.net/web-security/clickjacking) is an attack in which the user is tricked into unknowingly clicking content in an invisible website by using a decoy website. For example, the user could be tricked into clicking a "Collect reward" button behind an invisible iframe of a sensitive website, such as banking or social media, right over a state-changing action, such as deleting an account or making a money transfer.

## What does the script check?

The Python scripts verifies `X-Frame-Options` and `Content-Security-Policy` headers in the HTTP response, along with its cookies.

### X-Frame-Options

Verifies the header in  `X-Frame-Options`, if present, is set in either `DENY` or `SAMEORIGIN`, preventing framing from pages outside its domain.

### Content-Security-Policy

Verifies the header in  `Content-Security-Policy`, if present, has `frame-ancestors` directive with any option.

### Cookies

Verifies `Set-Cookie` hedaers to verify if it has any protected cookie with options `Strict` or `Lax`, preventing iframes from sending valid requests.

---

Educational purposes only. Use responsibly!