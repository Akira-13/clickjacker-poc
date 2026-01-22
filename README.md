# Clickjack Vulnerability Analyzer and PoC Creator

This tool analyzes the headers in a URL to verify if a site is vulnerable to clickjacking and prepares a PoC creator.

## Quickstart

    python3 clickjack.py [url]

When prompted (and if site is vulnerable), a PoC HTML creator will be generated with the target URL in an iframe. Then, follow instructions from the PoC generator.

![PoCGen](https://github.com/user-attachments/assets/7aecbf00-436d-41f2-a0b5-59c457c7faa5)

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

## What is the PoC generator?

It's a simple HTML and JS code that allows you to position the target site in an iframe over a decoy site.

### Features

#### Automatic PoC generation

Saves you guessing with manual CSS adjusting. Just pick a decoy, position the iframe and export to clipboard!

#### Decoy templates

Choose between a generic button, a fake reCAPTCHA and a fake redirecting message as decoys.

#### Opacity slider

Adjust the opacity of the iframe in generation.

#### Sandboxing

Checkbox to enable sandboxing in the exported PoC for frame busting code bypass.

#### Multi-step PoC

Allows you to record multiple iframe positions for multi-click clickjacking attacks.

---

Educational purposes only. Use responsibly!
