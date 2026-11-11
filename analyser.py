from email import policy
from email.parser import BytesParser
import re
from urllib.parse import urlparse


def read_headers(path):
    """Read an .eml file and return its key headers."""
    with open(path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    return {
        "from": msg["From"],
        "reply_to": msg["Reply-To"],
        "return_path": msg["Return-Path"],
        "subject": msg["Subject"],
        "auth_results": msg["Authentication-Results"],
    }


def get_domain(address):
    """Return the clean, lowercase domain from an email address."""
    parts = address.split("@")
    domain = parts[-1]
    domain = domain.strip("<> ")
    return domain.lower()


def check_email(headers):
    """Check domain alignment and SPF / DKIM / DMARC results."""
    from_domain = get_domain(headers["from"])
    return_domain = get_domain(headers["return_path"])
    auth = headers["auth_results"].lower()

    print("From domain:", from_domain)
    print("Return-Path domain:", return_domain)

    # 1. Same domain, or one is a subdomain of the other?
    if (
        from_domain == return_domain
        or return_domain.endswith("." + from_domain)
        or from_domain.endswith("." + return_domain)
    ):
        print("Domains: ALIGNED")
    else:
        print("Domains: MISMATCH - spoof alert")

    # 2. Did each authentication check pass?
    for check in ["spf=pass", "dkim=pass", "dmarc=pass"]:
        if check in auth:
            print(check, ": OK")
        else:
            print(check, ": FAILED or missing")


def get_urls(path, from_domain):
    """Find every unique link in the email body and flag links outside the sender's domain."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = msg.get_body(preferencelist=("html", "plain"))
    text = body.get_content()

    # Find all links, then remove duplicates
    links = re.findall(r"https?://[^\s\"'<>]+", text)
    links = set(links)

    print("Links found:", len(links))
    for link in links:
        host = urlparse(link).hostname
        if host == from_domain or host.endswith("." + from_domain):
            print("  OK      ", host)
        else:
            print("  EXTERNAL", host, "->", link)


if __name__ == "__main__":
    headers = read_headers("samples/test1.eml")
    check_email(headers)
    print()
    get_urls("samples/test1.eml", get_domain(headers["from"]))