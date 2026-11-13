from email import policy
from email.parser import BytesParser
import re
import hashlib
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
    """Check domain alignment and SPF / DKIM / DMARC. Returns risk points."""
    score = 0
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
        score += 3

    # 2. Did each authentication check pass?
    for check in ["spf=pass", "dkim=pass", "dmarc=pass"]:
        if check in auth:
            print(check, ": OK")
        else:
            print(check, ": FAILED or missing")
            score += 2

    return score


def get_urls(path, from_domain):
    """Find unique links in the body and flag external ones. Returns risk points."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = msg.get_body(preferencelist=("html", "plain"))
    text = body.get_content()

    # Find all links, then remove duplicates
    links = re.findall(r"https?://[^\s\"'<>]+", text)
    links = set(links)

    print("Links found:", len(links))
    external = False
    for link in links:
        host = urlparse(link).hostname
        if host == from_domain or host.endswith("." + from_domain):
            print("  OK      ", host)
        else:
            print("  EXTERNAL", host, "->", link)
            external = True

    if external:
        return 1
    return 0


def get_attachments(path):
    """Hash each attachment and flag risky file types. Returns risk points."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    risky = (".exe", ".js", ".vbs", ".scr", ".bat", ".html", ".htm",
             ".zip", ".rar", ".iso", ".docm", ".xlsm")

    count = 0
    score = 0
    for part in msg.iter_attachments():
        count = count + 1
        name = part.get_filename()
        data = part.get_payload(decode=True)
        file_hash = hashlib.sha256(data).hexdigest()
        print("Attachment:", name)
        print("  SHA-256:", file_hash)
        if name and name.lower().endswith(risky):
            print("  RISKY file type - do not open, check the hash on VirusTotal")
            score += 5

    if count == 0:
        print("No attachments")

    return score


if __name__ == "__main__":
    path = "samples/test1.eml"
    headers = read_headers(path)
    total = 0
    total += check_email(headers)
    print()
    total += get_urls(path, get_domain(headers["from"]))
    print()
    total += get_attachments(path)

    print()
    print("RISK SCORE:", total)
    if total >= 6:
        print("Verdict: HIGH RISK - likely phishing")
    elif total >= 3:
        print("Verdict: MEDIUM RISK - check carefully")
    else:
        print("Verdict: LOW RISK")