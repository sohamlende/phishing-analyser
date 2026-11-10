from email import policy
from email.parser import BytesParser


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
    parts = address.split("@")
    domain = parts[-1]
    domain = domain.strip("<> ")

    return domain.lower()


def check_email(headers):
    from_domain = get_domain(headers["from"])
    return_domain = get_domain(headers["return_path"])
    auth = headers["auth_results"].lower()

    print("From domain:", from_domain)
    print("Return-Path domain:", return_domain)

    # 1. Same domain, or one is a subdomain of the other?
    if from_domain == return_domain or return_domain.endswith("." + from_domain) or from_domain.endswith("." + return_domain):
        print("Domains: ALIGNED")
    else:
        print("Domains: MISMATCH -spoof alert")

    # 2. Check each result passed
    for check in ["spf=pass", "dkim=pass", "dmarc=pass"]:
        if check in auth:
            print(check, ": OK")
        else:
            print(check, ": FAILED or missing")



headers = read_headers("samples/test1.eml")
check_email(headers)
