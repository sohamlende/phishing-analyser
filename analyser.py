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


headers = read_headers("samples/test1.eml")
for key, value in headers.items():
    print(key, ":", value)
    
    
print(get_domain("jane@example.com"))
print(get_domain("GradIreland <news@EMAIL.gradireland.com>"))
print(get_domain("<bounce@mail.AIB-secure.com>"))