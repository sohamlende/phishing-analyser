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


headers = read_headers("samples/test1.eml")
for key, value in headers.items():
    print(key, ":", value)