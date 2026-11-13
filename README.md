# Phishing Email Analyser

A Python tool that analyses a suspicious email (`.eml` file) the way a SOC analyst would, and gives it a risk score.

## What it checks

| Check              | What it looks for                                                                                                                      | Risk points        |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| Sender alignment   | Does the `From` domain match the `Return-Path` domain? A mismatch is a classic spoofing sign.                                          | +3                 |
| SPF / DKIM / DMARC | Did the email pass sender authentication?                                                                                              | +2 per failure     |
| Links              | Extracts every link in the body and flags any outside the sender's domain                                                              | +1 if any external |
| Attachments        | SHA-256 hash of every attachment (to look up on VirusTotal) and flags risky file types such as `.exe`, `.js`, `.html`, `.zip`, `.docm` | +5 per risky file  |

**Verdict:** 0-2 LOW, 3-5 MEDIUM, 6+ HIGH.

## How to run

Requires Python 3 (standard library only, nothing to install).

```
python analyser.py examples/fake_phish.eml
```

To analyse your own email: in Gmail open the email, click ⋮ → **Download message**, save the `.eml` file and run the tool on it.

## Example output

Running it on the included fake phishing email (fictional domains, harmless attachment):

```
From domain: examplebank.com
Return-Path domain: mailer.example-cheap-hosting.net
Domains: MISMATCH - spoof alert
spf=pass : FAILED or missing
dkim=pass : FAILED or missing
dmarc=pass : FAILED or missing

Links found: 1
  EXTERNAL examplebank-secure-login.example.net -> http://examplebank-secure-login.example.net/verify?id=48213

Attachment: Invoice_Nov2026.pdf.exe
  SHA-256: cd61b24bb04ddbdcf65131ead6611810d32a894aec351ddf7433eedbcf55b72c
  RISKY file type - do not open, check the hash on VirusTotal

RISK SCORE: 15
Verdict: HIGH RISK - likely phishing
```

A real newsletter from a legitimate sender scored **1 (LOW RISK)**: all authentication checks passed and the only finding was image links hosted on an external CDN.

## What I learned

- How email authentication (SPF, DKIM, DMARC) works and how to read it from raw headers
- Parsing email structure (MIME parts, base64 attachments) with Python's `email` library
- Using regex to extract URLs, and handling false positives (for example, an XHTML namespace URL that looks like a link)
- Hashing files with SHA-256 for threat-intelligence lookups

## Limitations and next steps

- Link checks compare domains only; they don't follow redirects or check reputation
- Next: look up attachment hashes and link domains automatically through the VirusTotal API

## Privacy

Real emails are kept in a `samples/` folder that is excluded from Git (`.gitignore`), so no personal data is published.
