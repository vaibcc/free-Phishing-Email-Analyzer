# VAIB Free Phishing Email Analyzer

A free, browser-based tool for inspecting suspicious email messages and identifying common phishing indicators. The application runs locally in your browser: message content is not uploaded to a server.

## Features

- Paste raw email content or load an `.eml` file from your device.
- Parse common message headers, including sender, Reply-To, Return-Path, Subject and Received lines.
- Extract URLs and identify suspicious patterns, including raw IP-address hosts, URL shorteners, unusual hostnames and unencrypted HTTP links.
- Inspect SPF, DKIM and DMARC results when those results are present in the supplied authentication headers.
- Calculate a transparent heuristic risk score and explain each finding.
- Export a JSON report or print the report to PDF.

## Important authentication limitation

SPF, DKIM and DMARC results displayed by this tool are parsed from the supplied message headers. The tool does **not** independently verify DNS records, cryptographic DKIM signatures, SPF authorization, DMARC alignment, or the authenticity of the headers. An attacker may forge or alter header content. Treat these values as reported evidence, not proof that a message is authentic.

## Privacy

Analysis is performed client-side in your browser. The application does not send email content to a backend or third-party analysis service. The optional Google Fonts stylesheet is a remote styling resource; remove the import in `styles.css` if you require a fully offline experience. Avoid sharing exported reports if they contain sensitive message content or personal information.

## Run locally

1. Clone the repository:
   ```bash
   git clone https://github.com/vaibcc/free-Phishing-Email-Analyzer.git
   cd free-Phishing-Email-Analyzer
   ```
2. Open `index.html` in a modern browser.

No build process, account, API key or paid service is required.

## Deploy

This is a static website. Publish the repository root using GitHub Pages, Cloudflare Pages or another static hosting provider.

## Limitations

This is a triage aid, not a mail gateway, sandbox, threat-intelligence service or substitute for incident response. Heuristic findings can produce false positives and false negatives. The tool does not inspect binary attachment contents or follow URLs to determine their final destinations. Do not open suspicious links or attachments to test them.

## Contributing

Issues and pull requests are welcome. Please use safe, sanitized examples when reporting parsing bugs. Never commit real emails, credentials, tokens or personal data.

## License

MIT. See [LICENSE](LICENSE).

---

Built by **VAIB Technical Tools**.
