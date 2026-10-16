# Roadmap beyond LinkShield AI 3.0

Built in 3.0: one check for text, links, screenshots, voice notes and files; claim fact-checks; links inside documents; VirusTotal lookup; share target; Telegram and WhatsApp bots; guest sign-in; a cloud sandbox service.

Next:

1. Sandbox hardening: internal-only ingress, an egress proxy that denies private and metadata ranges, and a disposable VM per scan for high-risk links.
2. Live trials: run the Telegram and WhatsApp bots and the share target with real users; neither bot has been exercised against the real services yet.
3. Detection quality: a benign and malicious test set, measured false-positive and false-negative rates, a larger brand registry, certificate-transparency and domain-age signals.
4. Localisation: translate the rules-built summary and interface, and have native speakers review the Indian-language scam word lists.
5. Reach: QR-code checks, a browser extension, an iOS share extension.
6. Operations: budget alerts, abuse detection, retention controls, secrets rotation.
