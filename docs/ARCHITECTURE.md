# LinkShield AI 3.0 architecture

Interactive version: [`wireframes/linkshield-wireframes.html`](wireframes/linkshield-wireframes.html).

```text
Browser UI        Share to LinkShield        Chat bots
(paste, attach,   (Android share sheet,      (Telegram, WhatsApp:
 record)           service worker)            verified webhooks)
      \                  |                        /
       +-----------------+-----------------------+
                         | HTTPS + identity
                 Cloud Run: API service
          +----------------------------------+
          | Auth guard    token check, rate limit, every endpoint
          | Session store history and preferences      -> Firestore
          | Check engine  extract -> claims | links | files -> summary
          +----------------------------------+
            |            |             |                |
     Sandbox worker   Vertex AI     Web Risk        VirusTotal
     (own Cloud Run   Gemini +      known threat    known-file lookup
      service, no     Google        addresses       (fingerprint only)
      roles; browser  Search
      visit + file    Text-to-Speech -> spoken verdict
      inspection)     BigQuery -> anonymous trends     Cloud Storage -> private screenshots
```

## The check engine (`app/security/engine.py`)

1. **Extract.** Gemini reads the text, screenshot or voice note and returns a transcript, up to three checkable claims and the pressure tactics used. Without Gemini, links are pulled out by pattern and tactics by word lists, and the report says what was not read.
2. **Claims.** Each claim is researched with Google Search grounding and judged from the research notes only. No sources means confidence is capped.
3. **Links.** Up to three links go to `orchestrator.scan`: Web Risk, a sandbox browser visit, URL rules. A link that leads to a file has that file inspected.
4. **Files.** An attachment goes to `orchestrator.scan_upload`. The sandbox reads its structure. The API then asks VirusTotal about its fingerprint and sends up to three links found inside it back through the link branch (one level deep only).
5. **Level.** The worst fixed verdict among the parts. If nothing could be judged, the level is `unverified`.
6. **Summary.** Gemini is given the fixed level and the evidence and writes a headline, an explanation and next steps. A rules-built summary is used when Gemini is off.

## Security boundaries

- The API process never renders or fetches a user-supplied address. It calls only fixed services: the sandbox worker, Google APIs, VirusTotal, and the Telegram and Meta APIs.
- The sandbox worker is the only place untrusted pages and files are handled. It has a bearer token, short timeouts, public-address checks on every request and redirect hop, and no credentials. In the cloud it is a separate Cloud Run service that only the API's service account may invoke. Python-level address checks do not stop DNS rebinding; see `SECURITY.md`.
- Message, page and file text is passed to Gemini as evidence, never as instructions. Link and file verdicts are computed before Gemini is called and are not read back from its answer.
- Bot webhooks reject calls without Telegram's secret header or Meta's body signature. Replies defang web addresses.
- History is scoped to the signed-in or guest identity. Analytics hold a hash, never the address or message.

## Not built

A native Android app or scanner, an iOS share extension, automatic reading of private chats, file execution or detonation, and per-scan disposable virtual machines for the sandbox.
