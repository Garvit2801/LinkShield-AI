# Security & responsible operation

This project accepts untrusted URLs and optionally renders them in Chromium. Do **not** publicly expose the browser worker or run it in a corporate or development workstation environment without proper network isolation. Docker containers alone are **not** a fully hardened malware sandbox.

## Implemented controls

- Restricts submitted destinations to HTTP(S), standard ports, no URL credentials, and rejects explicitly private and reserved IPs and internal domain suffixes.
- Primary API does not visit suspect sites; Web Risk reputation check is server-to-Google only.
- Sandbox browser worker validates authorization token and destination, separately validates subresource host DNS, disables service workers, declines browser downloads, blocks some high-risk resource types, imposes time limits and captures limited evidence.
- File inspection (`sandbox/filescan.py`) runs only in the worker. Files are fetched into memory with a size cap (`FILE_MAX_BYTES`, default 40 MB; uploads `UPLOAD_MAX_BYTES`, default 25 MB), every redirect hop is re-validated, and bytes are parsed statically then discarded. Nothing is written to disk, rendered or executed. It has no malware signatures: a clean result means no known structural danger signs, not that the file is safe. Incomplete inspections (truncated, encrypted, unknown type, download refused) are never reported as low risk.
- The worker only observes browsing and form attributes; it does **not** click links, submit credentials, log into sites, execute downloaded files or detonate samples.
- Reports escape DOM text; suspicious URLs are displayed defanged rather than as clickable links.
- Google matches override heuristic scores; Gemini cannot override deterministic classifications. Missing analysis is represented as unavailable or unverified.
- Optional GCS screenshot storage is private, scoped by user, and has a one-day retention lifecycle; Firestore history omits raw message context and image blobs.
- Firebase ID token validation supported for authenticated production deployments.
- Every API route, including the original `/api/check`, `/api/tts` and `/api/trends`, requires an identity and is rate limited. With Firestore on, the limit is shared by all server instances.
- VirusTotal lookups send only a file's SHA-256 fingerprint. Links found inside a file are followed one level deep, at most three per file, through the same sandbox and address checks as any other link.
- Bot webhooks verify Telegram's secret header and Meta's HMAC body signature before reading a message; replies defang web addresses.
- In the cloud the worker is a separate Cloud Run service with a role-less service account, invocable only by the API's service account, with its token in Secret Manager.

## Security gaps to address *before production*

1. **Hostile JavaScript / browser exploit risk:** deploy worker on ephemeral Compute Engine VMs in a **separate security project**, use hardened kernels and updated Chromium, restrict CPU/memory/time, start new VM/disk per untrusted investigation at high assurance. A persistent worker/container is only a local MVP.
2. **SSRF/DNS rebinding:** route browser traffic through an **enforced egress proxy**, firewall or network namespace policy denying internal, link-local, RFC1918, CGNAT, cloud metadata and Kubernetes/service ranges. Source-code DNS checks alone are not sufficient. Browser should never have access to production API networks, secrets or credentials.
3. **IAM:** sandbox compute identity must have no business-data credentials. Never mount Google Cloud ADC or the Docker socket into the sandbox. Never colocate API production secrets in its network namespace.
4. **Service transport:** the Terraform deployment authenticates API -> worker with a Google identity token and a Secret Manager token, but the worker still has a public Cloud Run address and unrestricted internet egress. For hostile traffic, put it on internal ingress with a VPC connector and an egress proxy.
5. **Network abuse:** prevent scanning private systems, intranet hosts, unauthorized targets and excessive crawling via global quotas and automated abuse detection. Enforce scan authorization, Cloud Armor/API Gateway, cost quotas and durable throttling.
6. **Data handling:** URLs and browser captures may contain personal information. Obtain informed user consent, redact sensitive tokens/query params, consider safe retention and regional privacy needs. Google Web Risk/Gemini receive request evidence when enabled.
7. **Detection quality:** evaluate with benign and known-malicious test datasets (safely, offline or sandboxed), confusion matrices, false positive/negative rates, reporting calibration and human review. Never display scores as probabilities.
8. **Untrusted model input:** do not grant Gemini tools or external actions based on webpage instructions; maintain fixed schemas and strict evidence boundaries.

## Risk statement

A page with no identified indicators is **not certified safe**; phishing pages may be personalized, geo-fenced, authenticated, delayed or conditional. Scoring is an explainable triage aid, not a verified cybersecurity verdict.

## Sandbox behaviour tests

Web content (links, and HTML or SVG attachments) is opened in a throwaway, phone-sized browser with no permissions, no service workers
and no saved downloads. Before the page's own code runs, a probe records clipboard writes, permission prompts, pop-ups, full-screen and
back-button traps. The page's clock is then fast-forwarded by 30 seconds and 5 minutes, so code that waits before acting still runs while
it is watched. Obviously fake details (`ls-canary-7731@example.com`) are typed into the first login-style box, without pressing Enter or
any button, to catch pages that send keystrokes as they are typed. The scoring lives in `app/security/behaviour.py`.

Programs, Office macros and APKs are still never executed: the sandbox is Linux on Cloud Run, so running Windows or Android malware there
would show nothing useful and would add risk. Code files (`.py`, `.sh` and similar) are judged by what the code does (download-and-run,
hidden code, remote control, password theft), not by being code.
