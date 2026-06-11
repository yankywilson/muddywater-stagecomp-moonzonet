# Intelligence Assessment — Stagecomp Downloader and the moonzonet.com C2

**Handling:** TLP:CLEAR (public release version) · **Original analytic product:** TLP:AMBER
**Author:** Yanky Wilson — independent CTI research ([github.com/yankywilson](https://github.com/yankywilson))
**Date:** 2026-06-11
**Subject:** A native C++ first-stage downloader ("Stagecomp") beaconing to `moonzonet.com`, assessed as MuddyWater (Iran) tooling
**Drafted to:** ICD-203 analytic standards (estimative language; source/confidence stated; assumptions and gaps made explicit)

---

## 1. Executive summary

This assessment covers a single Windows downloader (SHA-256 `a92d28f1…ecc0`) recovered and reverse-engineered in full. The binary is a **minimal courier**: it fingerprints the host, registers with an HTTPS command-and-control (C2) server at `moonzonet.com`, waits for an operator "go" verdict, downloads a three-file second stage, launches it, and deletes itself.

We assess **— with moderate confidence —** that the downloader is tooling of **MuddyWater**, an Iranian state-aligned threat group widely attributed to Iran's Ministry of Intelligence and Security (MOIS). Confidence is held at moderate because attribution rests on a **single primary open source** plus weaker corroboration, and because several observed traits (commodity code-signing abuse, a low-grade scam decoy) are atypical for a state program and introduce genuine alternative explanations.

The **second-stage payload was not recovered** — the C2 never returned an "approved" verdict in any available detonation — and this is the principal intelligence gap.

---

## 2. Key judgments

**KJ-1.** The sample is **almost certainly a purpose-built first-stage downloader**, not a full implant. *(High confidence — based on complete static reverse engineering of the control flow, cross-checked by two independent automated tools.)* It has no persistence, no privilege escalation, no mutex, and no string obfuscation; it launches, stages, and exits.

**KJ-2.** The downloader is **likely MuddyWater (Iran/MOIS) tooling**. *(Moderate confidence — one primary open-source report identifies the "Stagecomp" family and ties it to MuddyWater; two threat-intel platforms echo the tag but may derive from the same source.)*

**KJ-3.** The operator's network infrastructure is **almost certainly Cloudflare-fronted with no exposed origin**. *(High confidence — passive DNS, certificate transparency, and host-scan data across multiple providers show only Cloudflare edge addresses and public-CA certificates; no origin server leaked.)* The single durable network indicator is the domain itself.

**KJ-4.** The campaign **likely post-dates and reuses infrastructure tradecraft from a same-actor cluster involving Chaos-style activity**, consistent with the cited reporting's false-flag framing. *(Moderate confidence — temporal and tradecraft overlap from one source; not independently reproduced here.)*

**KJ-5.** It is **unlikely** that the low-grade Telegram/SaaS scam decoy hosted on the same domain reflects the core operator's intent; it is **more likely** a commodity lure template reused for delivery. *(Moderate confidence — the decoy matches 10,000+ near-identical pages and the loader contains no code referencing it.)* This tension is unresolved and is treated as a caveat against over-confident state attribution, not as supporting evidence.

---

## 3. Sourcing and method

- **Primary:** first-hand static reverse engineering of the binary (Ghidra hand analysis; cross-checked with CAPA and FLOSS). This is the highest-confidence basis in this product.
- **Corroborating (technical):** certificate transparency (Censys, crt.sh), passive DNS (SecurityTrails), BGP/host data (Hurricane Electric), multi-vendor sandbox reports. Used to resolve infrastructure and to *exclude* false leads.
- **Corroborating (attribution):** one primary vendor report naming "Stagecomp"/MuddyWater; two platform tags treated as **dependent**, not independent, corroboration.
- **Analytic posture:** recovery-first and validation-gated. Indicators were retained only when reproduced; artifacts of the analysis path (e.g. an injected TLS certificate) were identified and discarded. Null results are reported as findings.

---

## 4. Technical findings (the verified kill chain)

1. **Decoy & setup.** Pops a trivial `MessageBoxA("Hi", ":)")`, detaches the console, sleeps ~45s.
2. **Host fingerprint.** Computer name + user name + domain (`%USERDOMAIN%`, else `WORKGROUP`; failures → `Unknown`), assembled into a beacon identity `<ComputerName>_<UserName>_<TickCount>`.
3. **Register.** WinHTTP (User-Agent `StageClient/2.0`) POSTs JSON to `https://moonzonet.com/register`.
4. **Poll & gate.** POSTs `/check` and proceeds on **either** `"approved":true` **or** `"retry":true` (both are go-signals). On neither, it re-registers, sleeps 15s, and loops.
5. **Stage.** Three GETs to `/download/Game.{dll,exe,config}`, written as `WebView2Loader.dll`, `Game.exe`, `visualwincomp.txt` into a `GameFiles` folder under Downloads (or Public\Downloads).
6. **Execute.** `CreateProcessA` launches `Game.exe`.
7. **Clean up.** On success, reports `/status`, then self-deletes via `cmd.exe /c ping 127.0.0.1 -n 6 > nul && del /f /q "<self>"` and exits.

The C2 application protocol is opaque only at the payload layer; the **request structure is fully recovered**. The second-stage `Game.exe` (referred to in the cited reporting as a trojanized WebView2 sample) was **not** obtained.

---

## 5. Attribution analysis

**Assessed actor: MuddyWater (Iran / MOIS) — moderate confidence.**

Supporting:
- One primary open-source report names the "Stagecomp" family and attributes it to MuddyWater.
- Independent sandbox/platform tags align with that attribution.
- TTPs (HTTPS courier → staged second stage; minimal first-stage footprint) are consistent with the group's documented patterns.

Detracting / alternative hypotheses considered:
- **Single-source dependency.** The platform tags likely inherit from the same primary report; this is not three independent confirmations.
- **Commodity code-signing.** The loader abused a *consumer-grade* Microsoft Trusted Signing certificate ("Donald Gay", revoked) — cheaper, more disposable tradecraft than is typical for a mature state program, and equally available to criminal actors.
- **Scam decoy tension.** A $100/$199 Telegram funnel on the same domain is uncharacteristic of state collection and fits commodity crime or a shared-hosting reseller.
- **Documented false-flag context.** The cited cluster reportedly mixes ransomware-style activity, which is consistent both with deliberate MuddyWater misdirection *and* with mis-clustering.

On balance the MuddyWater hypothesis is the best-supported, but the alternatives are not eliminated. **We do not raise this to high confidence**, and we explicitly do not treat the decoy or the commodity cert as evidence *for* state attribution.

A recognized MuddyWater hallmark — Microsoft Teams / help-desk social engineering for initial access — is **not present in this isolated downloader** and was not assessed; this sample sits downstream of initial access.

---

## 6. Infrastructure assessment

- DNS: Cloudflare nameservers; A/AAAA records are Cloudflare edge addresses only; **no MX, no TXT**.
- Certificates: eight public-CA DV certificates (Let's Encrypt, Sectigo, Google Trust Services), all issued in a synchronized day-one burst on 2026-01-14 — the signature of Cloudflare Universal SSL + Advanced Certificate Manager, **not** multiple origin servers.
- The self-signed "Universe Security" certificate seen on the malware's wire is **absent from all certificate transparency and scan data** and is assessed as an **analysis-path (MITM) artifact**, not operator infrastructure.
- **No origin leak** surfaced across any passive source. The durable network indicator is `moonzonet.com`; the fronting IPs are not durable and should not be used for blocking or pivoting.

**Provenance timeline:** domain registered + first certificate 2026-01-14 → loader compiled 2026-02-14 → code-signed 2026-02-17 → current edge cert 2026-05-12 → active June 2026.

---

## 7. Iran / MuddyWater context for analysts

MuddyWater is a long-running Iranian state-aligned group associated with espionage and access operations against government, telecommunications, and NGO targets across the Middle East, and periodically beyond it. Its documented pattern is **access-and-stage**: gain a foothold (often via social engineering), deploy lightweight first-stage tooling, and pull heavier capability only on validated targets. The Stagecomp downloader fits that pattern cleanly — a disposable courier with a server-side approval gate that lets operators **withhold the real payload from sandboxes and non-targets**, which is exactly the behavior that left our second stage unrecovered.

Two cautions for analysts building on this:
- Treat the **single-source attribution** as provisional pending independent confirmation.
- The **commodity-scam decoy** is a real anomaly. It may indicate shared/abused hosting, a delivery contractor, or deliberate noise — but it should temper any clean "Iranian APT" narrative until resolved.

---

## 8. Intelligence gaps

1. **Second-stage payload (`Game.exe`) — not recovered.** The gate never approved in available detonations; the payload may simply not exist in public feeds. *(Highest-priority gap.)*
2. **Independent attribution confirmation.** Need a second primary source not derived from the original report.
3. **Initial-access vector for this specific intrusion** — not in scope of the downloader.
4. **Operator origin infrastructure** — fully masked by Cloudflare; no leak found.
5. **Victimology / targeting** — no telemetry on who received this loader.

---

## 9. Outlook

If the second stage is a remote-access trojan consistent with the cited reporting, affected hosts **likely** face hands-on-keyboard follow-on (credential access, lateral movement, collection). Because the first stage is disposable and server-gated, **defenders should not rely on retrieving the payload to detect the campaign** — the durable detection surface is the loader's own behavior and the C2 domain, both covered by the accompanying rule pack.

---

## Appendix A — Indicators
See [`IOCs.md`](../IOCs.md), including the **excluded-indicator** table (artifacts deliberately not deployed).

## Appendix B — ATT&CK
See [`docs/ATTACK_MAPPING.md`](ATTACK_MAPPING.md).

## Appendix C — Estimative language
"Almost certainly" ≈ 95–99% · "highly likely" ≈ 80–95% · "likely" ≈ 55–80% · "roughly even chance" ≈ 45–55% · "unlikely" ≈ 20–45% · "remote" ≈ 1–5%. Confidence (high/moderate/low) reflects source reliability and corroboration, and is stated separately from likelihood.
